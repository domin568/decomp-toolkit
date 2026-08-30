//! PEF (Preferred Executable Format) container parsing.
//!
//! Field layout and documentation follow "Mac OS Runtime Architectures for System 7
//! Through Mac OS 9", January 31 1997.
//! TODO: pattern-initialized data is exposed still packed.

use anyhow::{anyhow, bail, ensure, Context, Result};

use crate::obj::{ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind};

use crate::util::pef_decompress;

/// "Joy!"
pub const TAG1: u32 = 0x4A6F_7921;
/// "peff"
#[allow(dead_code)]
pub const TAG2: u32 = 0x7065_6666;
/// "pwpc" - the PowerPC CFM
#[allow(dead_code)]
pub const ARCHITECTURE_PPC: u32 = 0x7077_7063;
/// "m68k" - the CFM-68K
#[allow(dead_code)]
pub const ARCHITECTURE_68K: u32 = 0x6D36_386B;

/// On-disk size of [`PefContainerHeader`].
const CONTAINER_HEADER_SIZE: usize = 40;
/// On-disk size of [`PefSectionHeader`].
const SECTION_HEADER_SIZE: usize = 28;
/// A section name offset of `0xFFFFFFFF` marks an unnamed section.
const NO_SECTION_NAME: u32 = 0xFFFF_FFFF;

#[inline]
pub(crate) fn be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let b = data
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("PEF: read past end of file at {:#X}", offset))?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[inline]
pub(crate) fn be_u16(data: &[u8], offset: usize) -> Result<u16> {
    let b = data
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("PEF: read past end of file at {:#X}", offset))?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

#[inline]
pub(crate) fn u8_at(data: &[u8], offset: usize) -> Result<u8> {
    data.get(offset).copied().ok_or_else(|| anyhow!("PEF: read past end of file at {:#X}", offset))
}

/// Read a NUL-terminated string at `offset` within the byte range `table`.
pub(crate) fn cstr_at(data: &[u8], table: (usize, usize), offset: u32) -> Result<&str> {
    let (start, end) = table;
    let begin = start.checked_add(offset as usize).context("Invalid PEF string offset")?;
    let bytes = data.get(begin..end).ok_or_else(|| anyhow!("Invalid PEF string offset"))?;
    let nul =
        bytes.iter().position(|&b| b == 0).ok_or_else(|| anyhow!("Unterminated PEF string"))?;
    std::str::from_utf8(&bytes[..nul]).map_err(|_| anyhow!("Non UTF-8 PEF string"))
}

/// The container header, located at offset 0.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PefContainerHeader {
    /// Must be [`TAG1`] ("Joy!").
    pub tag1: u32,
    /// Must be [`TAG2`] ("peff").
    pub tag2: u32,
    /// "pwpc" for PowerPC, "m68k" for CFM-68K.
    pub architecture: u32,
    /// Version of PEF used in the container. The current version is 1.
    pub format_version: u32,
    /// Seconds since January 1, 1904 (the Macintosh time-measurement scheme).
    pub date_time_stamp: u32,
    /// Used by the Code Fragment Manager to check shared library compatibility.
    pub old_def_version: u32,
    /// Used by the Code Fragment Manager to check shared library compatibility.
    pub old_imp_version: u32,
    /// Used by the Code Fragment Manager to check shared library compatibility.
    pub current_version: u32,
    /// Total number of sections in the container.
    pub section_count: u16,
    /// Number of instantiated sections, i.e. those required for execution.
    pub inst_section_count: u16,
    /// Reserved for future use.
    pub reserved_a: u32,
}

impl PefContainerHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        ensure!(
            data.len() >= CONTAINER_HEADER_SIZE,
            "Invalid PEFContainerHeader header size or alignment"
        );
        let header = Self {
            tag1: be_u32(data, 0)?,
            tag2: be_u32(data, 4)?,
            architecture: be_u32(data, 8)?,
            format_version: be_u32(data, 12)?,
            date_time_stamp: be_u32(data, 16)?,
            old_def_version: be_u32(data, 20)?,
            old_imp_version: be_u32(data, 24)?,
            current_version: be_u32(data, 28)?,
            section_count: be_u16(data, 32)?,
            inst_section_count: be_u16(data, 34)?,
            reserved_a: be_u32(data, 36)?,
        };
        ensure!(header.tag1 == TAG1 && header.tag2 == TAG2, "Invalid PEF magic");
        Ok(header)
    }

    /// Byte range of the section name table: it follows the section header array and runs
    /// up to the container offset of the first section.
    fn name_table_range(&self, sections: &[PefSectionHeader]) -> (usize, usize) {
        let start = CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE * self.section_count as usize;
        let end = sections.first().map_or(start, |s| s.container_offset as usize);
        (start, end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PefSectionKind {
    /// Read-only executable code, uncompressed.
    Code = 0,
    /// Uncompressed initialized read/write data, followed by zero-initialized data.
    UnpackedData = 1,
    /// Read/write data initialized by a pattern specification held in the section contents.
    PatternInitializedData = 2,
    /// Uncompressed initialized read-only data.
    Constant = 3,
    /// Imports, exports and entry points. A container has at most one loader section.
    Loader = 4,
    /// Reserved for future use.
    Debug = 5,
    /// Code that is both executable and modifiable.
    ExecutableData = 6,
    /// Reserved for future use.
    Exception = 7,
    /// Reserved for future use.
    Traceback = 8,
}

impl PefSectionKind {
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::Code,
            1 => Self::UnpackedData,
            2 => Self::PatternInitializedData,
            3 => Self::Constant,
            4 => Self::Loader,
            5 => Self::Debug,
            6 => Self::ExecutableData,
            7 => Self::Exception,
            8 => Self::Traceback,
            v => bail!("Unknown PEF section kind {}", v),
        })
    }

    /// Whether the section holds code or data that is loaded into memory.
    pub fn is_instantiated(self) -> bool {
        matches!(
            self,
            Self::Code | Self::UnpackedData | Self::PatternInitializedData | Self::ExecutableData
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::UnpackedData => "unpacked data",
            Self::PatternInitializedData => "pattern-initialized data",
            Self::Constant => "constant",
            Self::Loader => "loader",
            Self::Debug => "debug",
            Self::ExecutableData => "executable data",
            Self::Exception => "exception",
            Self::Traceback => "traceback",
        }
    }
}

/// One entry of the section header array, which begins immediately after the container header.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PefSectionHeader {
    /// Offset from the start of the section name table to this section's name.
    pub name_offset: u32,
    /// Preferred address at which to place the section's instance.
    pub default_address: u32,
    /// Size required by the section's contents at execution time, including the
    /// zero-initialized tail (whose length is `total_size - unpacked_size`).
    pub total_size: u32,
    /// Size of the contents explicitly initialized from the container. For packed data,
    /// the size to which the compressed contents expand.
    pub unpacked_size: u32,
    /// Size of the section's contents as stored in the container. For packed data, the
    /// size of the pattern description.
    pub packed_size: u32,
    /// Offset from the beginning of the container to the section's contents.
    pub container_offset: u32,
    /// Type of the section.
    pub section_kind: PefSectionKind,
    /// How the section is shared between processes.
    pub share_kind: u8,
    /// Desired in-memory alignment as a power of two.
    pub alignment: u8,
    /// Reserved for future use.
    pub reserved_a: u8,
}

impl PefSectionHeader {
    fn parse_at(data: &[u8], offset: usize) -> Result<Self> {
        Ok(Self {
            name_offset: be_u32(data, offset)?,
            default_address: be_u32(data, offset + 4)?,
            total_size: be_u32(data, offset + 8)?,
            unpacked_size: be_u32(data, offset + 12)?,
            packed_size: be_u32(data, offset + 16)?,
            container_offset: be_u32(data, offset + 20)?,
            section_kind: PefSectionKind::from_u8(u8_at(data, offset + 24)?)?,
            share_kind: u8_at(data, offset + 25)?,
            alignment: u8_at(data, offset + 26)?,
            reserved_a: u8_at(data, offset + 27)?,
        })
    }
}

fn parse_section_headers(
    data: &[u8],
    header: &PefContainerHeader,
) -> Result<Vec<PefSectionHeader>> {
    ensure!(header.section_count != 0, "Missing sections");
    let count = header.section_count as usize;
    let table_end = CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE * count;
    ensure!(data.len() > table_end, "Cut file");
    (0..count)
        .map(|i| PefSectionHeader::parse_at(data, CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE * i))
        .collect()
}

/// Look up a section name in the name table. Names are NUL-terminated C strings.
fn section_name(data: &[u8], name_table: (usize, usize), name_offset: u32) -> Result<&str> {
    if name_offset == NO_SECTION_NAME {
        return Ok("");
    }
    cstr_at(data, name_table, name_offset).context("Reading PEF section name")
}

/// A parsed PEF container: the header, the section table, and the section names.
#[derive(Debug, Clone)]
pub struct PefFile {
    pub header: PefContainerHeader,
    pub sections: Vec<PefSectionHeader>,
    /// One name per section, empty for unnamed sections.
    pub names: Vec<String>,
}

impl PefFile {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = PefContainerHeader::parse(data)?;
        let sections = parse_section_headers(data, &header)?;
        let name_table = header.name_table_range(&sections);
        let names = sections
            .iter()
            .map(|s| section_name(data, name_table, s.name_offset).map(str::to_string))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { header, sections, names })
    }

    /// The instantiated contents of every section, in section order, with
    /// pattern-initialized sections expanded.
    pub fn section_data(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        self.sections
            .iter()
            .map(|section| {
                let start = section.container_offset as usize;
                let end = start
                    .checked_add(section.packed_size as usize)
                    .context("Invalid PEF section offset or size")?;
                let raw = data
                    .get(start..end)
                    .ok_or_else(|| anyhow!("Invalid PEF section offset or size"))?;
                match section.section_kind {
                    PefSectionKind::PatternInitializedData => pef_decompress::decompress(raw)
                        .context("Failed to decompress PEF pattern-initialized data section"),
                    _ => Ok(raw.to_vec()),
                }
            })
            .collect()
    }
}

/// Map a PEF section kind onto decomp-toolkit's section kind.
fn obj_section_kind(kind: PefSectionKind) -> Result<ObjSectionKind> {
    Ok(match kind {
        PefSectionKind::Code | PefSectionKind::ExecutableData => ObjSectionKind::Code,
        PefSectionKind::UnpackedData | PefSectionKind::PatternInitializedData => ObjSectionKind::Data,
        PefSectionKind::Loader | PefSectionKind::Constant => ObjSectionKind::ReadOnlyData,
        PefSectionKind::Debug | PefSectionKind::Exception | PefSectionKind::Traceback => {
            bail!("unknown section type")
        },
    })
}

pub fn process_pef(buf: &[u8], name: &str) -> Result<ObjInfo> {
    let pef = PefFile::parse(buf)?;
    let contents = pef.section_data(buf)?;

    // PEF sections carry no load address of their own here, so lay the instantiated ones
    // out consecutively in a synthetic address space.
    const VIRT_ADDR_START: u32 = 0x1000;
    let mut virt_addr_off = VIRT_ADDR_START;
    let mut sections = Vec::with_capacity(pef.sections.len());
    for ((section, section_name), data) in
        pef.sections.iter().zip(&pef.names).zip(contents).filter(|((s, _), _)| s.section_kind.is_instantiated())
    {
        ensure!(section.alignment < 6, "Unsupported PEF section alignment {}", section.alignment);

        sections.push(ObjSection {
            name: section_name.clone(),
            kind: obj_section_kind(section.section_kind)?,
            address: virt_addr_off as u64,
            size: section.unpacked_size as u64,
            data,
            align: 2u64 << section.alignment,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: Some(virt_addr_off as u64),
            file_offset: section.container_offset as u64,
            section_known: true,
            splits: Default::default(),
        });

        virt_addr_off += section.unpacked_size;
    }

    Ok(ObjInfo::new(
        ObjKind::Executable,
        ObjArchitecture::PowerPc,
        name.to_string(),
        vec![],
        sections,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small PowerPC CFM fragment built for these tests. Three sections: code,
    /// pattern-initialized data, and the loader.
    const TEST1: &[u8] = include_bytes!("../../assets/pef/test1.pef");

    fn test1_header() -> PefContainerHeader {
        PefContainerHeader::parse(TEST1).expect("test1.pef should parse")
    }

    /// Build a minimal PEF container from `(name, kind, data)` triples.
    ///
    /// The fork's name-table test used a third-party binary; synthesising the container
    /// here keeps the same coverage without vendoring one into dtk.
    fn build_pef(sections: &[(&str, PefSectionKind, &[u8])]) -> Vec<u8> {
        let count = sections.len();
        let table_end = CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE * count;

        let mut names = Vec::new();
        let mut name_offsets = Vec::new();
        for (name, _, _) in sections {
            name_offsets.push(names.len() as u32);
            names.extend_from_slice(name.as_bytes());
            names.push(0);
        }

        // Section contents follow the name table; the first section's container offset is
        // what bounds the name table, so this ordering matters.
        let data_start = table_end + names.len();
        let mut blobs = Vec::new();
        let mut offsets = Vec::new();
        for (_, _, data) in sections {
            offsets.push((data_start + blobs.len()) as u32);
            blobs.extend_from_slice(data);
        }

        let mut out = Vec::new();
        out.extend_from_slice(&TAG1.to_be_bytes());
        out.extend_from_slice(&TAG2.to_be_bytes());
        out.extend_from_slice(&ARCHITECTURE_PPC.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes()); // format_version
        out.extend_from_slice(&0u32.to_be_bytes()); // date_time_stamp
        out.extend_from_slice(&0u32.to_be_bytes()); // old_def_version
        out.extend_from_slice(&0u32.to_be_bytes()); // old_imp_version
        out.extend_from_slice(&0u32.to_be_bytes()); // current_version
        out.extend_from_slice(&(count as u16).to_be_bytes());
        out.extend_from_slice(&(count as u16).to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes()); // reserved_a

        for (i, (_, kind, data)) in sections.iter().enumerate() {
            out.extend_from_slice(&name_offsets[i].to_be_bytes());
            out.extend_from_slice(&0u32.to_be_bytes()); // default_address
            out.extend_from_slice(&(data.len() as u32).to_be_bytes()); // total_size
            out.extend_from_slice(&(data.len() as u32).to_be_bytes()); // unpacked_size
            out.extend_from_slice(&(data.len() as u32).to_be_bytes()); // packed_size
            out.extend_from_slice(&offsets[i].to_be_bytes());
            out.push(*kind as u8);
            out.push(1); // share_kind
            out.push(0); // alignment
            out.push(0); // reserved_a
        }
        out.extend_from_slice(&names);
        out.extend_from_slice(&blobs);
        out
    }

    #[test]
    fn parses_container_header() {
        let header = test1_header();
        assert_eq!(header.tag1, TAG1);
        assert_eq!(header.tag2, TAG2);
        assert_eq!(header.architecture, ARCHITECTURE_PPC);
        assert_eq!(header.format_version, 1);
        assert_eq!(header.section_count, 3);
        assert_eq!(header.inst_section_count, 2);
    }

    #[test]
    fn parses_section_table() {
        let sections = parse_section_headers(TEST1, &test1_header()).unwrap();
        assert_eq!(sections.len(), 3);

        assert_eq!(sections[0].section_kind, PefSectionKind::Code);
        assert_eq!(sections[0].container_offset, 0x200);
        assert_eq!(sections[0].packed_size, 0xB4EC);
        assert_eq!(sections[0].unpacked_size, 0xB4EC);

        assert_eq!(sections[1].section_kind, PefSectionKind::PatternInitializedData);
        assert_eq!(sections[1].container_offset, 0xB6F0);
        assert_eq!(sections[1].packed_size, 0x5E3);
        assert_eq!(sections[1].unpacked_size, 0x954);

        assert_eq!(sections[2].section_kind, PefSectionKind::Loader);
        assert_eq!(sections[2].container_offset, 0x80);
        assert_eq!(sections[2].packed_size, 0x178);
    }

    #[test]
    fn unnamed_sections_resolve_to_empty_string() {
        let header = test1_header();
        let sections = parse_section_headers(TEST1, &header).unwrap();
        let name_table = header.name_table_range(&sections);
        for section in &sections {
            assert_eq!(section.name_offset, NO_SECTION_NAME);
            assert_eq!(section_name(TEST1, name_table, section.name_offset).unwrap(), "");
        }
    }

    #[test]
    fn reads_section_names_from_name_table() {
        let buf = build_pef(&[
            (".text", PefSectionKind::Code, &[0x60, 0x00, 0x00, 0x00]),
            (".data", PefSectionKind::UnpackedData, &[1, 2, 3, 4]),
            (".ppcldr", PefSectionKind::Loader, &[0; 8]),
        ]);

        let header = PefContainerHeader::parse(&buf).unwrap();
        let sections = parse_section_headers(&buf, &header).unwrap();
        let name_table = header.name_table_range(&sections);

        let names: Vec<&str> = sections
            .iter()
            .map(|s| section_name(&buf, name_table, s.name_offset).unwrap())
            .collect();
        assert_eq!(names, vec![".text", ".data", ".ppcldr"]);

        // The first section's contents start immediately after the name table.
        assert_eq!(sections[0].container_offset as usize, name_table.1);
        assert_eq!(sections[0].packed_size, 4);
    }

    #[test]
    fn maps_section_kinds_to_obj_kinds() {
        use PefSectionKind::*;
        assert_eq!(obj_section_kind(Code).unwrap(), ObjSectionKind::Code);
        assert_eq!(obj_section_kind(ExecutableData).unwrap(), ObjSectionKind::Code);
        assert_eq!(obj_section_kind(UnpackedData).unwrap(), ObjSectionKind::Data);
        assert_eq!(obj_section_kind(PatternInitializedData).unwrap(), ObjSectionKind::Data);
        assert_eq!(obj_section_kind(Constant).unwrap(), ObjSectionKind::ReadOnlyData);
        assert_eq!(obj_section_kind(Loader).unwrap(), ObjSectionKind::ReadOnlyData);
        // These fell through to the caller's catch-all error arm in the object-based code.
        assert!(obj_section_kind(Debug).is_err());
        assert!(obj_section_kind(Exception).is_err());
        assert!(obj_section_kind(Traceback).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = TEST1.to_vec();
        buf[0] = b'X';
        let err = PefContainerHeader::parse(&buf).unwrap_err().to_string();
        assert!(err.contains("Invalid PEF magic"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_short_container() {
        assert!(PefContainerHeader::parse(&TEST1[..CONTAINER_HEADER_SIZE - 1]).is_err());
    }

    #[test]
    fn rejects_missing_sections() {
        let mut buf = TEST1.to_vec();
        buf[32] = 0; // section_count high byte
        buf[33] = 0; // section_count low byte
        let header = PefContainerHeader::parse(&buf).unwrap();
        let err = parse_section_headers(&buf, &header).unwrap_err().to_string();
        assert!(err.contains("Missing sections"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_truncated_section_table() {
        let header = test1_header();
        // Enough bytes for the container header, but not for the section table.
        let truncated = &TEST1[..CONTAINER_HEADER_SIZE + SECTION_HEADER_SIZE];
        let err = parse_section_headers(truncated, &header).unwrap_err().to_string();
        assert!(err.contains("Cut file"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_unknown_section_kind() {
        let mut buf = TEST1.to_vec();
        // section_kind byte of the first section header
        buf[CONTAINER_HEADER_SIZE + 24] = 9;
        let header = PefContainerHeader::parse(&buf).unwrap();
        let err = parse_section_headers(&buf, &header).unwrap_err().to_string();
        assert!(err.contains("Unknown PEF section kind"), "unexpected error: {err}");
    }

    /// End-to-end: the loader section is not instantiated, so it is dropped, and the
    /// pattern-initialized section arrives expanded.
    #[test]
    fn process_pef_expands_pattern_initialized_data() {
        let obj = process_pef(TEST1, "test1").unwrap();
        assert_eq!(obj.sections.len(), 2);

        let (_, code) = obj.sections.iter().next().unwrap();
        assert_eq!(code.kind, ObjSectionKind::Code);
        assert_eq!(code.data.len(), 0xB4EC);
        assert_eq!(code.size, 0xB4EC);

        let (_, data) = obj.sections.iter().nth(1).unwrap();
        assert_eq!(data.kind, ObjSectionKind::Data);
        // 0x5E3 packed in the container, 0x954 once expanded.
        assert_eq!(data.data.len(), 0x954);
        assert_eq!(data.size, 0x954);
    }
}
