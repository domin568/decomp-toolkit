//! PEF loader section parsing.
//!
//! The loader section holds everything the Code Fragment Manager needs to prepare a
//! fragment: the symbols it imports from other fragments, the symbols it exports, where
//! its relocations live, and its main/init/term entry points. Field layout follows "Mac OS
//! Runtime Architectures for System 7 Through Mac OS 9", January 31 1997.

use anyhow::{anyhow, Context, Result};

use crate::util::pef::{be_u16, be_u32, cstr_at, u8_at, PefSectionHeader, PefSectionKind};
use crate::util::pef_relocations::{parse_relocations, PefRelocation};

/// On-disk size of [`PefLoaderInfoHeader`].
const LOADER_INFO_HEADER_SIZE: usize = 56;
/// On-disk size of [`PefImportedLibrary`].
const IMPORTED_LIBRARY_SIZE: usize = 24;
/// On-disk size of an imported symbol: a single packed class-and-name word.
const IMPORTED_SYMBOL_SIZE: usize = 4;
/// On-disk size of an export hash slot.
const EXPORT_HASH_SLOT_SIZE: usize = 4;
/// On-disk size of an export key table entry.
const EXPORT_KEY_SIZE: usize = 4;
/// On-disk size of an exported symbol: class-and-name, value, section index.
const EXPORTED_SYMBOL_SIZE: usize = 10;

/// A section index of -1 means the fragment has no such entry point.
const NO_SECTION: i32 = -1;
/// Mask selecting the name offset from a packed class-and-name word.
const NAME_OFFSET_MASK: u32 = 0x00FF_FFFF;

/// The class of a symbol, held in the top byte of a packed class-and-name word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PefSymbolClass {
    /// A code address.
    Code = 0,
    /// A data address.
    Data = 1,
    /// A standard procedure pointer (transition vector).
    TVector = 2,
    /// A direct data area (table of contents) symbol.
    Toc = 3,
    /// A linker-inserted glue symbol.
    Glue = 4,
}

impl PefSymbolClass {
    /// The low nibble carries the class; the high bit is the weak-import flag.
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value & 0x0F {
            0 => Self::Code,
            1 => Self::Data,
            2 => Self::TVector,
            3 => Self::Toc,
            4 => Self::Glue,
            v => return Err(anyhow!("Unknown PEF symbol class {}", v)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Data => "data",
            Self::TVector => "tvector",
            Self::Toc => "toc",
            Self::Glue => "glue",
        }
    }
}

/// The loader info header, at the start of the loader section.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PefLoaderInfoHeader {
    /// Section containing the main symbol, or -1 if there is none.
    pub main_section: i32,
    /// Offset of the main symbol from the start of that section.
    pub main_offset: u32,
    /// Section containing the initialization routine's transition vector, or -1.
    pub init_section: i32,
    /// Offset of the initialization routine from the start of that section.
    pub init_offset: u32,
    /// Section containing the termination routine's transition vector, or -1.
    pub term_section: i32,
    /// Offset of the termination routine from the start of that section.
    pub term_offset: u32,
    /// Number of imported libraries.
    pub imported_library_count: u32,
    /// Total number of imported symbols.
    pub total_imported_symbol_count: u32,
    /// Number of sections carrying load-time relocations.
    pub reloc_section_count: u32,
    /// Offset from the loader section to the relocations area.
    pub reloc_instr_offset: u32,
    /// Offset from the loader section to the loader string table.
    pub loader_strings_offset: u32,
    /// Offset from the loader section to the export hash table.
    pub export_hash_offset: u32,
    /// Number of export hash slots, as a power of two.
    pub export_hash_table_power: u32,
    /// Number of exported symbols.
    pub exported_symbol_count: u32,
}

impl PefLoaderInfoHeader {
    fn parse_at(data: &[u8], offset: usize) -> Result<Self> {
        Ok(Self {
            main_section: be_u32(data, offset)? as i32,
            main_offset: be_u32(data, offset + 4)?,
            init_section: be_u32(data, offset + 8)? as i32,
            init_offset: be_u32(data, offset + 12)?,
            term_section: be_u32(data, offset + 16)? as i32,
            term_offset: be_u32(data, offset + 20)?,
            imported_library_count: be_u32(data, offset + 24)?,
            total_imported_symbol_count: be_u32(data, offset + 28)?,
            reloc_section_count: be_u32(data, offset + 32)?,
            reloc_instr_offset: be_u32(data, offset + 36)?,
            loader_strings_offset: be_u32(data, offset + 40)?,
            export_hash_offset: be_u32(data, offset + 44)?,
            export_hash_table_power: be_u32(data, offset + 48)?,
            exported_symbol_count: be_u32(data, offset + 52)?,
        })
    }
}

/// A library this fragment imports symbols from.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PefImportedLibrary {
    pub name: String,
    /// Version information used to check compatibility.
    pub old_imp_version: u32,
    /// Version information used to check compatibility.
    pub current_version: u32,
    /// Number of symbols imported from this library.
    pub imported_symbol_count: u32,
    /// Index of this library's first entry in the imported symbol table.
    pub first_imported_symbol: u32,
    /// The library must be initialized before this fragment.
    pub init_before: bool,
    /// Preparation continues even if the library cannot be found.
    pub weak: bool,
}

/// One imported symbol, resolved to its library and name.
#[derive(Debug, Clone)]
pub struct PefImport {
    pub library: String,
    pub name: String,
    pub class: PefSymbolClass,
    pub weak: bool,
}

/// One exported symbol.
#[derive(Debug, Clone)]
pub struct PefExport {
    pub name: String,
    pub class: PefSymbolClass,
    /// Offset of the symbol from the start of its section.
    pub value: u32,
    /// Index of the section containing the symbol.
    pub section_index: u16,
}

/// A transition vector: a procedure pointer made of a code address and a TOC pointer.
#[derive(Debug, Clone, Copy)]
pub struct PefTransitionVector {
    /// Section holding the vector itself.
    pub section: i32,
    /// Offset of the vector within that section.
    pub offset: u32,
    /// The code address the vector points at, if the section contents could be read.
    pub code: Option<u32>,
    /// The TOC pointer the vector carries, if the section contents could be read.
    pub toc: Option<u32>,
}

/// Everything parsed out of the loader section.
#[derive(Debug, Clone)]
pub struct PefLoader {
    pub header: PefLoaderInfoHeader,
    pub libraries: Vec<PefImportedLibrary>,
    pub imports: Vec<PefImport>,
    pub exports: Vec<PefExport>,
    pub relocations: Vec<PefRelocation>,
}

impl PefLoader {
    /// Parse the loader section starting at `loader_offset` in the container.
    ///
    /// `section_count` is the total number of sections in the file (`PefFile::sections.len()`),
    /// used to validate the section index each relocation header names.
    pub fn parse(data: &[u8], loader_offset: usize, section_count: usize) -> Result<Self> {
        let header = PefLoaderInfoHeader::parse_at(data, loader_offset)
            .context("Reading PEF loader info header")?;

        // The loader string table runs from its own offset up to the export hash table.
        let strings = (
            offset_of(loader_offset, header.loader_strings_offset, "loader string table")?,
            offset_of(loader_offset, header.export_hash_offset, "export hash table")?,
        );

        // The tables follow the info header back to back: imported libraries, then imported
        // symbols. The relocation headers follow the imported symbols; the relocation
        // instructions they point into are a separate area, at its own offset from the
        // loader section (`reloc_instr_offset`) rather than following the headers.
        let libraries_at = loader_offset + LOADER_INFO_HEADER_SIZE;
        let library_count = header.imported_library_count as usize;
        let symbols_at = libraries_at + IMPORTED_LIBRARY_SIZE * library_count;
        let symbol_count = header.total_imported_symbol_count as usize;
        let relocation_headers_at = symbols_at + IMPORTED_SYMBOL_SIZE * symbol_count;
        let reloc_instr_at =
            offset_of(loader_offset, header.reloc_instr_offset, "relocation instructions")?;

        let libraries = parse_libraries(data, libraries_at, library_count, strings)?;
        let imports = parse_imports(data, symbols_at, symbol_count, &libraries, strings)?;
        let relocations = parse_relocations(
            data,
            relocation_headers_at,
            header.reloc_section_count as usize,
            reloc_instr_at,
            section_count,
        )?;
        let exports = parse_exports(data, loader_offset, &header, strings)?;

        Ok(Self { header, libraries, imports, exports, relocations })
    }

    /// The fragment's main entry point, if it has one.
    ///
    /// `section_data` maps a section index to that section's instantiated contents;
    /// pattern-initialized sections must already be expanded.
    pub fn main(&self, section_data: &[Vec<u8>]) -> Option<PefTransitionVector> {
        transition_vector(self.header.main_section, self.header.main_offset, section_data)
    }

    /// The fragment's initialization routine, if it has one.
    pub fn init(&self, section_data: &[Vec<u8>]) -> Option<PefTransitionVector> {
        transition_vector(self.header.init_section, self.header.init_offset, section_data)
    }

    /// The fragment's termination routine, if it has one.
    pub fn term(&self, section_data: &[Vec<u8>]) -> Option<PefTransitionVector> {
        transition_vector(self.header.term_section, self.header.term_offset, section_data)
    }
}

/// Locate the loader section in a parsed section table.
pub fn loader_section(sections: &[PefSectionHeader]) -> Option<(usize, &PefSectionHeader)> {
    sections.iter().enumerate().find(|(_, s)| s.section_kind == PefSectionKind::Loader)
}

fn offset_of(base: usize, delta: u32, what: &str) -> Result<usize> {
    base.checked_add(delta as usize).with_context(|| format!("Invalid PEF {what} offset"))
}

fn parse_libraries(
    data: &[u8],
    offset: usize,
    count: usize,
    strings: (usize, usize),
) -> Result<Vec<PefImportedLibrary>> {
    (0..count)
        .map(|i| {
            let at = offset + IMPORTED_LIBRARY_SIZE * i;
            let options = u8_at(data, at + 20)?;
            Ok(PefImportedLibrary {
                name: cstr_at(data, strings, be_u32(data, at)?)
                    .context("Reading PEF imported library name")?
                    .to_string(),
                old_imp_version: be_u32(data, at + 4)?,
                current_version: be_u32(data, at + 8)?,
                imported_symbol_count: be_u32(data, at + 12)?,
                first_imported_symbol: be_u32(data, at + 16)?,
                init_before: options & 0x80 != 0,
                weak: options & 0x40 != 0,
            })
        })
        .collect()
}

fn parse_imports(
    data: &[u8],
    offset: usize,
    count: usize,
    libraries: &[PefImportedLibrary],
    strings: (usize, usize),
) -> Result<Vec<PefImport>> {
    let mut imports = Vec::with_capacity(count);
    for library in libraries {
        let start = library.first_imported_symbol as usize;
        let end = start
            .checked_add(library.imported_symbol_count as usize)
            .filter(|&end| end <= count)
            .with_context(|| {
                format!("Imported symbol range for library `{}` is out of bounds", library.name)
            })?;
        for index in start..end {
            let word = be_u32(data, offset + IMPORTED_SYMBOL_SIZE * index)?;
            let class = (word >> 24) as u8;
            imports.push(PefImport {
                library: library.name.clone(),
                name: cstr_at(data, strings, word & NAME_OFFSET_MASK)
                    .context("Reading PEF imported symbol name")?
                    .to_string(),
                class: PefSymbolClass::from_u8(class)?,
                // The high bit of the class byte marks a weak import.
                weak: class & 0x80 != 0,
            });
        }
    }
    Ok(imports)
}

fn parse_exports(
    data: &[u8],
    loader_offset: usize,
    header: &PefLoaderInfoHeader,
    strings: (usize, usize),
) -> Result<Vec<PefExport>> {
    let count = header.exported_symbol_count as usize;
    if count == 0 {
        return Ok(Vec::new());
    }

    // Hash slots, then the key table, then the symbols themselves.
    let slot_count = 1usize
        .checked_shl(header.export_hash_table_power)
        .context("Invalid PEF export hash table size")?;
    let hash_at = offset_of(loader_offset, header.export_hash_offset, "export hash table")?;
    let key_at = hash_at
        .checked_add(EXPORT_HASH_SLOT_SIZE * slot_count)
        .context("Invalid PEF export key table offset")?;
    let symbol_at = key_at
        .checked_add(EXPORT_KEY_SIZE * count)
        .context("Invalid PEF exported symbol table offset")?;

    (0..count)
        .map(|i| {
            // Exported names are not NUL-terminated; their length lives in the key table.
            let name_len = be_u16(data, key_at + EXPORT_KEY_SIZE * i)? as usize;
            let at = symbol_at + EXPORTED_SYMBOL_SIZE * i;
            let word = be_u32(data, at)?;
            let name_at = strings
                .0
                .checked_add((word & NAME_OFFSET_MASK) as usize)
                .context("Invalid PEF exported symbol name offset")?;
            let name = data
                .get(name_at..name_at + name_len)
                .ok_or_else(|| anyhow!("PEF exported symbol name runs past the end of the file"))?;
            Ok(PefExport {
                name: String::from_utf8_lossy(name).into_owned(),
                class: PefSymbolClass::from_u8((word >> 24) as u8)?,
                value: be_u32(data, at + 4)?,
                section_index: be_u16(data, at + 8)?,
            })
        })
        .collect()
}

/// Read the transition vector at `section:offset`.
///
/// A transition vector is two words: the code address and the TOC pointer.
fn transition_vector(
    section: i32,
    offset: u32,
    section_data: &[Vec<u8>],
) -> Option<PefTransitionVector> {
    if section == NO_SECTION {
        return None;
    }
    let contents = usize::try_from(section).ok().and_then(|index| section_data.get(index));
    let word = |at: usize| {
        contents
            .and_then(|c| c.get(at..at + 4))
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    Some(PefTransitionVector {
        section,
        offset,
        code: word(offset as usize),
        toc: word(offset as usize + 4),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::pef::PefFile;
    use crate::util::pef_relocations::{PefRelocationArgs, PefRelocationOpcode};

    const TEST1: &[u8] = include_bytes!("../../assets/pef/test1.pef");

    fn test1_loader() -> (PefFile, PefLoader) {
        let pef = PefFile::parse(TEST1).unwrap();
        let (_, section) = loader_section(&pef.sections).expect("test1 has a loader section");
        let loader =
            PefLoader::parse(TEST1, section.container_offset as usize, pef.sections.len())
                .unwrap();
        (pef, loader)
    }

    #[test]
    fn parses_imported_symbols() {
        let (_, loader) = test1_loader();
        let imports: Vec<(&str, &str)> =
            loader.imports.iter().map(|i| (i.library.as_str(), i.name.as_str())).collect();
        assert_eq!(imports, vec![
            ("InterfaceLib", "NewPtr"),
            ("InterfaceLib", "Gestalt"),
            ("InterfaceLib", "ExitToShell"),
            ("InterfaceLib", "DisposePtr"),
            ("InterfaceLib", "NewPtrClear"),
            ("MathLib", "fabs"),
            ("MathLib", "num2dec"),
        ]);
        assert!(loader.imports.iter().all(|i| i.class == PefSymbolClass::TVector));
        assert!(loader.imports.iter().all(|i| !i.weak));
    }

    #[test]
    fn parses_imported_libraries() {
        let (_, loader) = test1_loader();
        assert_eq!(loader.libraries.len(), 2);
        assert_eq!(loader.libraries[0].name, "InterfaceLib");
        assert_eq!(loader.libraries[0].imported_symbol_count, 5);
        assert_eq!(loader.libraries[0].first_imported_symbol, 0);
        assert_eq!(loader.libraries[1].name, "MathLib");
        assert_eq!(loader.libraries[1].imported_symbol_count, 2);
        assert_eq!(loader.libraries[1].first_imported_symbol, 5);
    }

    #[test]
    fn test1_exports_nothing() {
        let (_, loader) = test1_loader();
        assert_eq!(loader.header.exported_symbol_count, 0);
        assert!(loader.exports.is_empty());
    }

    /// `test1` has a single relocation header covering section 1, whose 69-word instruction
    /// stream decodes into 69 single-word instructions.
    #[test]
    fn parses_relocations() {
        let (_, loader) = test1_loader();
        assert_eq!(loader.header.reloc_section_count, 1);
        assert_eq!(loader.relocations.len(), 69);
        assert!(loader.relocations.iter().all(|r| r.section_index == 1));

        // The stream opens by pulling in all seven imported symbols as one run.
        let first = &loader.relocations[0];
        assert_eq!(first.instruction_offset, 0);
        assert_eq!(first.opcode, PefRelocationOpcode::ImportRun);
        assert!(matches!(first.args, PefRelocationArgs::Run { run_length: 7 }));

        // Every instruction here is a single word, so offsets step by two and the last
        // one ends exactly at the end of the stream.
        for (i, reloc) in loader.relocations.iter().enumerate() {
            assert_eq!(reloc.instruction_offset, i * 2);
            assert_eq!(reloc.opcode.word_count(), 1);
        }
    }

    /// The main symbol is a transition vector in the data section; its first word is the
    /// code address to enter and its second is the TOC pointer.
    #[test]
    fn resolves_main_transition_vector() {
        let (pef, loader) = test1_loader();
        let contents = pef.section_data(TEST1).unwrap();
        let main = loader.main(&contents).expect("test1 has a main symbol");
        assert_eq!(main.section, 1);
        assert_eq!(main.offset, 0x184);
        assert_eq!(main.code, Some(0x5170));
        assert_eq!(main.toc, Some(0));
        assert!(loader.term(&contents).is_none());
    }
}
