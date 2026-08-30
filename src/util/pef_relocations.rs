//! PEF relocation related code, simple relocation machine
//!
//! reference: Mac OS Runtime Architectures for System 7 Through Mac OS 9, January 31 1997.

use anyhow::{anyhow, ensure, Context, Result};

use crate::util::pef::{be_u16, be_u32};

/// On-disk size of [`PefRelocationHeader`].
const RELOCATION_HEADER_SIZE: usize = 12;

/// Where a section's load-time relocations live.
#[derive(Debug, Clone, Copy)]
pub struct PefRelocationHeader {
    /// Section these relocations apply to.
    pub section_index: u16,
    /// Number of 16-bit relocation blocks.
    pub reloc_count: u32,
    /// Byte offset from the relocations area to the first instruction.
    pub first_reloc_offset: u32,
}
/// A relocation instruction's opcode.
///
/// The opcode lives in the high-order 7 bits of the 16-bit instruction word, i.e. in the
/// top byte with its low bit masked off — which is how the values below are written, so
/// they can be matched directly against the first byte using [`Self::mask`].
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PefRelocationOpcode
{
    BySectDWithSkip  = 0x00, /* Binary: 00x_xxxx*/
    BySectC          = 0x40, /* Binary: 010_0000, group is "RelocRun"*/
    BySectD          = 0x42, /* Binary: 010_0001*/
    TVector12        = 0x44, /* Binary: 010_0010*/
    TVector8         = 0x46, /* Binary: 010_0011*/
    VTable8          = 0x48, /* Binary: 010_0100*/
    ImportRun        = 0x4A, /* Binary: 010_0101*/
    SmByImport       = 0x60, /* Binary: 011_0000, group is "RelocSmIndex"*/
    SmSetSectC       = 0x62, /* Binary: 011_0001*/
    SmSetSectD       = 0x64, /* Binary: 011_0010*/
    SmBySection      = 0x66, /* Binary: 011_0011*/
    IncrPosition     = 0x80, /* Binary: 100_0xxx*/
    SmRepeat         = 0x90, /* Binary: 100_1xxx*/
    SetPosition      = 0xA0, /* Binary: 101_000x*/
    LgByImport       = 0xA4, /* Binary: 101_001x*/
    LgRepeat         = 0xB0, /* Binary: 101_100x*/
    LgSetOrBySection = 0xB4, /* Binary: 101_101x*/
    Custom           = 0xC0, /* Binary: 111_xxxx, group is "RelocCustom", unknown*/
    UndefinedOpcode  = 0xFF, /* Used in masking table for all undefined values.*/
}

impl PefRelocationOpcode {
    fn mask (self) -> u8 {
        match self {
            PefRelocationOpcode::BySectDWithSkip  => 0b1100_0000,
            PefRelocationOpcode::BySectC          => 0b1111_1110,
            PefRelocationOpcode::BySectD          => 0b1111_1110,
            PefRelocationOpcode::TVector12        => 0b1111_1110,
            PefRelocationOpcode::TVector8         => 0b1111_1110,
            PefRelocationOpcode::VTable8          => 0b1111_1110,
            PefRelocationOpcode::ImportRun        => 0b1111_1110,
            PefRelocationOpcode::SmByImport       => 0b1111_1110,
            PefRelocationOpcode::SmSetSectC       => 0b1111_1110,
            PefRelocationOpcode::SmSetSectD       => 0b1111_1110,
            PefRelocationOpcode::SmBySection      => 0b1111_1110,
            PefRelocationOpcode::IncrPosition     => 0b1111_0000,
            PefRelocationOpcode::SmRepeat         => 0b1111_0000,
            PefRelocationOpcode::SetPosition      => 0b1111_1100,
            PefRelocationOpcode::LgByImport       => 0b1111_1100,
            PefRelocationOpcode::LgRepeat         => 0b1111_1100,
            PefRelocationOpcode::LgSetOrBySection => 0b1111_1100,
            PefRelocationOpcode::Custom           => 0b1110_0000,
            _ => 0xFF, // Undefined opcode
        }
    }
    fn matches (self, byte: u8) -> bool {
        (byte & self.mask()) == (self as u8)
    }

    /// Number of 16-bit words
    pub fn word_count(self) -> usize {
        match self {
            Self::SetPosition | Self::LgByImport | Self::LgRepeat | Self::LgSetOrBySection => 2,
            _ => 1,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::BySectDWithSkip => "RelocBySectDWithSkip",
            Self::BySectC => "RelocBySectC",
            Self::BySectD => "RelocBySectD",
            Self::TVector12 => "RelocTVector12",
            Self::TVector8 => "RelocTVector8",
            Self::VTable8 => "RelocVTable8",
            Self::ImportRun => "RelocImportRun",
            Self::SmByImport => "RelocSmByImport",
            Self::SmSetSectC => "RelocSmSetSectC",
            Self::SmSetSectD => "RelocSmSetSectD",
            Self::SmBySection => "RelocSmBySection",
            Self::IncrPosition => "RelocIncrPosition",
            Self::SmRepeat => "RelocSmRepeat",
            Self::SetPosition => "RelocSetPosition",
            Self::LgByImport => "RelocLgByImport",
            Self::LgRepeat => "RelocLgRepeat",
            Self::LgSetOrBySection => "RelocLgSetOrBySection",
            Self::Custom => "RelocCustom",
            Self::UndefinedOpcode => "RelocUndefinedOpcode",
        }
    }
}

/// The subopcode of a [`PefRelocationOpcode::LgSetOrBySection`] instruction, which is the
/// one opcode whose three cases share a single 7-bit encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PefLgSubopcode {
    /// Relocate one word by the address of the section named by `index`.
    LgBySection = 0,
    /// Set `sectionC` to the address of the section named by `index`.
    LgSetSectC = 1,
    /// Set `sectionD` to the address of the section named by `index`.
    LgSetSectD = 2,
}

impl PefLgSubopcode {
    fn from_u8(value: u8) -> Result<Self> {
        Ok(match value {
            0 => Self::LgBySection,
            1 => Self::LgSetSectC,
            2 => Self::LgSetSectD,
            v => return Err(anyhow!("Unknown PEF RelocLgSetOrBySection subopcode {}", v)),
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::LgBySection => "RelocLgBySection",
            Self::LgSetSectC => "RelocLgSetSectC",
            Self::LgSetSectD => "RelocLgSetSectD",
        }
    }
}

const PEF_RELOCATION_OPCODE_TABLE: [PefRelocationOpcode; 18] = [
    PefRelocationOpcode::BySectDWithSkip,
    PefRelocationOpcode::BySectC,
    PefRelocationOpcode::BySectD,
    PefRelocationOpcode::TVector12,
    PefRelocationOpcode::TVector8,
    PefRelocationOpcode::VTable8,
    PefRelocationOpcode::ImportRun,
    PefRelocationOpcode::SmByImport,
    PefRelocationOpcode::SmSetSectC,
    PefRelocationOpcode::SmSetSectD,
    PefRelocationOpcode::SmBySection,
    PefRelocationOpcode::IncrPosition,
    PefRelocationOpcode::SmRepeat,
    PefRelocationOpcode::SetPosition,
    PefRelocationOpcode::LgByImport,
    PefRelocationOpcode::LgRepeat,
    PefRelocationOpcode::LgSetOrBySection,
    PefRelocationOpcode::Custom,
];

/// The decoded operands of a relocation instruction.
///
/// Counts the format stores biased by one (`runLength - 1`, `offset - 1`, and so on) are
/// un-biased here, so every value below is the effective one.
#[derive(Debug, Clone, Copy)]
pub enum PefRelocationArgs {
    /// [`PefRelocationOpcode::BySectDWithSkip`]: skip `skip_count` words, then relocate
    /// `reloc_count` contiguous words by `sectionD`.
    SkipAndRelocate { skip_count: u16, reloc_count: u16 },
    /// The "relocate value" group: a run of `run_length` items.
    Run { run_length: u16 },
    /// The small "relocate by index" group: a 9-bit section or import index.
    Index { index: u16 },
    /// [`PefRelocationOpcode::IncrPosition`]: advance the relocation address by `offset`
    /// bytes, or [`PefRelocationOpcode::SetPosition`]: set it to `offset`.
    Offset { offset: u32 },
    /// A repeat instruction: re-execute the preceding `block_count` instruction blocks
    /// `repeat_count` more times.
    Repeat { block_count: u16, repeat_count: u32 },
    /// [`PefRelocationOpcode::LgByImport`]: a 26-bit import index.
    LargeIndex { index: u32 },
    /// [`PefRelocationOpcode::LgSetOrBySection`]: a subopcode plus a 22-bit section index.
    LargeSection { subopcode: PefLgSubopcode, index: u32 },
    /// The instruction carries no operands, or none that are understood.
    None,
}

/// One decoded relocation instruction.
#[derive(Debug, Clone, Copy)]
pub struct PefRelocation {
    /// Byte offset of this instruction within its section's relocation stream.
    pub instruction_offset: usize,
    /// The raw instruction word, or both words packed big-endian for the long forms.
    pub raw: u32,
    /// Section these relocations apply to.
    pub section_index: u16,
    /// The opcode of the relocation instruction.
    pub opcode: PefRelocationOpcode,
    /// The decoded operands.
    pub args: PefRelocationArgs,
}

impl PefRelocation {
    /// Every decoded field, ready to print. Mirrors `TracebackTable::fields`.
    pub fn fields(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("Opcode", self.opcode.name().to_string()),
            ("Stream offset", format!("{:#X}", self.instruction_offset)),
            ("Raw", match self.opcode.word_count() {
                2 => format!("{:#010X}", self.raw),
                _ => format!("{:#06X}", self.raw),
            }),
        ];
        match self.args {
            PefRelocationArgs::SkipAndRelocate { skip_count, reloc_count } => {
                out.push(("Skip count", skip_count.to_string()));
                out.push(("Reloc count", reloc_count.to_string()));
            }
            PefRelocationArgs::Run { run_length } => {
                out.push(("Run length", run_length.to_string()));
            }
            PefRelocationArgs::Index { index } => {
                out.push(("Index", index.to_string()));
            }
            PefRelocationArgs::Offset { offset } => {
                out.push(("Offset", format!("{offset:#X}")));
            }
            PefRelocationArgs::Repeat { block_count, repeat_count } => {
                out.push(("Block count", block_count.to_string()));
                out.push(("Repeat count", repeat_count.to_string()));
            }
            PefRelocationArgs::LargeIndex { index } => {
                out.push(("Index", index.to_string()));
            }
            PefRelocationArgs::LargeSection { subopcode, index } => {
                out.push(("Subopcode", subopcode.name().to_string()));
                out.push(("Index", index.to_string()));
            }
            PefRelocationArgs::None => {}
        }
        out
    }
}

pub struct PefRelocationVm<'a> {
    pub bytecode: &'a [u8],
    pub bytecode_offset: usize,
    pub section_base_address: u32,
    pub import_index: u16,
    pub section_c: u32,
    pub section_d: u32,
}

impl <'a> PefRelocationVm<'a> {
    pub fn parse(bytecode: &'a [u8], section_index : u16) -> Result<Vec<PefRelocation>> {
        let mut relocations = Vec::new();
        let mut vm = PefRelocationVm { bytecode, bytecode_offset: 0, section_base_address: 0, import_index: 0, section_c: 0, section_d: 0 };
        while vm.bytecode_offset < bytecode.len() {
            relocations.push(vm.next_instruction(section_index)?);
        }
        Ok(relocations)
    }

    /// Decode the instruction at the current offset and advance past it.
    fn next_instruction(&mut self, section_index: u16) -> Result<PefRelocation> {
        let instruction_offset = self.bytecode_offset;
        let opcode = self
            .next_opcode()
            .with_context(|| format!("PEF relocation instruction at {instruction_offset:#X}"))?;

        let word = be_u16(self.bytecode, instruction_offset).with_context(|| {
            format!("Reading PEF relocation instruction at {instruction_offset:#X}")
        })? as u32;

        // The long forms carry their operand across a second word.
        let raw = match opcode.word_count() {
            2 => {
                let low = be_u16(self.bytecode, instruction_offset + 2).with_context(|| {
                    format!(
                        "Reading second word of PEF relocation instruction at \
                         {instruction_offset:#X}"
                    )
                })? as u32;
                (word << 16) | low
            }
            _ => word,
        };
        // The operand of a long form: the first word's spare low bits, then the whole
        // second word. `raw` already holds exactly that layout.
        let long_operand = |bits: u32| raw & ((1 << (16 + bits)) - 1);

        let args = match opcode {
            // 00 | skipCount (8) | relocCount (6)
            PefRelocationOpcode::BySectDWithSkip => PefRelocationArgs::SkipAndRelocate {
                skip_count: ((word & 0b0011_1111_1100_0000) >> 6) as u16,
                reloc_count: (word & 0b0000_0000_0011_1111) as u16,
            },

            // 010 | subopcode (4) | runLength - 1 (9). The subopcode is already folded
            // into the opcode, so only the run length is left to read.
            PefRelocationOpcode::BySectC
            | PefRelocationOpcode::BySectD
            | PefRelocationOpcode::TVector12
            | PefRelocationOpcode::TVector8
            | PefRelocationOpcode::VTable8
            | PefRelocationOpcode::ImportRun => {
                PefRelocationArgs::Run { run_length: ((word & 0b0000_0001_1111_1111) + 1) as u16 }
            }

            // 011 | subopcode (4) | index (9)
            PefRelocationOpcode::SmByImport
            | PefRelocationOpcode::SmSetSectC
            | PefRelocationOpcode::SmSetSectD
            | PefRelocationOpcode::SmBySection => {
                PefRelocationArgs::Index { index: (word & 0b0000_0001_1111_1111) as u16 }
            }

            // 1000 | offset - 1 (12)
            PefRelocationOpcode::IncrPosition => {
                PefRelocationArgs::Offset { offset: (word & 0b0000_1111_1111_1111) + 1 }
            }

            // 1001 | blockCount - 1 (4) | repeatCount - 1 (8)
            PefRelocationOpcode::SmRepeat => PefRelocationArgs::Repeat {
                block_count: (((word & 0b0000_1111_0000_0000) >> 8) + 1) as u16,
                repeat_count: (word &  0b0000_0000_1111_1111) + 1,
            },

            // 101000 | offset (26, across both words)
            PefRelocationOpcode::SetPosition => {
                PefRelocationArgs::Offset { offset: long_operand(10) }
            }

            // 101001 | index (26, across both words)
            PefRelocationOpcode::LgByImport => {
                PefRelocationArgs::LargeIndex { index: long_operand(10) }
            }

            // 101100 | blockCount - 1 (4) | repeatCount (22, across both words)
            PefRelocationOpcode::LgRepeat => PefRelocationArgs::Repeat {
                block_count: (((word & 0b0000_0011_1100_0000) >> 6) + 1) as u16,
                repeat_count: long_operand(6),
            },

            // 101101 | subopcode (4) | index (22, across both words)
            PefRelocationOpcode::LgSetOrBySection => PefRelocationArgs::LargeSection {
                subopcode: PefLgSubopcode::from_u8(((word & 0b0000_0011_1100_0000) >> 6) as u8)?,
                index: long_operand(6),
            },

            PefRelocationOpcode::Custom | PefRelocationOpcode::UndefinedOpcode => {
                PefRelocationArgs::None
            }
        };

        self.bytecode_offset += 2 * opcode.word_count();
        Ok(PefRelocation { instruction_offset, raw, section_index, opcode, args })
    }
    fn next_opcode(&mut self) -> Option<PefRelocationOpcode> {
        let probe_byte = *self.bytecode.get(self.bytecode_offset)?;
        PEF_RELOCATION_OPCODE_TABLE.iter().find(|&&opcode| opcode.matches(probe_byte)).copied()
    }
}

/// Parse the relocations from the PEF file data,
pub(crate) fn parse_relocations(
    data: &[u8],
    header_offset: usize,
    header_count: usize,
    reloc_instr_at: usize,
    section_count: usize,
) -> Result<Vec<PefRelocation>> {
    let mut relocations = Vec::new();
    for i in 0..header_count {
        let at = header_offset + RELOCATION_HEADER_SIZE * i;
        let section_index = be_u16(data, at)
            .with_context(|| format!("Reading PEF relocation header {i} section index"))?;
        let reloc_count = be_u32(data, at + 4)
            .with_context(|| format!("Reading PEF relocation header {i} count"))?;
        let first_reloc_offset = be_u32(data, at + 8)
            .with_context(|| format!("Reading PEF relocation header {i} first offset"))?;
        ensure!(
            (section_index as usize) < section_count,
            "PEF relocation header {i} section index {section_index} is out of bounds \
             ({section_count} section(s) in file)"
        );

        let start = reloc_instr_at
            .checked_add(first_reloc_offset as usize)
            .with_context(|| format!("PEF relocation header {i} instruction offset"))?;
        let len = (reloc_count as usize)
            .checked_mul(2)
            .with_context(|| format!("PEF relocation header {i} instruction length"))?;
        let end = start
            .checked_add(len)
            .with_context(|| format!("PEF relocation header {i} instruction range"))?;
        ensure!(
            end <= data.len(),
            "PEF relocation header {i} instructions run past the end of the file"
        );

        let relocs = PefRelocationVm::parse(&data[start..end], section_index)
            .with_context(|| format!("Parsing PEF relocation header {i} instructions"))?;
        relocations.extend(relocs);
    }
    Ok(relocations)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The relocation instruction stream of `assets/pef/test1.pef`: 69 single-word
    /// instructions covering section 1.
    const TEST1_STREAM: [u8; 138] = [
        0x4A, 0x06, 0x42, 0x01, 0x40, 0x01, 0x42, 0x04, 0x40, 0x00, 0x42, 0x04, 0x40, 0x01, 0x42,
        0x01, 0x40, 0x01, 0x42, 0x06, 0x40, 0x03, 0x42, 0x01, 0x40, 0x00, 0x42, 0x01, 0x40, 0x00,
        0x42, 0x00, 0x40, 0x02, 0x42, 0x03, 0x40, 0x00, 0x42, 0x00, 0x00, 0xC2, 0x80, 0x0B, 0x46,
        0x14, 0x02, 0xC1, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x01, 0x41,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x04, 0x41, 0x80, 0x1B, 0x40, 0x00, 0x80, 0x1F, 0x40,
        0x00, 0x80, 0x03, 0x40, 0x7B, 0x42, 0x00, 0x00, 0x43, 0x80, 0x0B, 0x40, 0x00, 0x42, 0x01,
        0x00, 0x42, 0x40, 0x00, 0x00, 0xC1, 0x00, 0x43, 0x80, 0x0B, 0x40, 0x00, 0x42, 0x00, 0x40,
        0x08, 0x80, 0x07, 0x40, 0x00, 0x80, 0x0F, 0x40, 0x05, 0x42, 0x01, 0x08, 0x81, 0x80, 0x0B,
        0x40, 0x05, 0x80, 0x07, 0x40, 0x00, 0x80, 0x0F, 0x40, 0x02, 0x80, 0x07, 0x40, 0x07, 0x03,
        0x45, 0x40, 0x9A,
    ];

    #[test]
    fn decodes_every_instruction_in_the_stream() {
        let relocs = PefRelocationVm::parse(&TEST1_STREAM, 1).unwrap();
        assert_eq!(relocs.len(), 69);
        assert!(relocs.iter().all(|r| r.section_index == 1));

        // Single-word instructions throughout, so the offsets step by two and the last one
        // ends exactly at the end of the stream: proof the decoder never lost sync.
        for (i, reloc) in relocs.iter().enumerate() {
            assert_eq!(reloc.instruction_offset, i * 2);
            assert_eq!(reloc.opcode.word_count(), 1);
        }
        let last = relocs.last().unwrap();
        assert_eq!(last.instruction_offset + 2 * last.opcode.word_count(), TEST1_STREAM.len());
    }

    #[test]
    fn decodes_operands() {
        let relocs = PefRelocationVm::parse(&TEST1_STREAM, 1).unwrap();

        // 0x4A06: RelocImportRun, runLength - 1 = 6.
        assert_eq!(relocs[0].opcode, PefRelocationOpcode::ImportRun);
        assert_eq!(relocs[0].raw, 0x4A06);
        assert!(matches!(relocs[0].args, PefRelocationArgs::Run { run_length: 7 }));

        // 0x4201: RelocBySectD, runLength - 1 = 1.
        assert_eq!(relocs[1].opcode, PefRelocationOpcode::BySectD);
        assert!(matches!(relocs[1].args, PefRelocationArgs::Run { run_length: 2 }));

        // 0x00C2: RelocBySectDWithSkip, skipCount = 3, relocCount = 2.
        let skip = &relocs[20];
        assert_eq!(skip.opcode, PefRelocationOpcode::BySectDWithSkip);
        assert_eq!(skip.raw, 0x00C2);
        assert!(matches!(
            skip.args,
            PefRelocationArgs::SkipAndRelocate { skip_count: 3, reloc_count: 2 }
        ));

        // 0x800B: RelocIncrPosition, offset - 1 = 0xB.
        let incr = &relocs[21];
        assert_eq!(incr.opcode, PefRelocationOpcode::IncrPosition);
        assert!(matches!(incr.args, PefRelocationArgs::Offset { offset: 0xC }));
    }

    /// The opcode histogram guards against a decoder that desyncs: a mis-sized instruction
    /// would shift every following opcode and change these counts.
    #[test]
    fn opcode_histogram() {
        let relocs = PefRelocationVm::parse(&TEST1_STREAM, 1).unwrap();
        let count =
            |op: PefRelocationOpcode| relocs.iter().filter(|r| r.opcode == op).count();
        assert_eq!(count(PefRelocationOpcode::BySectDWithSkip), 18);
        assert_eq!(count(PefRelocationOpcode::BySectC), 23);
        assert_eq!(count(PefRelocationOpcode::BySectD), 14);
        assert_eq!(count(PefRelocationOpcode::IncrPosition), 12);
        assert_eq!(count(PefRelocationOpcode::TVector8), 1);
        assert_eq!(count(PefRelocationOpcode::ImportRun), 1);
    }

    #[test]
    fn rejects_an_undefined_opcode() {
        // 0xE0 matches no entry in the opcode table.
        assert!(PefRelocationVm::parse(&[0xE0, 0x00], 0).is_err());
    }

    #[test]
    fn rejects_a_truncated_long_form() {
        // 0xA0 is RelocSetPosition, a two-word form, with only one word available.
        assert!(PefRelocationVm::parse(&[0xA0, 0x00], 0).is_err());
    }

    #[test]
    fn fields_and_summary_render_operands() {
        let relocs = PefRelocationVm::parse(&TEST1_STREAM, 1).unwrap();
        let fields = relocs[0].fields();
        assert_eq!(fields[0], ("Opcode", "RelocImportRun".to_string()));
        assert!(fields.iter().any(|(k, v)| *k == "Run length" && v == "7"));
    }
}
