use std::{
    collections::BTreeMap, error::Error, io::{self, Cursor, Read, Seek}
};

use anyhow::{anyhow, bail, ensure, Result};

use crate::{
    analysis::cfa::{locate_bss_memsets, locate_sda_bases, SectionAddress},
    array_ref,
    obj::{
        ObjArchitecture, ObjInfo, ObjKind, ObjSection, ObjSectionKind, ObjSymbol, ObjSymbolFlagSet,
        ObjSymbolFlags, ObjSymbolKind, SectionIndex,
    },
    util::{
        alf::{AlfFile, AlfSymbol, ALF_MAGIC},
        align_up,
        reader::{skip_bytes, Endian, FromReader},
    },
};

use object::{Object, ObjectSection, SectionKind};

pub fn process_pef(buf: &[u8], name: &str) -> Result<ObjInfo> {
    let pef = object::read::pef::PefFile::parse(&*buf)?;

    let mut sections = vec![];
    for pef_section in pef.sections() {
        
        let (name_str, kind) = match pef_section.kind() {
            SectionKind::Text => Ok((pef_section.name()?, ObjSectionKind::Code)),
            SectionKind::Data => Ok((pef_section.name()?, ObjSectionKind::Data)),
            SectionKind::Metadata => Ok((pef_section.name()?, ObjSectionKind::ReadOnlyData)),
            _ => Err(anyhow!("unknown section type")),
        }?;
    
        let name = name_str.to_string();
        sections.push(ObjSection {
            name,
            kind,
            address: pef_section.address() as u64,
            size: pef_section.size() as u64,
            data: pef_section.data().expect("Could not get section data").to_vec(),
            align: 0,
            elf_index: 0,
            relocations: Default::default(),
            virtual_address: Some(pef_section.address() as u64),
            file_offset: pef_section.address() as u64,
            section_known: true,
            splits: Default::default(),
        });
    }
    let obj = ObjInfo::new(
        ObjKind::Executable,
        ObjArchitecture::PowerPc,
        name.to_string(),
        vec![],
        sections,
    );
    Ok(obj)
}
