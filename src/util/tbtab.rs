use anyhow::{anyhow, bail, ensure, Result};

use std::io::{ Cursor, Read };
use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug)]
pub enum Language {
    C = 0,
    Fortran = 1,
    Pascal = 2,
    Ada = 3,
    Pl1 = 4,
    Basic = 5,
    Lisp = 6,
    Cobol = 7,
    Modula2 = 8,
    Cpp = 9,
    Rpg = 10,
    Pl8 = 11,
    Asm = 12,
}

impl std::convert::TryFrom<u8> for Language {
    type Error = u8; 
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0  => Ok(Language::C),
            1  => Ok(Language::Fortran),
            2  => Ok(Language::Pascal),
            3  => Ok(Language::Ada),
            4  => Ok(Language::Pl1),
            5  => Ok(Language::Basic),
            6  => Ok(Language::Lisp),
            7  => Ok(Language::Cobol),
            8  => Ok(Language::Modula2),
            9  => Ok(Language::Cpp),
            10 => Ok(Language::Rpg),
            11 => Ok(Language::Pl8),
            12 => Ok(Language::Asm),
            other => Err(other),
        }
    }
}

pub enum OnConditionDirective {
    WalkOnCond	= 0,	/* Walk the stack without restoring state */
    DiscardOnCond = 1,	/* Walk the stack and discard */
    InvokeOnCond =	2,	/* Invoke a specific system routine */
}

#[repr(C, packed)]
pub struct TracebackTableShort {
    reserved:                  i32, // always 0
    type_:                     u8,  // traceback format version, should be 0
    language:                  u8,   
    flags1:                    u8,
    flags2:                    u8,
    flags3:                    u8,
    flags4:                    u8,
    number_of_fixed_parms:     u8,
    flags5:                    u8,
}

impl TracebackTableShort {
    // flags1
    // TODO, for little endian
    const GLOBAL_LINKAGE:              u8 = 0b1000_0000; // Set if routine is global linkage
    const OUT_OF_LINE_EPILOG_PRO:      u8 = 0b0100_0000; // Set if is out-of-line epilog/prologue 
    const HAS_TB_TABLE_OFFSET:         u8 = 0b0010_0000; // Set if offset from start of proc stored
    const INTERNAL_PROCEDURE:          u8 = 0b0001_0000; // Set if routine is internal
    const CONTROLLED_STORAGE:          u8 = 0b0000_1000; // Set if routine involves controlled storage
    const TOCLESS:                     u8 = 0b0000_0100; // Set if routine contains no TOC
    const FP_PRESENT:                  u8 = 0b0000_0010; // Set if routine performs FP operations
    const FP_LOG_OR_ABORT:             u8 = 0b0000_0001; // Set if routine logs or aborts FP ops

    // flags2
    const INTERRUPT_HANDLER:           u8 = 0b1000_0000; // Set if routine is interrupt handler
    const FN_NAME_PRESENT:             u8 = 0b0100_0000; // Set if name is present in proc table 
    const ALLOCA_USED:                 u8 = 0b0010_0000; // Set if alloca used to allocate storage
    const ON_COND_DIRECTIVE_MASK:      u8 = 0b0001_1100; // On-condition directives
    const CRSAVED:                     u8 = 0b0000_0010; // Set if procedure saves the condition reg
    const LRSAVED:                     u8 = 0b0000_0001; // Set if procedure saves the link reg

    // flags3
    const BACKCHAIN_STORED:            u8 = 0b1000_0000; // Set if procedure stores the backchain
    const FIXUP:                       u8 = 0b0100_0000; // Set if code is generated fixup code
    const FPRSAVED_MASK:               u8 = 0b0011_1111; // Number of FPRs saved, max of 32

    // flags4
    const HAS_EXT_TABLE:               u8 = 0b1000_0000; // 
    const HAS_VECTOR_INFO:             u8 = 0b0100_0000; // 
    const GPR_SAVED_MASK:              u8 = 0b0011_1111; // Number of GPRs saved, max of 32

    // flags5
    const FP_PARMS_MASK:               u8 = 0b1111_1110; // Number of floating point parameters
    const PARMS_ON_STACK:              u8 = 0b0000_0001; // Set if all parameters placed on stack

    // tb_offset is offset inside section_data
    pub fn read(tb_data: &[u8]) -> anyhow::Result<Self> {

        Ok(Self {
            reserved: i32::from_be_bytes(tb_data[0..4].try_into()?),
            type_:                 tb_data[4],
            language:              tb_data[5],
            flags1:                tb_data[6],
            flags2:                tb_data[7],
            flags3:                tb_data[8],
            flags4:                tb_data[9],
            number_of_fixed_parms: tb_data[10],
            flags5:                tb_data[11],
        })
    }

    pub fn size() -> usize {
        std::mem::size_of::<Self>()
    }

    pub fn language(&self) -> Result<Language> {
        match Language::try_from(self.language) {
            Ok(lang)   => Ok(lang),
            Err(unknown_lang) => Err(anyhow!("Unknown language value: {}", unknown_lang)),
        }
    }

    // flags1
    pub fn is_global_linkage(&self) -> bool { self.flags1 & Self::GLOBAL_LINKAGE != 0 }
    pub fn is_out_of_line_prolog_epilog(&self) -> bool { self.flags1 & Self::OUT_OF_LINE_EPILOG_PRO != 0 }
    pub fn has_traceback_table_offset(&self) -> bool { self.flags1 & Self::HAS_TB_TABLE_OFFSET != 0 }
    pub fn is_internal_procedure(&self) -> bool { self.flags1 & Self::INTERNAL_PROCEDURE != 0 }
    pub fn has_controlled_storage(&self) -> bool { self.flags1 & Self::CONTROLLED_STORAGE != 0 }
    pub fn is_tocless(&self) -> bool { self.flags1 & Self::TOCLESS != 0 }
    pub fn is_floating_point_present(&self) -> bool { self.flags1 & Self::FP_PRESENT != 0 }
    pub fn log_abort_fp(&self) -> bool { self.flags1 & Self::FP_LOG_OR_ABORT != 0 }

    // flags2
    pub fn is_interupt_handler(&self) -> bool { self.flags2 & Self::INTERRUPT_HANDLER != 0 }
    pub fn name_present(&self) -> bool { self.flags2 & Self::FN_NAME_PRESENT != 0 }
    pub fn uses_alloca(&self) -> bool { self.flags2 & Self::ALLOCA_USED != 0 }
    pub fn on_condition_directive(&self) -> u8 { (self.flags2 & Self::ON_COND_DIRECTIVE_MASK) >> 2 }
    pub fn cr_saved(&self) -> bool { self.flags2 & Self::CRSAVED != 0 }
    pub fn lr_saved(&self) -> bool { self.flags2 & Self::LRSAVED != 0 }

    // flags3
    pub fn stores_bc(&self) -> bool { self.flags3 & Self::BACKCHAIN_STORED != 0 }
    pub fn is_fixup(&self) -> bool { self.flags3 & Self::FIXUP != 0 }
    pub fn fp_regs_saved(&self) -> u8 { self.flags3 & Self::FPRSAVED_MASK }

    // flags4
    pub fn has_ext_table(&self) -> bool { self.flags4 & Self::HAS_EXT_TABLE != 0 }
    pub fn has_vector_info(&self) -> bool { self.flags4 & Self::HAS_VECTOR_INFO != 0 }
    pub fn gpr_regs_saved(&self) -> u8 { self.flags4 & Self::GPR_SAVED_MASK }

    pub fn get_number_of_fixed_parms(&self) -> u8 { self.number_of_fixed_parms }

    // flags5
    pub fn get_number_of_fp_parms(&self) -> u8 { self.flags5 & Self::FP_PARMS_MASK >> 1 }
    pub fn params_on_stack(&self) -> bool { self.flags5 & Self::PARMS_ON_STACK != 0 }

}

/// more info at retro68/gcc/gcc/config/rs6000/rs6000-logue.cc
#[repr(C, packed)]
pub struct TracebackTable {
    pub short:                     TracebackTableShort,
    pub parm_info:                 Option<u32>,     // Order and type encoding of parameters:
                                                    // Left-justified bit-encoding as follows:
                                                    // '0'  ==> fixed parameter
                                                    // '10' ==> single-precision float parameter
                                                    // '11' ==> double-precision float parameter
    pub fnc_size:                  Option<u32>,     // Offset from start of code to tb table
    pub hand_mask:                 Option<i32>,     // What interrupts are handled by
    pub ctl_info:                  Option<Vec<i32>>,// CTL anchors
    pub name:                      Option<String>,
    pub alloca_reg:                Option<i8>,      // Register for alloca automatic storage 
    ext_size:                      usize,
}

impl TracebackTable {
    pub fn read(section_data: &[u8], tb_offset: usize) -> Option<Self> {

        let extended_tb_offset = tb_offset.checked_add(TracebackTableShort::size())?;
        let short_tb_frame = section_data.get(tb_offset..extended_tb_offset)?;
        let _zero = short_tb_frame
                    .get(..4)?
                    .try_into().ok().map(|arr: [u8; 4]| arr) 
                    .map(u32::from_be_bytes)
                    .filter(|&v| v == 0)?;

        let short_tb = TracebackTableShort::read(short_tb_frame).ok()?;
        let mut ext_tb_cur = Cursor::new(&section_data[extended_tb_offset..]);

        let parm_info_ = (short_tb.get_number_of_fixed_parms() > 0 || short_tb.get_number_of_fp_parms() > 0)
            .then(|| ext_tb_cur.read_u32::<BigEndian>().ok())
            .flatten();

        let mut fnc_size_= (short_tb.has_traceback_table_offset())
            .then(|| ext_tb_cur.read_u32::<BigEndian>().ok())
            .flatten();

        let mut hand_mask_= (short_tb.is_interupt_handler())
            .then(|| ext_tb_cur.read_i32::<BigEndian>().ok())
            .flatten();

        let ctl_info_ = short_tb.has_controlled_storage()
            .then(|| {
                ext_tb_cur.read_i32::<BigEndian>().ok().and_then(|cnt| {
                    let cnt = cnt as usize;
                    let mut v = Vec::with_capacity(cnt);
                    for _ in 0..cnt {
                        v.push(ext_tb_cur.read_i32::<BigEndian>().ok()?);
                    }
                    Some(v)
                })
            })
            .flatten();

        let name_ = short_tb.name_present()
            .then(|| {
                ext_tb_cur.read_u16::<BigEndian>().ok().and_then(|len| {
                    let len = len as usize;
                    let mut buf = vec![0; len];
                    ext_tb_cur.read_exact(&mut buf).ok()?;
                    String::from_utf8(buf).ok()
                })
            })
            .flatten();

        if let Some(ref name) = name_ {
            log::trace!("{}", name);
        }
        
        let alloca_reg_ = short_tb.uses_alloca()
            .then(|| ext_tb_cur.read_i8().ok())
            .flatten();

        let ext_tb_size = ext_tb_cur.position() as usize;

        /*
        log::trace!(
           "tb_offset 0x{:x}
           is_global_linkage {}
           is_out_of_line_prolog_epilog {}
           has_traceback_table_offset {}
           is_internal_procedure {}
           has_controlled_storage {}
           is_tocless {}
           is_floating_point_present {}
           log_abort_fp {}
           is_interupt_handler {}
           name_present {}
           uses_alloca {}
           on_condition_directive {}
           cr_saved {}
           lr_saved {}
           stores_bc {}
           is_fixup {}
           fp_regs_saved {}
           has_ext_table {}
           has_vector_info {}
           gpr_regs_saved {}
           get_number_of_fixed_parms {} 
           get_number_of_fp_parms {} 
           params_on_stack {}
           ",
           tb_offset,
           short_tb.is_global_linkage() as u8,
           short_tb.is_out_of_line_prolog_epilog() as u8,
           short_tb.has_traceback_table_offset() as u8,
           short_tb.is_internal_procedure() as u8,
           short_tb.has_controlled_storage() as u8,
           short_tb.is_tocless() as u8,
           short_tb.is_floating_point_present() as u8,
           short_tb.log_abort_fp() as u8,
           short_tb.is_interupt_handler() as u8,
           short_tb.name_present() as u8,
           short_tb.uses_alloca() as u8,
           short_tb.on_condition_directive() as u8,
           short_tb.cr_saved() as u8,
           short_tb.lr_saved() as u8,
           short_tb.stores_bc() as u8,
           short_tb.is_fixup() as u8,
           short_tb.fp_regs_saved() as u8,
           short_tb.has_ext_table() as u8,
           short_tb.has_vector_info() as u8,
           short_tb.gpr_regs_saved() as u8,
           short_tb.get_number_of_fixed_parms() as u8,
           short_tb.get_number_of_fp_parms() as u8,
           short_tb.params_on_stack() as u8,
        );
        */
        Some(Self {
            short:                     short_tb,
            parm_info:                 parm_info_,
            fnc_size:                  fnc_size_, 
            hand_mask:                 hand_mask_,
            ctl_info:                  ctl_info_,
            name:                      name_,
            alloca_reg:                alloca_reg_, 
            ext_size:                  ext_tb_size,
        })
    }

    pub fn size(&self) -> usize {
        (std::mem::size_of::<TracebackTableShort>() + self.ext_size + 3) & !3 // 4 byte aligned 
    }
}
