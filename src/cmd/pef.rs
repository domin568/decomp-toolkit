use std::fs;

use anyhow::{Context, Result};
use argp::FromArgs;
use cwdemangle::{demangle, DemangleOptions};
use typed_path::Utf8NativePathBuf;

use crate::{
    analysis::cfa::AnalyzerState,
    obj::ObjInfo,
    util::{
        config::is_auto_symbol,
        path::native_path,
        pef::{process_pef, PefFile},
        pef_loader::{loader_section, PefLoader, PefTransitionVector},
        IntoCow, ToCow,
    },
};

#[derive(FromArgs, PartialEq, Debug)]
/// Commands for processing PEF files.
#[argp(subcommand, name = "pef")]
pub struct Args {
    #[argp(subcommand)]
    command: SubCommand,
}

#[derive(FromArgs, PartialEq, Debug)]
#[argp(subcommand)]
enum SubCommand {
    Info(InfoArgs),
}

#[derive(FromArgs, PartialEq, Eq, Debug)]
/// Prints information about an PEF file.
#[argp(subcommand, name = "info")]
pub struct InfoArgs {
    #[argp(positional, from_str_fn(native_path))]
    /// input file
    input: Utf8NativePathBuf,
}

pub fn run(args: Args) -> Result<()> {
    match args.command {
        SubCommand::Info(c_args) => info(c_args),
    }
}

fn info(args: InfoArgs) -> Result<()> {
    let in_buf = fs::read(&args.input)
        .with_context(|| format!("Failed to open input file: '{}'", args.input))?;

    let pef = PefFile::parse(&in_buf)?;
    let contents = pef.section_data(&in_buf)?;

    print_container(&pef);
    print_sections(&pef);

    if let Some((index, section)) = loader_section(&pef.sections) {
        let loader =
            PefLoader::parse(&in_buf, section.container_offset as usize, pef.sections.len())
                .with_context(|| format!("Parsing PEF loader section {index}"))?;
        print_loader(&loader, &contents);
    } else {
        println!("\nNo loader section.");
    }

    let mut obj = process_pef(&in_buf, "")?;
    let mut state = AnalyzerState::default();
    state.detect_functions(&obj)?;
    state.apply(&mut obj)?;

    print_symbols(&obj);
    print_traceback_tables(&state);

    println!("\n{} discovered functions from exception table", obj.known_functions.len());
    Ok(())
}

fn print_container(pef: &PefFile) {
    let header = &pef.header;
    println!("Container:");
    println!("\t{: <22} {}", "Architecture:", tag(header.architecture));
    println!("\t{: <22} {}", "Format version:", header.format_version);
    println!(
        "\t{: <22} {:#010X} ({})",
        "Date/time stamp:",
        header.date_time_stamp,
        mac_date(header.date_time_stamp)
    );
    println!("\t{: <22} {:#010X}", "Old definition:", header.old_def_version);
    println!("\t{: <22} {:#010X}", "Old implementation:", header.old_imp_version);
    println!("\t{: <22} {:#010X}", "Current version:", header.current_version);
    println!(
        "\t{: <22} {} ({} instantiated)",
        "Sections:", header.section_count, header.inst_section_count
    );
}

fn print_sections(pef: &PefFile) {
    println!("\nSections:");
    println!(
        "\t{: >3} | {: <10} | {: <24} | {: <10} | {: <10} | {: <10} | {: <10} | {: >5}",
        "Idx", "Name", "Kind", "File Off", "Packed", "Unpacked", "Total", "Align"
    );
    for (index, (section, name)) in pef.sections.iter().zip(&pef.names).enumerate() {
        println!(
            "\t{: >3} | {: <10} | {: <24} | {: <#10X} | {: <#10X} | {: <#10X} | {: <#10X} | {: >5}",
            index,
            if name.is_empty() { "-" } else { name.as_str() },
            section.section_kind.name(),
            section.container_offset,
            section.packed_size,
            section.unpacked_size,
            section.total_size,
            1u64.checked_shl(section.alignment.into()).unwrap_or(0),
        );
    }
}

fn print_loader(loader: &PefLoader, contents: &[Vec<u8>]) {
    let header = &loader.header;
    println!("\nLoader:");
    print_entry_point("Main", loader.main(contents));
    print_entry_point("Init", loader.init(contents));
    print_entry_point("Term", loader.term(contents));
    println!("\t{: <22} {}", "Relocation sections:", header.reloc_section_count);
    println!("\t{: <22} {:#010X}", "Relocations offset:", header.reloc_instr_offset);
    println!("\t{: <22} {:#010X}", "String table offset:", header.loader_strings_offset);
    println!(
        "\t{: <22} {:#010X} ({} slots)",
        "Export hash offset:",
        header.export_hash_offset,
        1u64.checked_shl(header.export_hash_table_power).unwrap_or(0)
    );

    println!("\nImported libraries ({}):", loader.libraries.len());
    for library in &loader.libraries {
        let mut notes = Vec::new();
        if library.weak {
            notes.push("weak");
        }
        if library.init_before {
            notes.push("init before");
        }
        println!(
            "\t{: <24} | {: >3} symbol(s) from #{}{}",
            library.name,
            library.imported_symbol_count,
            library.first_imported_symbol,
            if notes.is_empty() { String::new() } else { format!(" | {}", notes.join(", ")) }
        );
    }

    println!("\nImported symbols ({}):", loader.imports.len());
    println!("\t{: <24} | {: <8} | {: <4} | {}", "Library", "Class", "Weak", "Name");
    for import in &loader.imports {
        println!(
            "\t{: <24} | {: <8} | {: <4} | {}",
            import.library,
            import.class.name(),
            if import.weak { "yes" } else { "no" },
            import.name
        );
    }

    println!("\nExported symbols ({}):", loader.exports.len());
    println!("\t{: >3} | {: <8} | {: <10} | {}", "Sec", "Class", "Value", "Name");
    for export in &loader.exports {
        println!(
            "\t{: >3} | {: <8} | {: <#10X} | {}",
            export.section_index,
            export.class.name(),
            export.value,
            export.name
        );
    }

    if !loader.relocations.is_empty() {
        println!("\nRelocation instructions ({}):", loader.relocations.len());
        println!(
            "\t{: >3} | {: >8} | {: <10} | {: <22} | {}",
            "Sec", "Offset", "Raw", "Opcode", "Fields"
        );
        for reloc in &loader.relocations {
            println!(
                "\t{: >3} | {: >8} | {: <10} | {: <22} ",
                reloc.section_index,
                format!("{:#X}", reloc.instruction_offset),
                match reloc.opcode.word_count() {
                    2 => format!("{:#010X}", reloc.raw),
                    _ => format!("{:#06X}", reloc.raw),
                },
                reloc.opcode.name(),
            );
        }
    }
}

fn print_entry_point(label: &str, vector: Option<PefTransitionVector>) {
    let label = format!("{label}:");
    let Some(vector) = vector else {
        println!("\t{label: <22} none");
        return;
    };
    // A transition vector holds the code address to branch to and the TOC to enter with.
    match (vector.code, vector.toc) {
        (Some(code), Some(toc)) => println!(
            "\t{: <22} section {}:{:#X} -> code {:#010X}, toc {:#010X}",
            label, vector.section, vector.offset, code, toc
        ),
        _ => println!(
            "\t{: <22} section {}:{:#X} (contents unavailable)",
            label, vector.section, vector.offset
        ),
    }
}

fn print_symbols(obj: &ObjInfo) {
    println!("\nDiscovered symbols:");
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Section", "Address", "Size", "Name");
    let options = DemangleOptions { omit_empty_parameters: true, mw_extensions: true };
    for (_, symbol) in obj.symbols.iter_ordered().chain(obj.symbols.iter_abs()) {
        if symbol.name.starts_with('@') || is_auto_symbol(symbol) {
            continue;
        }
        let section_str = match symbol.section {
            Some(section) => obj.sections[section].name.as_str(),
            None => "ABS",
        };
        let size_str = if symbol.size_known {
            format!("{:#X}", symbol.size).into_cow()
        } else if symbol.section.is_none() {
            "ABS".to_cow()
        } else {
            "?".to_cow()
        };
        let name = demangle(symbol.name.as_str(), &options).unwrap_or_else(|| symbol.name.clone());
        println!(
            "\t{: >10} | {: <#10X} | {: <10} | {: <10}",
            section_str, symbol.address, size_str, name
        );
    }
}

fn print_traceback_tables(state: &AnalyzerState) {
    let tables = state
        .functions
        .iter()
        .filter_map(|(addr, info)| info.tbtab.as_ref().map(|tbtab| (addr, tbtab)))
        .collect::<Vec<_>>();

    println!("\nTraceback tables ({}):", tables.len());
    for (addr, tbtab) in tables {
        println!("\t{addr:#010X}");
        for (label, value) in tbtab.fields() {
            println!("\t\t{: <24} {}", format!("{label}:"), value);
        }
    }
}

/// Render a four-character tag such as `pwpc` or `m68k`.
fn tag(value: u32) -> String {
    let bytes = value.to_be_bytes();
    if bytes.iter().all(u8::is_ascii_graphic) {
        format!("{} ({:#010X})", String::from_utf8_lossy(&bytes), value)
    } else {
        format!("{value:#010X}")
    }
}

/// Format a Macintosh timestamp (seconds since 1904-01-01) as a UTC date.
fn mac_date(stamp: u32) -> String {
    /// Seconds between 1904-01-01 and 1970-01-01.
    const MAC_EPOCH_TO_UNIX: i64 = 2_082_844_800;
    let secs = stamp as i64 - MAC_EPOCH_TO_UNIX;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));

    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year,
        month,
        day,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}
