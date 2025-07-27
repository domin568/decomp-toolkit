use std::fs;

use anyhow::{Context, Result};
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;
use crate::util::config::is_auto_symbol;
use crate::util::{path::native_path, IntoCow, ToCow, pef::process_pef};
use crate::analysis::cfa::AnalyzerState;

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
    let mut obj = process_pef(&in_buf, "")?;
    //apply_signatures(&mut obj)?;

    let mut state = AnalyzerState::default();
    //FindSaveRestSleds::execute(&mut state, &obj)?;
    state.detect_functions(&obj)?;
    state.apply(&mut obj)?;
    for (addr, _) in state.functions.iter()
    {
        log::debug!(
            "{:#010X}", addr.address, 
        );
    }
    log::debug!(
        "Discovered {} functions",
        state.functions.iter().filter(|(_, i)| i.end.is_some()).count()
    );

    println!("{}:", obj.name);
    if let Some(entry) = obj.entry {
        println!("Entry point: {:#010X}", entry);
    }
    println!("\nSections:");
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Name", "Address", "Size", "File Off");
    for (_, section) in obj.sections.iter() {
        println!(
            "\t{: >10} | {:#010X} | {: <#10X} | {: <#10X}",
            section.name, section.address, section.size, section.file_offset
        );
    }
    println!("\nDiscovered symbols:");
    println!("\t{: >10} | {: <10} | {: <10} | {: <10}", "Section", "Address", "Size", "Name");
    for (_, symbol) in obj.symbols.iter_ordered().chain(obj.symbols.iter_abs()) {
        if symbol.name.starts_with('@') || is_auto_symbol(symbol) {
            continue;
        }
        let section_str = if let Some(section) = symbol.section {
            obj.sections[section].name.as_str()
        } else {
            "ABS"
        };
        let size_str = if symbol.size_known {
            format!("{:#X}", symbol.size).into_cow()
        } else if symbol.section.is_none() {
            "ABS".to_cow()
        } else {
            "?".to_cow()
        };
        println!(
            "\t{: >10} | {: <#10X} | {: <10} | {: <10}",
            section_str, symbol.address, size_str, symbol.name
        );
    }
    println!("\n{} discovered functions from exception table", obj.known_functions.len());
    Ok(())
}
