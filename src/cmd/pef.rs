use std::fs;

use anyhow::{Context, Result};
use argp::FromArgs;
use typed_path::Utf8NativePathBuf;

use crate::util::path::native_path;

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
    let _in_buf = fs::read(&args.input)
    .with_context(|| format!("Failed to open input file: '{}'", args.input))?;
    Ok(())
}