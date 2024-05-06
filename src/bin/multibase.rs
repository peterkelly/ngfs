// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::error::Error;
use clap::{Parser, Subcommand};
use ngfs::ipfs::types::multibase::{
    DecodeError,
    Base,
    encode,
    encode_noprefix,
    decode,
};

#[derive(Parser)]
#[command(name="multibase")]
struct Opt {
    #[command(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand)]
enum SubCommand {
    /// List available bases and their codes
    List,
    /// Detect which base a given value is encoded in
    Detect(Detect),
    /// Decode a value and print the data as hex
    Decode(Decode),
    /// Convert a value to a different base
    Convert(Convert),
}

#[derive(Parser)]
struct Detect {
    value: String,
}

#[derive(Parser)]
struct Decode {
    value: String,
}

#[derive(Parser)]
struct Convert {
    to: String,
    value: String,
}

fn list() -> Result<(), Box<dyn Error>> {
    for base in Base::available() {
        println!("{} {}", base.code(), base.name());
    }
    Ok(())
}

fn detect(args: &Detect) -> Result<(), Box<dyn Error>> {
    let code = args.value.chars().next().ok_or(DecodeError::EmptyString)?;
    let base = Base::for_code(code).ok_or(DecodeError::UnsupportedEncoding(code))?;
    println!("{}", base.name());
    Ok(())
}

fn decode_cmd(args: &Decode) -> Result<(), Box<dyn Error>> {
    let binary = decode(&args.value)?;
    let hex = encode_noprefix(&binary, Base::Base16);
    println!("{}", hex);
    Ok(())
}

fn convert(args: &Convert) -> Result<(), Box<dyn Error>> {
    let to_base = Base::for_name(&args.to).ok_or_else(|| format!("Unknown base: {}", args.to))?;
    let binary = decode(&args.value)?;
    println!("{}", encode(&binary, to_base));
    Ok(())
}

fn main_inner() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    match opt.subcmd {
        SubCommand::List => list(),
        SubCommand::Detect(s) => detect(&s),
        SubCommand::Decode(s) => decode_cmd(&s),
        SubCommand::Convert(s) => convert(&s),
    }
}

fn main() {
    match main_inner() {
        Ok(()) => {},
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
