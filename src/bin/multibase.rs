#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use clap::{Clap, ArgSettings};
use torrent::ipfs::types::multibase::{
    DecodeError,
    Base,
    encode,
    encode_noprefix,
    decode,
    decode_noprefix,
};
use torrent::error;

#[derive(Clap)]
#[clap(name="multibase")]
struct Opt {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
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

#[derive(Clap)]
struct Detect {
    value: String,
}

#[derive(Clap)]
struct Decode {
    value: String,
}

#[derive(Clap)]
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
    let code = args.value.chars().nth(0).ok_or_else(|| DecodeError::EmptyString)?;
    let base = Base::for_code(code).ok_or_else(|| DecodeError::UnsupportedEncoding(code))?;
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
    let to_base = Base::for_name(&args.to).ok_or_else(|| error!("Unknown base: {}", args.to))?;
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
