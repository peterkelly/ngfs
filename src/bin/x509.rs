#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::fmt;
use std::error::Error;
use clap::{Clap, ValueHint};
use torrent::util::{BinaryData, DebugHexDump, Indent, escape_string};
use torrent::binary::BinaryReader;
use torrent::error;
use torrent::asn1;
use torrent::asn1::printer::ObjectDescriptor;
use torrent::x509;

#[derive(Clap)]
#[clap(name="x509")]
struct Opt {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Print(Print),
    Generate(Print),
}

#[derive(Clap)]
struct Print {
    #[clap(index = 1, value_name = "INFILE", value_hint=ValueHint::FilePath,
        about = "DER-encoded file to read certificate from")]
    infile: String,
}

#[derive(Clap)]
struct Generate {
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    match opt.subcmd {
        SubCommand::Print(s) => print(&s),
        SubCommand::Generate(s) => generate()
    }
}

fn generate() -> Result<(), Box<dyn Error>> {
    Ok(())
}

fn print(subcmd: &Print) -> Result<(), Box<dyn Error>> {
    // Read ASN.1 structure from file
    let data: Vec<u8> = std::fs::read(&subcmd.infile)?;
    let mut reader = BinaryReader::new(&data);
    let item = asn1::reader::read_item(&mut reader)?;

    // Parse ASN.1 structure to create certificate
    let certificate = x509::Certificate::from_asn1(&item)?;

    // Print certificate
    let mut registry = asn1::printer::ObjectRegistry::new();
    x509::populate_registry(&mut registry);
    x509::print_certificate(&registry, &certificate);

    Ok(())
}
