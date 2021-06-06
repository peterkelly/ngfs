#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::fmt;
use std::error::Error;
use std::path::PathBuf;
use clap::{Clap, ValueHint};
use torrent::util::{BinaryData, DebugHexDump, Indent, escape_string};
use torrent::binary::BinaryReader;
use torrent::error;
use torrent::asn1;
use torrent::asn1::printer::ObjectDescriptor;
use torrent::asn1::writer::encode_item;
use torrent::x509;

#[derive(Clap, Debug)]
#[clap(name = "asn1: Test for reading/writing ASN.1 DER files")]
struct Opt {
    #[clap(long, about = "Show byte ranges for each value")]
    ranges: bool,

    #[clap(index = 1, value_name = "INFILE", value_hint=ValueHint::FilePath,
        about = "DER-encoded file to read from")]
    input: String,

    #[clap(value_name = "OUTFILE", long, value_hint=ValueHint::FilePath,
        about = "Re-encode data structure from input and write to OUTFILE")]
    output: Option<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    let data: Vec<u8> = std::fs::read(opt.input)?;
    let mut reader = BinaryReader::new(&data);
    let item = asn1::reader::read_item(&mut reader)?;

    let mut registry = asn1::printer::ObjectRegistry::new();
    x509::populate_registry(&mut registry);

    let mut printer = asn1::printer::Printer::new();
    printer.truncate = true;
    printer.lines = true;
    printer.registry = Some(&registry);
    printer.ranges = opt.ranges;
    printer.print(&item);

    if let Some(output) = opt.output {
        let mut output_data: Vec<u8> = Vec::new();
        encode_item(&item, &mut output_data)?;
        std::fs::write(&output, &output_data).map_err(|e| error!("{}: {}", output, e))?;
        println!("Wrote {}", output);
    }

    Ok(())
}
