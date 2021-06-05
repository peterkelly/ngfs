#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::fmt;
use std::error::Error;
use torrent::util::{BinaryData, DebugHexDump, Indent, escape_string};
use torrent::binary::BinaryReader;
use torrent::error;
use torrent::asn1;
use torrent::asn1::printer::ObjectDescriptor;
use torrent::asn1::writer::encode_item;
use torrent::x509;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut ranges: bool = false;
    let mut input_filename: Option<&str> = None;
    let mut output_filename: Option<&str> = None;

    let mut argno = 1;
    while argno < args.len() {
        if argno + 1 < args.len() && args[argno] == "--output" {
            output_filename = Some(&args[argno + 1]);
            argno += 2;
        }
        else if args[argno] == "--ranges" {
            ranges = true;
            argno += 1;
        }
        else if input_filename.is_some() {
            // eprintln!("Unexpected argument: {}", args[argno]);
            // std::process::exit(1);
            return Err(error!("Unexpected argument: {}", args[argno]));
        }
        else {
            input_filename = Some(&args[argno]);
            argno += 1;
        }
    }

    let input_filename: &str = match input_filename {
        Some(v) => v,
        None => {
            return Err(error!("No input file specified"));
        }
    };

    let data: Vec<u8> = std::fs::read(input_filename)?;
    let mut reader = BinaryReader::new(&data);
    let item = asn1::reader::read_item(&mut reader)?;

    let mut registry = asn1::printer::ObjectRegistry::new();
    x509::populate_registry(&mut registry);

    let mut printer = asn1::printer::Printer::new();
    printer.truncate = true;
    printer.lines = true;
    printer.registry = Some(&registry);
    printer.ranges = ranges;
    printer.print(&item);

    if let Some(output_filename) = output_filename {
        let mut output_data: Vec<u8> = Vec::new();
        encode_item(&item, &mut output_data)?;
        std::fs::write(&output_filename, &output_data)
            .map_err(|e| error!("{}: {}", output_filename, e))?;
        println!("Wrote {}", output_filename);
    }

    Ok(())
}
