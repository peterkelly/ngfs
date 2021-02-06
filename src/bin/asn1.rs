#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use torrent::util::{BinaryData, DebugHexDump, Indent, escape_string};
use torrent::binary::BinaryReader;
use torrent::result::GeneralError;
use torrent::asn1;

fn main() -> Result<(), Box<dyn Error>> {
    let filename = match std::env::args().nth(1) {
        Some(v) => v,
        None => {
            eprintln!("Please specify filename");
            std::process::exit(1);
        }
    };
    let data: Vec<u8> = std::fs::read(filename)?;
    // println!("data.len() = {}", data.len());
    let mut reader = BinaryReader::new(&data);
    let value = asn1::read_value(&mut reader)?;
    // println!("{:#?}", value);
    let mut asn1_printer = asn1::Printer::new();
    asn1_printer.truncate = true;
    asn1_printer.lines = true;
    asn1_printer.print(&value);
    // let identifier = read_identifier(&mut reader)?;
    // println!("identifier = {:?}", identifier);
    // let length = read_length(&mut reader)?;
    // println!("length = {}", length);
    // let contents = reader.read_nested(length as usize)?;
    Ok(())
}
