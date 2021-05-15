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
use torrent::result::GeneralError;
use torrent::asn1;
use torrent::asn1::printer::ObjectDescriptor;
use torrent::x509;

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
    let item = asn1::reader::read_item(&mut reader)?;

    let certificate = x509::Certificate::from_asn1(&item)?;
    println!("Got certificate");

    let mut registry = asn1::printer::ObjectRegistry::new();
    x509::populate_registry(&mut registry);
    x509::print_certificate(&registry, &certificate);


    Ok(())
}
