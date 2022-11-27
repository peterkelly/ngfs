#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use torrent::util::util::{escape_string, from_hex, BinaryData};
use torrent::error;
use torrent::ipfs::types::multibase::{Base, encode, decode};
use std::iter::FromIterator;
use std::error::Error;
use std::fmt;

fn main_result() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();

    let numbers_filename = match args.get(1) {
        Some(v) => v,
        None => {
            eprintln!("Please specify numbers filename");
            std::process::exit(1);
        }
    };

    let base_name = match args.get(2) {
        Some(v) => v,
        None => {
            eprintln!("Please specify base");
            std::process::exit(1);
        }
    };

    let base = match Base::for_name(&base_name) {
        Some(v) => v,
        None => {
            eprintln!("Unknown base: {}", base_name);
            std::process::exit(1);
        }
    };

    let numbers_content = std::fs::read_to_string(numbers_filename)?;
    let mut lineno = 0;
    for line in numbers_content.lines() {
        if let Some(num_bytes) = from_hex(line) {
            let encoded = encode(&num_bytes, base);
            println!("{:<40} {}", line, encoded);

            match decode(&encoded) {
                Ok(bytes) => {
                    if bytes == num_bytes {
                        // println!("Decode: OK");
                    }
                    else {
                        eprintln!("Decode: Not equal");
                        eprintln!("Expected: {}", BinaryData(&num_bytes));
                        eprintln!("Actual:   {}", BinaryData(&bytes));
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("Decode: {}", e);
                    std::process::exit(1);
                }
            }
        }
        else {
            return Err(error!("Line {}: Invalid hex string: {}", lineno, escape_string(line)));
        }
        lineno += 1;
    }

    Ok(())
}

fn main() {
    // gen_inverse_all();
    match main_result() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
