// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use ngfs::util::util::{from_hex, BinaryData};
use ngfs::ipfs::types::multibase::{Base, encode, decode};
use std::error::Error;

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

    let base = match Base::for_name(base_name) {
        Some(v) => v,
        None => {
            eprintln!("Unknown base: {}", base_name);
            std::process::exit(1);
        }
    };

    let numbers_content = std::fs::read_to_string(numbers_filename)?;
    for (lineno, line) in numbers_content.lines().enumerate() {
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
            return Err(format!("Line {}: Invalid hex string: {:?}", lineno, line).into());
        }
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
