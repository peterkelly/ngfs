#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use tokio;
use std::env;
use std::error::Error;
use std::future::Future;
use torrent::result::{GeneralError, general_error};
use torrent::multibase::decode;
use torrent::util::{BinaryData};
use torrent::protobuf::{PBufReader, VarInt};
use torrent::cid::CID;
use torrent::p2p::p2p_test;
use rand::prelude::Rng;
use rand::distributions::{Distribution, Uniform};

fn get_argument<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a String, Box<dyn Error>> {
    match args.get(index) {
        Some(command) => {
            Ok(command)
        }
        None => {
            Err(GeneralError::new(&format!("Missing argument: {}", name)))
        }
    }
}


async fn cid_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cid_str = get_argument(args, 0, "cid")?;
    let cid_bytes = decode(cid_str)?;
    let cid = CID::from_string(&cid_str)?;
    println!("{:#?}", cid);

    Ok(())
}

async fn p2p_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let server_addr = get_argument(args, 0, "server_addr")?;
    p2p_test(&server_addr).await?;
    Ok(())
}

fn u64_to_varint(mut value: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    while value > 0 {
        let seven = value & 0x7f;
        bytes.push(seven as u8);
        value = value >> 7;
    }
    let mut index = 0;
    while index + 1 < bytes.len() {
        bytes[index] = bytes[index] | 0x80;
        index += 1;
    }
    return bytes;
}

async fn varint_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    let range = Uniform::new_inclusive(0, u64::max_value());
    let mut generator = range.sample_iter(rng);
    let mut count = 0;
    for i in 0..100000 {
        let raw: u64 = generator.next().unwrap();
        let bits: u64 = generator.next().unwrap() % 63;
        let value = raw >> bits;
        // let value: u64 = 0x042e2d258cdae657;
        // println!("value   = 0x{:016x}", value);
        let varint_bytes = u64_to_varint(value);

        // for (i, b) in varint_bytes.iter().enumerate() {
        //     print!("{:08b}", b);
        //     if i + 1 < varint_bytes.len() {
        //         print!(" ");
        //     }
        // }
        // println!();

        let mut offset = 0;
        match VarInt::read_from(&varint_bytes, &mut offset) {
            Some(v) => {
                let decoded_value = v.to_u64();
                if value == decoded_value {
                    println!("0x{:016x} OK", value);
                }
                else {
                    return general_error(&format!("0x{:016x} != 0x{:016x}", value, decoded_value));
                }
            }
            None => {
                return general_error(&format!("0x{:016x} INVALID", value));
            }
        }
        // let decoded = VarInt::read_from(&varint_bytes, &mut offset);
        // match decoded {
        //     Some(v) => {
        //         println!("decoded = 0x{:016x}", v.to_u64());
        //     }
        //     None => {
        //         println!("Decoding failed");
        //     }
        // }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let command = get_argument(&args, 1, "command")?;
    // println!("command = {}", command);

    match command.as_str() {
        "cid" => {
            cid_command(&args[2..]).await?;
            Ok(())
        }
        "p2p" => {
            p2p_command(&args[2..]).await?;
            Ok(())
        }
        "varint" => {
            varint_command(&args[2..]).await?;
            Ok(())
        }
        _ => {
            Err(GeneralError::new(&format!("Unknown command: {}", command)))?
        }
    }
}
