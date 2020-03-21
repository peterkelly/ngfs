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

async fn varint_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let range = Uniform::new_inclusive(0, u64::max_value());
    let mut rng = rand::thread_rng();
    let mut generator = range.sample_iter(rng);
    for i in 0..1000000 {
        let raw: u64 = generator.next().unwrap();
        let bits: u64 = generator.next().unwrap() % 64;
        let value = raw >> bits;
        let varint_bytes = VarInt::encode_u64(value);

        let mut offset = 0;
        match VarInt::read_from(&varint_bytes, &mut offset) {
            Some(v) => {
                let decoded_value = v.to_u64();
                if value == decoded_value {
                    println!("{:10} 0x{:016x} OK", i, value);
                }
                else {
                    return general_error(&format!("0x{:016x} != 0x{:016x}", value, decoded_value));
                }
            }
            None => {
                return general_error(&format!("0x{:016x} INVALID", value));
            }
        }
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
