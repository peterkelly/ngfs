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
use torrent::error;
use torrent::multibase::decode;
use torrent::util::{BinaryData};
use torrent::protobuf::{PBufReader, PBufWriter, VarInt};
use torrent::cid::CID;
use torrent::p2p::{p2p_test, PrivateKey, print_fields};
use rand::prelude::Rng;
use rand::distributions::{Distribution, Uniform};
use openssl;

fn get_argument<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a String, Box<dyn Error>> {
    match args.get(index) {
        Some(command) => {
            Ok(command)
        }
        None => {
            Err(error!("Missing argument: {}", name))
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
    match p2p_test(&server_addr).await {
        Ok(_) => {},
        Err(e) => {
            eprintln!("p2p_test failed: {}", e);
            std::process::exit(1);
        }
    }
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
                    return Err(error!("0x{:016x} != 0x{:016x}", value, decoded_value));
                }
            }
            None => {
                return Err(error!("0x{:016x} INVALID", value));
            }
        }
    }
    Ok(())
}

async fn getkey_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let filename = get_argument(args, 0, "filename")?;
    let data = std::fs::read(filename)?;
    println!("data.len = {}", data.len());
    let private_key = PrivateKey::from_pb(&data)?;
    println!("Got private key (type {:?}, {} bytes)", private_key.key_type, private_key.data.len());
    // std::fs::write("private_key.out", &private_key.data)?;
    let pkey = openssl::rsa::Rsa::private_key_from_der(&private_key.data)?;
    println!("pkey = {:?}", pkey);


    Ok(())
}

async fn write_pbuf_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let mut writer = PBufWriter::new();
    writer.write_int64(3, -1234567890123456789);
    // writer.write_string(3, "Hello World");
    // writer.write_bytes(3, &vec![0xca, 0xfe, 0xbe]);
    // writer.write_sint64(3, -12345);
    println!("{}", BinaryData(&writer.data));
    // print_fields(&writer.data)?;

    let mut reader = PBufReader::new(&writer.data);
    while let Some(field) = reader.read_field()? {
        println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            field.offset, field.field_number, field.data);
        println!("value = {}", field.data.to_i64()?);
        // println!("value = {}", field.data.to_string()?);
        // println!("value = {}", BinaryData(&field.data.to_bytes()?));
        // println!("value = {}", field.data.to_i64_zigzag()?);
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
        "getkey" => {
            getkey_command(&args[2..]).await?;
            Ok(())
        }
        "write-pbuf" => {
            write_pbuf_command(&args[2..]).await?;
            Ok(())
        }
        _ => {
            Err(error!("Unknown command: {}", command))?
        }
    }
}
