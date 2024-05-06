// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::error::Error;
use ngfs::util::util::{BinaryData};
use ngfs::formats::protobuf::protobuf::{PBufReader, PBufWriter, VarInt, FromPB};
use ngfs::formats::protobuf::varint;
use ngfs::ipfs::types::cid::CID;
use ngfs::libp2p::peer_id::PrivateKey;
use rand::distributions::{Distribution, Uniform};

fn get_argument<'a>(args: &'a [String], index: usize, name: &str) -> Result<&'a String, Box<dyn Error>> {
    match args.get(index) {
        Some(command) => {
            Ok(command)
        }
        None => {
            Err(format!("Missing argument: {}", name).into())
        }
    }
}


async fn cid_command(args: &[String]) -> Result<(), Box<dyn Error>> {
    let cid_str = get_argument(args, 0, "cid")?;
    let cid = CID::from_string(cid_str)?;
    println!("Plain: {}", cid);
    println!("Debug: {:#?}", cid);

    Ok(())
}

async fn varint_command(_args: &[String]) -> Result<(), Box<dyn Error>> {
    let range = Uniform::new_inclusive(0, u64::max_value());
    let rng = rand::thread_rng();
    let mut generator = range.sample_iter(rng);
    for i in 0..1000000 {
        let raw: u64 = generator.next().unwrap();
        let bits: u64 = generator.next().unwrap() % 64;
        let value = raw >> bits;
        let mut varint_bytes: Vec<u8> = Vec::new();
        varint::encode_u64(value, &mut varint_bytes);

        let mut offset = 0;
        match VarInt::read_from(&varint_bytes, &mut offset) {
            Some(v) => {
                let decoded_value = v.to_u64()?;
                if value == decoded_value {
                    println!("{:10} 0x{:016x} OK", i, value);
                }
                else {
                    return Err(format!("0x{:016x} != 0x{:016x}", value, decoded_value).into());
                }
            }
            None => {
                return Err(format!("0x{:016x} INVALID", value).into());
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

async fn write_pbuf_command(_args: &[String]) -> Result<(), Box<dyn Error>> {
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
        println!("value = {}", field.data.to_int64()?);
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
            Err(format!("Unknown command: {}", command))?
        }
    }
}
