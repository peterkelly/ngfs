#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use torrent::util::escape_string;
use torrent::result::{general_error, GeneralError};
use torrent::protobuf::{PBufReader, FieldRef};
use torrent::util::BinaryData;

fn show_field<'a>(field: &FieldRef<'a>) -> Result<(), Box<dyn Error>> {
    match field.field_number {
        // required string   name = 2;
        2 => {
            println!("    name: {}", escape_string(&field.data.to_string()?));
        }
        // required uint64   id = 1;
        1 => {
            println!("    id: {}", field.data.to_u64()?);
        }
        // optional string   email = 3;
        3 => {
            println!("    email: {}", escape_string(&field.data.to_string()?));
        }

        // required fixed64  test_fixed64  = 4;
        4 => {
            let v: u64 = field.data.to_u64()?;
            println!("    test_fixed64: {}", v);
        }
        // required sfixed64 test_sfixed64 = 5;
        5 => {
            let v: i64 = field.data.to_i64()?;
            println!("    test_sfixed64: {}", v);
        }
        // required double   test_double   = 6;
        6 => {
            let v: f64 = field.data.to_double()?;
            println!("    test_double: {}", v);
        }
        // required fixed32  test_fixed32  = 7;
        7 => {
            let v: u32 = field.data.to_u32()?;
            println!("    test_fixed32: {}", v);
        }
        // required sfixed32 test_sfixed32 = 8;
        8 => {
            let v: i32 = field.data.to_i32()?;
            println!("    test_sfixed32: {}", v);
        }
        // required float    test_float    = 9;
        9 => {
            let v: f32 = field.data.to_float()?;
            println!("    test_float: {}", v);
        }

        // required int32    test_int32    = 10;
        10 => {
            let v: i32 = field.data.to_i32()?;
            println!("    test_int32: {}", v);
        }
        // required int64    test_int64    = 11;
        11 => {
            let v: i64 = field.data.to_i64()?;
            println!("    test_int64: {}", v);
        }
        // required uint32   test_uint32   = 12;
        12 => {
            let v: u32 = field.data.to_u32()?;
            println!("    test_uint32: {}", v);
        }
        // required uint64   test_uint64   = 13;
        13 => {
            let v: u64 = field.data.to_u64()?;
            println!("    test_uint64: {}", v);
        }
        // required sint32   test_sint32   = 14;
        14 => {
            let v: i32 = field.data.to_i32_zigzag()?;
            println!("    test_sint32: {}", v);
        }
        // required sint64   test_sint64   = 15;
        15 => {
            let v: i64 = field.data.to_i64_zigzag()?;
            println!("    test_sint64: {}", v);
        }
        // required bool     test_bool     = 16;
        16 => {
            let v: bool = field.data.to_bool()?;
            println!("    test_bool: {}", v);
        }

        _ => {
            println!("    Other field number: {}", field.field_number);
        }
    }

    Ok(())
}


// https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-pb.md


struct PBLink {
    hash: Vec<u8>,
    name: String,
    tsize: u64,
}

struct PBNode {
    links: Vec<PBNode>,
    data: Option<Vec<u8>>,
}





impl PBLink {
    fn from_pb(data: &[u8]) -> Result<PBLink, Box<dyn Error>> {
        let mut hash: Option<Vec<u8>> = None;
        let mut name: Option<String> = None;
        let mut tsize: Option<u64> = None;

        let mut reader = PBufReader::new(&data);
        while let Some(field) = reader.read_field()? {
            match field.field_number {
                1 => {
                    hash = Some(Vec::from(field.data.to_bytes()?));
                    // println!("    hash {}", BinaryData(hash));
                }
                2 => {
                    name = Some(field.data.to_string()?);
                    // println!("    name {}", name);
                }
                3 => {
                    tsize = Some(field.data.to_u64()?);
                    // println!("    size {}", size);
                }
                _ => {
                    // println!("Other field {}", field.field_number);
                }
            }
        }

        let hash = match hash {
            Some(v) => v,
            None => return general_error("Missing field: hash"),
        };


        let name = match name {
            Some(v) => v,
            None => return general_error("Missing field: name"),
        };

        let tsize = match tsize {
            Some(v) => v,
            None => return general_error("Missing field: tsize"),
        };

        Ok(PBLink { hash, name, tsize })
    }
}





// https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-pb.md
// fn print_directory_entry(data: &[u8]) -> Result<(), Box<dyn Error>> {
//     let mut reader = PBufReader::new(&data);
//     while let Some(field) = reader.read_field()? {
//         match field.field_number {
//             1 => {
//                 let hash = field.data.to_bytes()?;
//                 println!("    hash {}", BinaryData(hash));
//             }
//             2 => {
//                 let name = field.data.to_string()?;
//                 println!("    name {}", name);
//             }
//             3 => {
//                 let size = field.data.to_u64()?;
//                 println!("    size {}", size);
//             }
//             _ => {
//                 println!("Other field {}", field.field_number);
//             }
//         }
//     }


//     // print_fields(data)?;
//     Ok(())
// }

fn print_directory(raw_data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut links: Vec<PBLink> = Vec::new();
    let mut data: Option<Vec<u8>> = None;

    let mut reader = PBufReader::new(&raw_data);
    while let Some(field) = reader.read_field()? {
        match field.field_number {
            1 => {
                data = Some(Vec::from(field.data.to_bytes()?));
            }
            2 => {
                let b = field.data.to_bytes()?;
                links.push(PBLink::from_pb(b)?);
            }
            _ => {
                println!("Other field {}", field.field_number);
            }
        }
    }

    for link in links.iter() {
        println!("{:<30} {:<16} {}", link.name, link.tsize, BinaryData(&link.hash));
    }
    println!();
    match data {
        Some(data) => {
            println!("Data {}", BinaryData(&data));
        }
        None => {
            println!("Data None");
        }
    }
    Ok(())
}

fn print_fields(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut reader = PBufReader::new(&data);
    while let Some(field) = reader.read_field()? {
        println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            field.offset, field.field_number, field.data);
        // println!();
        // match show_field(&field) {
        //     Ok(_) => (),
        //     Err(e) => {
        //         println!("    Error: {}", e);
        //     }
        // }
        // println!();
    }
    Ok(())
}

fn main_result() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let filename = args.get(1).ok_or_else(|| GeneralError::new("No filename specified"))?;
    let raw_data = std::fs::read(filename)?;
    // print_fields(&raw_data)?;
    print_directory(&raw_data)?;

    Ok(())
}

// curl "http://localhost:5001/api/v0/block/get?arg=<key>"
fn main() {
    match main_result() {
        Ok(_) => (),
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}
