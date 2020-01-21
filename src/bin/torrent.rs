#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::collections::BTreeMap;
use torrent::bencoding;
use torrent::bencoding::{Node, Value};
use torrent::util::BinaryData;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
// use std::fmt::Write;
use std::fmt;

pub struct InfoHash {
    data: [u8; 20],
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BinaryData(&self.data))
    }
}


pub struct Torrent {
    data: Vec<u8>,
    root: Node,
    info_hash: InfoHash,
    name: String,
}

impl Torrent {
    pub fn from_bytes(data: &[u8]) -> Result<Torrent, String> {
        let node = bencoding::parse(data).or_else(|e| Err(format!("Corrupt torrent: {}", e)))?;
        let root_dict: &BTreeMap<String, Node> = match &node.value {
            Value::Dictionary(entries) => {
                entries
            }
            _ => {
                return Err(String::from("Root is not a dictionary"));
            }
        };
        let info = root_dict.get("info").ok_or_else(|| String::from("Missing info dictionary"))?;
        let info_dict = info.value.as_dictionary().ok_or_else(|| String::from("Invalid info dictionary"))?;

        let name_node = info_dict.get("name").ok_or_else(|| String::from("info: Missing name property"))?;
        let name_bstr = name_node.value.as_byte_string().ok_or_else(|| String::from("name: Not a string"))?;
        let name = String::from_utf8(name_bstr.clone()).or_else(|e| Err(format!("name: {}", e)))?;

        let mut hasher: Sha1 = Sha1::new();
        // hasher.input_str("hello world");
        hasher.input(&data[info.start..info.end]);
        let hex: String = hasher.result_str();
        println!("hex = {}", hex);
        println!("sha1 output bits = {}", hasher.output_bits());

        let mut hashdata: [u8; 20] = [0; 20];
        hasher.result(&mut hashdata);
        println!("{}", hashdata[0]);

        let info_hash = InfoHash { data: hashdata };


        // let x: () = info_dict;

        Ok(Torrent { data: Vec::from(data), root: node, info_hash, name })
    }
}

// impl Torrent {
//     fn parse(data: &[u8]) -> Result<bencoding::Node, String> {
//         println!("data length = {}", data.len());
//         Err(String::from("Cannot parse"))
//     }
// }

fn decode(data: &[u8]) -> Result<bencoding::Node, String> {
    bencoding::parse(data).or_else(|e| Err(format!("Corrupt torrent: {}", e)))
}

fn test_parse2(data: &[u8]) -> Result<(), String> {
    // let mut parser = BEParser::new(data);
    // let res = parser.parse_node(&String::from(""));
    let node = decode(data)?;
    node.dump(0);
    println!("");
    match node.value {
        bencoding::Value::Dictionary(entries) => {
            println!("Is a dictionary");
            match entries.get("info") {
                Some(info) => {
                    println!("Have info {} - {}", info.start, info.end);
                    let mut hasher: Sha1 = Sha1::new();
                    // hasher.input_str("hello world");
                    hasher.input(&data[info.start..info.end]);
                    let hex: String = hasher.result_str();
                    println!("hex = {}", hex);
                    // let x: () = hex;
                }
                None => {
                    println!("Do not have info");
                }
            }
        }
        _ => {
            println!("Not a dictionary");
        }
    };
    Ok(())
}

fn test_parse(data: &[u8]) {
    match test_parse2(data) {
        Ok(_) => {},
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    println!("-----------");
    match Torrent::from_bytes(data) {
        Ok(torrent) => {
            println!("Torrent loaded successfully");
            println!("    name = {}", torrent.name);
            println!("    info hash = {}", torrent.info_hash);
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

// fn main() {
//     for i in 0..=255 {
//         println!("{:02x} -- {}", i, byte_repr(i));
//     }
// }

fn main() {
    // println!("Hello World!");

    let args: Vec<String> = std::env::args().collect();
    // println!("args.len() = {}", args.len());
    // for arg in &args {
    //     let x: i32 = arg;
    //     println!("arg: {}", arg);
    // }

    if args.len() < 2 {
        eprintln!("No filename specified");
        std::process::exit(1);
    }

    let filename: &String = &args[1];
    // println!("filename = {}", filename);

    let res = std::fs::read(filename);
    match res {
        Ok(data) => {
            // let a: () = x;
            // let parser = BEParser { offset: 0, data: data.as_slice() };
            test_parse(data.as_slice());
            // let torrent = Torrent::parse(data.as_slice());
        }
        Err(err) => {
            println!("Cannot read {}: {}", filename, err);
            std::process::exit(1);
            // let b: () = x;
        }
    }

    // let data: Vec<u8> = vec![0x12, 0xab, 0xcd];
    // println!("{:x?}", data);
    // let mut hex_str = String::new();
    // for byte in data {
    //     write!(hex_str, "{:02x}", byte);
    // }

}
