#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::collections::BTreeMap;
use torrent::bencoding;
use torrent::bencoding::{Value};
use torrent::util::BinaryData;
use torrent::result::{Error, Result, error};
use torrent::torrent::{Torrent};
use crypto::digest::Digest;
use crypto::sha1::Sha1;
// use std::fmt::Write;
use std::fmt;
use std::path::PathBuf;
use std::ffi::OsString;

fn decode(data: &[u8]) -> Result<bencoding::Value> {
    match bencoding::parse(data) {
        Ok(v) => Ok(v),
        Err(e) => Err(Error::new(format!("Corrupt torrent: {}", e))),
    }
}

fn view_bencoding(data: &[u8]) -> Result<()> {
    let value = decode(data)?;
    value.dump(0);
    println!("");
    match value {
        bencoding::Value::Dictionary(d) => {
            let entries = &d.entries;
            println!("Is a dictionary");
            match entries.get("info") {
                Some(info) => {
                    println!("Have info {} - {}", info.loc().start, info.loc().end);
                    let mut hasher: Sha1 = Sha1::new();
                    // hasher.input_str("hello world");
                    hasher.input(&data[info.loc().start..info.loc().end]);
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

fn view_torrent(data: &[u8]) {
    match Torrent::from_bytes(data) {
        Ok(torrent) => {
            println!("Torrent loaded successfully");
            println!("    name = {}", torrent.name);
            println!("    info hash = {}", torrent.info_hash);
            for (group_index, group) in torrent.trackers.iter().enumerate() {
                println!("    group {}", group_index);
                for (tracker_index, tracker) in group.members.iter().enumerate() {
                    println!("        {}: {}", tracker_index, tracker.url);
                }
            }
            println!("    files");
            for file in torrent.files.iter() {
                println!("        {:<12} {}", file.length, file.path);
            }
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("No filename specified");
        std::process::exit(1);
    }

    let filename: &String = &args[1];

    let res = std::fs::read(filename);
    match res {
        Ok(data) => {

            match view_bencoding(&data) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("{}", e);
                    std::process::exit(1);
                }
            };
            println!("-----------");


            view_torrent(data.as_slice());
        }
        Err(err) => {
            println!("Cannot read {}: {}", filename, err);
            std::process::exit(1);
        }
    }
}
