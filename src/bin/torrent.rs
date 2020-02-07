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
use std::path::PathBuf;

pub struct InfoHash {
    data: [u8; 20],
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BinaryData(&self.data))
    }
}

pub struct Tracker {
    pub url: String,
}

pub struct TrackerGroup {
    pub members: Vec<Tracker>,
}

pub struct TorrentFile {
    pub length: usize,
    pub path: PathBuf,
}

pub struct Torrent {
    pub data: Vec<u8>,
    pub root: Node,
    pub info_hash: InfoHash,
    pub name: String,
    pub trackers: Vec<TrackerGroup>,
    pub files: Vec<TorrentFile>,
}

impl Torrent {
    fn parse_announce_list(be_announce_list_node: &Node) -> Result<Vec<TrackerGroup>, String> {
        let mut groups: Vec<TrackerGroup> = Vec::new();
        let be_announce_list = be_announce_list_node.value.as_list()
            .ok_or_else(|| String::from("announce_list is not a list"))?;
        for be_group_node in be_announce_list.iter() {
            let mut members: Vec<Tracker> = Vec::new();
            let be_group_list = be_group_node.value.as_list()
                .ok_or_else(|| String::from("group is not a list"))?;
            for tracker_node in be_group_list.iter() {
                // let x: () = tracker_node;
                let tracker_string = tracker_node.value.as_byte_string()
                    .ok_or_else(|| String::from("Tracker URL is not a string"))?;
                let tracker_string_utf8 = String::from_utf8(tracker_string.clone())
                    .map_err(|e| format!("{}", e))?;
                // let x: () = tracker_string_utf8;
                members.push(Tracker { url: tracker_string_utf8 });
            }
            groups.push(TrackerGroup { members });
        }

        return Ok(groups);
    }

    fn parse_files(be_files_node: &Node) -> Result<Vec<TorrentFile>, String> {
        let mut files: Vec<TorrentFile> = Vec::new();
        let be_files_list = be_files_node.value.as_list()
            .ok_or_else(|| String::from("files is not a list"))?;
        for be_file_node in be_files_list.iter() {
            let be_file_dict = be_file_node.value.as_dictionary()
                .ok_or_else(|| String::from("file is not a dictionary"))?;
            let be_length_node = be_file_dict.get("length")
                .ok_or_else(|| String::from("file: missing length"))?;
            let be_path_node = be_file_dict.get("path")
                .ok_or_else(|| String::from("file: missing path"))?;
            let length: usize = be_length_node.value.as_integer()
                .ok_or_else(|| String::from("file: length is not an integer"))?;
            let be_components_list = be_path_node.value.as_list()
                .ok_or_else(|| String::from("file: path is not a list"))?;
            let mut path = std::path::PathBuf::new();
            // let mut components: Vec<String> = Vec::new();
            for be_component_node in be_components_list.iter() {
                let component_bytes = be_component_node.value.as_byte_string()
                    .ok_or_else(|| String::from("path component is not a string"))?;
                let component = String::from_utf8(component_bytes.clone())
                    .map_err(|e| format!("{}", e))?;
                path.push(component);
                // components.push(component);
            }
            files.push(TorrentFile { length, path });
        }
        return Ok(files);
    }

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


        let announce_list = root_dict.get("announce-list")
            .ok_or_else(|| String::from("Missing announce-list property"))?;
        let trackers = Torrent::parse_announce_list(announce_list)?;

        let files_node = info_dict.get("files")
            .ok_or_else(|| String::from("info: Missing files property"))?;
        let files = Self::parse_files(files_node)?;




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
        // let trackers: Vec<TrackerGroup> = Vec::new();


        Ok(Torrent { data: Vec::from(data), root: node, info_hash, name, trackers, files })
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
            for (group_index, group) in torrent.trackers.iter().enumerate() {
                println!("    group {}", group_index);
                for (tracker_index, tracker) in group.members.iter().enumerate() {
                    println!("        {}: {}", tracker_index, tracker.url);
                }
            }
            println!("    files");
            for file in torrent.files.iter() {
                match file.path.clone().into_os_string().into_string() {
                    Ok(path) => {
                        println!("        {:<12} {}", file.length, path);

                    }
                    Err(e) => {
                        println!("        {} INVALID", file.length);
                    }
                }
            }
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
