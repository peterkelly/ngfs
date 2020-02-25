// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::fmt;
use std::collections::BTreeMap;
use crypto::digest::Digest;
use crypto::sha1::Sha1;
use super::bencoding;
use super::bencoding::{Value};
use super::result::{Error, Result, error};
use super::util::BinaryData;

pub struct InfoHash {
    data: [u8; 20],
}

pub struct PieceHash {
    data: [u8; 20],
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", BinaryData(&self.data))
    }
}

impl fmt::Display for PieceHash {
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
    pub path: String,
}

pub struct Torrent {
    pub data: Vec<u8>,
    pub root: Value,
    pub info_hash: InfoHash,
    pub name: String,
    pub tracker_groups: Vec<TrackerGroup>,
    pub files: Vec<TorrentFile>,
    pub piece_length: usize,
    pub pieces: Vec<PieceHash>,
}

impl Torrent {
    fn parse_announce_list(be_announce_list_value: &Value) -> Result<Vec<TrackerGroup>> {
        let mut groups: Vec<TrackerGroup> = Vec::new();
        let be_announce_list = be_announce_list_value.as_list()?;
        for be_group_value in be_announce_list.items.iter() {
            let mut members: Vec<Tracker> = Vec::new();
            let be_group_list = be_group_value.as_list()?;
            for tracker_value in be_group_list.items.iter() {
                let tracker_string = tracker_value.as_byte_string()?;
                let tracker_string_utf8 = String::from_utf8(tracker_string.data.clone())
                    .map_err(|e| format!("{}", e))?;
                // let x: () = tracker_string_utf8;
                members.push(Tracker { url: tracker_string_utf8 });
            }
            groups.push(TrackerGroup { members });
        }

        return Ok(groups);
    }

    fn parse_files(be_files_value: &Value) -> Result<Vec<TorrentFile>> {
        let mut files: Vec<TorrentFile> = Vec::new();
        let be_files_list = be_files_value.as_list()?;
        for be_file_value in be_files_list.items.iter() {
            let be_file_dict = be_file_value.as_dictionary()?;
            let be_length_value = be_file_dict.entries.get("length")
                .ok_or_else(|| String::from("file: missing length"))?;
            let be_path_value = be_file_dict.entries.get("path")
                .ok_or_else(|| String::from("file: missing path"))?;
            let length: usize = be_length_value.as_integer()?.value;
            let be_components_list = be_path_value.as_list()?;
            let mut spath = String::new();
            for be_component_value in be_components_list.items.iter() {
                let component_bytes = be_component_value.as_byte_string()?;
                let component = String::from_utf8(component_bytes.data.clone())?;
                if spath.len() > 0 {
                    spath.push_str("/");
                }
                spath.push_str(&component);
            }
            files.push(TorrentFile { length, path: spath });
        }
        return Ok(files);
    }

    pub fn from_bytes(data: &[u8]) -> Result<Torrent> {
        // let node = bencoding::parse(data).or_else(|e| Err(format!("Corrupt torrent: {}", e)))?;
        let value = bencoding::parse(data)?;
        let root_dict: &BTreeMap<String, Value> = match &value {
            Value::Dictionary(d) => {
                &d.entries
            }
            _ => {
                return Err(Error::new("Root is not a dictionary"));
            }
        };
        let info = root_dict.get("info").ok_or_else(|| String::from("Missing info dictionary"))?;
        let info_dict = info.as_dictionary()?;

        let name_value = info_dict.entries.get("name").ok_or_else(|| String::from("info: Missing name property"))?;
        let name_bstr = name_value.as_byte_string()?;
        let name = String::from_utf8(name_bstr.data.clone()).or_else(|e| Err(format!("name: {}", e)))?;

        let announce_list = root_dict.get("announce-list")
            .ok_or_else(|| String::from("Missing announce-list property"))?;
        let tracker_groups = Torrent::parse_announce_list(announce_list)?;

        let files_node = info_dict.entries.get("files")
            .ok_or_else(|| String::from("info: Missing files property"))?;
        let files = Self::parse_files(files_node)?;

        let piece_length_value = info_dict.entries.get("piece length").ok_or_else(
            || String::from("info: Missing piece length property"))?;
        let piece_length = piece_length_value.as_integer()?.value;

        let pieces_value = info_dict.entries.get("pieces").ok_or_else(
            || String::from("info: Missing pieces property"))?;
        let pieces_data = &pieces_value.as_byte_string()?.data;

        if pieces_data.len() % 20 != 0 {
            return error(&format!("Pieces data is {} bytes, which is not a multiple of 20", pieces_data.len()))
        }

        let mut pieces = Vec::<PieceHash>::new();
        let mut i = 0;
        while i + 20 < pieces_data.len() {
            let mut data: [u8; 20] = [0; 20];
            data.copy_from_slice(&pieces_data[i..i + 20]);
            pieces.push(PieceHash { data });
            i += 20;
        }



        let mut hasher: Sha1 = Sha1::new();
        // hasher.input_str("hello world");
        hasher.input(&data[info.loc().start..info.loc().end]);
        // let hex: String = hasher.result_str();
        // println!("hex = {}", hex);
        // println!("sha1 output bits = {}", hasher.output_bits());

        let mut hashdata: [u8; 20] = [0; 20];
        hasher.result(&mut hashdata);
        // println!("{}", hashdata[0]);

        let info_hash = InfoHash { data: hashdata };
        Ok(Torrent {
            data: Vec::from(data),
            root: value,
            info_hash,
            name,
            tracker_groups,
            files,
            piece_length,
            pieces,
        })
    }
}
