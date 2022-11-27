use std::fmt;
use std::error::Error;
use sha1::{Sha1, Digest};
use crate::formats::bencoding;
use crate::formats::bencoding::{Value};
use crate::error;
use crate::util::util::BinaryData;

pub struct InfoHash {
    pub data: [u8; 20],
}

pub struct PieceHash {
    pub data: [u8; 20],
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
    fn parse_announce_list(be_announce_list_value: &Value) -> Result<Vec<TrackerGroup>, Box<dyn Error>> {
        let mut groups: Vec<TrackerGroup> = Vec::new();
        let be_announce_list = be_announce_list_value.as_list()?;
        for be_group_value in be_announce_list.items.iter() {
            let mut members: Vec<Tracker> = Vec::new();
            let be_group_list = be_group_value.as_list()?;
            for tracker_value in be_group_list.items.iter() {
                members.push(Tracker { url: tracker_value.as_string()? });
            }
            groups.push(TrackerGroup { members });
        }

        Ok(groups)
    }

    fn parse_files(be_files_value: &Value) -> Result<Vec<TorrentFile>, Box<dyn Error>> {
        let mut files: Vec<TorrentFile> = Vec::new();
        let be_files_list = be_files_value.as_list()?;
        for be_file_value in be_files_list.items.iter() {
            let be_file_dict = be_file_value.as_dictionary()?;
            let be_length_value = be_file_dict.get_required("length")?;
            let be_path_value = be_file_dict.get_required("path")?;
            let length: usize = be_length_value.as_integer()?.value;
            let be_components_list = be_path_value.as_list()?;
            let mut spath = String::new();
            for be_component_value in be_components_list.items.iter() {
                let component = be_component_value.as_string()?;
                if !spath.is_empty() {
                    spath.push('/');
                }
                spath.push_str(&component);
            }
            files.push(TorrentFile { length, path: spath });
        }
        Ok(files)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Torrent, Box<dyn Error>> {
        let value = bencoding::parse(data)?;
        let root = value.as_dictionary()?;
        let info = root.get_required("info")?.as_dictionary()?;

        let name = info.get_required("name")?.as_string()?;
        let announce_list = root.get_required("announce-list")?;
        let tracker_groups = Torrent::parse_announce_list(announce_list)?;

        let files_node = info.get_required("files")?;
        let files = Self::parse_files(files_node)?;

        let piece_length = info.get_required("piece length")?.as_integer()?.value;
        let pieces_data = &info.get_required("pieces")?.as_byte_string()?.data;
        if pieces_data.len() % 20 != 0 {
            return Err(error!("Pieces data is {} bytes, which is not a multiple of 20", pieces_data.len()));
        }

        let mut pieces = Vec::<PieceHash>::new();
        let mut i = 0;
        while i + 20 <= pieces_data.len() {
            let mut data: [u8; 20] = [0; 20];
            data.copy_from_slice(&pieces_data[i..i + 20]);
            pieces.push(PieceHash { data });
            i += 20;
        }

        let mut hasher: Sha1 = Sha1::new();
        hasher.update(&data[info.loc.start..info.loc.end]);
        let hashdata: [u8; 20] = hasher.finalize().into();

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
