#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use super::dagpb::{PBLink, PBNode};
use super::unixfs::{Data, DataType};
use super::super::cid::CID;
use std::collections::HashSet;

pub enum Node {
    Raw(Raw),
    Directory(Directory),
    File(File),
    Metadata(Metadata),
    Symlink(Symlink),
    HAMTShard(HAMTShard),
}

pub struct Raw {
}

pub struct DirectoryEntry {
    pub cid: CID,
    pub name: String,
    pub tsize: usize,
}

pub struct Directory {
    pub entries: Vec<DirectoryEntry>,
}

pub struct File {
}

pub struct Metadata {
}

pub struct Symlink {
}

pub struct HAMTShard {
}

#[derive(Debug)]
pub enum DecodeError {
    MissingData,
    EntryMissingFilename(usize),
    EntryMissingSize(usize),
    EntryDuplicateFilename(String), // Directory has duplicate filenames
    Other(String),
    Unimplemented(String),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeError::MissingData =>
                write!(f, "DAG-PB bytes field is None"),
            DecodeError::EntryMissingFilename(index) =>
                write!(f, "Directory entry {} has no filename", index),
            DecodeError::EntryMissingSize(index) =>
                write!(f, "Directory entry {} has no size", index),
            DecodeError::EntryDuplicateFilename(filename) =>
                write!(f, "Directory has duplicate filename: {:?}", filename),
            DecodeError::Other(msg) =>
                write!(f, "{}", msg),
            DecodeError::Unimplemented(op) =>
                write!(f, "Unimplemented: {}", op),
        }
    }
}

impl Error for DecodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl Node {
    pub fn from_dagpb_data(data: &[u8]) -> Result<Node, DecodeError> {
        let dagpb_node = PBNode::from_pb(data).map_err(|e| DecodeError::Other(format!("{}", e)))?;
        let bytes = match &dagpb_node.bytes {
            Some(bytes) => bytes,
            None => return Err(DecodeError::MissingData),
        };
        let unixfs_data = Data::from_pb(bytes).map_err(|e| DecodeError::Other(format!("{}", e)))?;
        match unixfs_data.type_ {
            DataType::Raw => Ok(Node::Raw(Raw::from_dagpb(dagpb_node, unixfs_data)?)),
            DataType::Directory => Ok(Node::Directory(Directory::from_dagpb(dagpb_node, unixfs_data)?)),
            DataType::File => Ok(Node::File(File::from_dagpb(dagpb_node, unixfs_data)?)),
            DataType::Metadata => Ok(Node::Metadata(Metadata::from_dagpb(dagpb_node, unixfs_data)?)),
            DataType::Symlink => Ok(Node::Symlink(Symlink::from_dagpb(dagpb_node, unixfs_data)?)),
            DataType::HAMTShard => Ok(Node::HAMTShard(HAMTShard::from_dagpb(dagpb_node, unixfs_data)?)),
        }
    }
}

impl Raw {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<Raw, DecodeError> {
        Err(DecodeError::Unimplemented(String::from("Raw")))
    }
}

impl Directory {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<Directory, DecodeError> {
        let mut entries: Vec<DirectoryEntry> = Vec::new();
        let mut names: HashSet<String> = HashSet::new();

        let mut index = 0;
        for link in dagpb_node.links {
            let name = match &link.name {
                None => return Err(DecodeError::EntryMissingFilename(index)),
                Some(name) => {
                    if name == "" {
                        return Err(DecodeError::EntryMissingFilename(index));
                    }
                    else if names.contains(name) {
                        return Err(DecodeError::EntryDuplicateFilename(name.clone()));
                    }
                    else {
                        name
                    }
                },
            };
            let size = match &link.tsize {
                None => return Err(DecodeError::EntryMissingSize(index)),
                Some(size) => *size,
            };
            names.insert(name.clone());
            entries.push(DirectoryEntry {
                cid: link.hash,
                name: name.clone(),
                tsize: size as usize,
            });
            index += 1;
        }

        Ok(Directory { entries })
    }
}

impl File {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<File, DecodeError> {
        Err(DecodeError::Unimplemented(String::from("File")))
    }
}

impl Metadata {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<Metadata, DecodeError> {
        Err(DecodeError::Unimplemented(String::from("Metadata")))
    }
}

impl Symlink {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<Symlink, DecodeError> {
        Err(DecodeError::Unimplemented(String::from("Symlink")))
    }
}

impl HAMTShard {
    pub fn from_dagpb(dagpb_node: PBNode, unixfs_data: Data) -> Result<HAMTShard, DecodeError> {
        Err(DecodeError::Unimplemented(String::from("HAMTShard")))
    }
}
