#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use crate::error;
use crate::protobuf::{PBufReader, PBufWriter};
use crate::cid::{CID, RawCID};
use crate::util::BinaryData;

#[derive(Debug)]
pub enum WantType {
    Block,
    Have,
}

#[derive(Debug)]
pub struct Entry {
    pub block: RawCID, // CID
    pub priority: i32, // default 1
    pub cancel: bool, // assume default false (not specified?)
    pub want_type: WantType, // default WantType::Block
    pub send_dont_have: bool, // default false
}

impl Entry {
    pub fn from_pb(raw_data: &[u8]) -> Result<Entry, Box<dyn Error>> {

        let mut opt_block: Option<Vec<u8>> = None;
        let mut priority: i32 = 1;
        let mut cancel: bool = false;
        let mut want_type: WantType = WantType::Block;
        let mut send_dont_have: bool = false;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            println!("        Entry: field {} wire_type {}", field.field_number, field.wire_type);

            match field.field_number {
                1 => {
                    opt_block = Some(Vec::from(field.data.to_bytes()?));
                },
                2 => {
                    priority = field.data.to_i32()?;
                }
                3 => {
                    cancel = field.data.to_bool()?;
                }
                4 => {
                    let v = field.data.to_i32()?;
                    match v {
                        0 => want_type = WantType::Block,
                        1 => want_type = WantType::Have,
                        _ => return Err(error!("Invalid want_type: {}", v)),
                    }
                }
                5 => {
                    send_dont_have = field.data.to_bool()?;
                }
                _ => (),
            }

        }

        let block = opt_block.ok_or_else(|| error!("Missing field: block"))?;
        match CID::from_bytes(&block) {
            Ok(cid) => {
                println!("Parsed CID: {:#?}", cid);
                println!("CID = {}", cid);
            }
            Err(e) => {
                println!("Parsing CID failed: {}", e);
            }
        }

        Ok(Entry {
            block: RawCID(block),
            priority,
            cancel,
            want_type,
            send_dont_have,
        })
    }
}

#[derive(Debug)]
pub struct WantList {
    pub entries: Vec<Entry>,
    pub full: bool, // default false
}

impl WantList {
    pub fn from_pb(raw_data: &[u8]) -> Result<WantList, Box<dyn Error>> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut full: bool = false;


        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            println!("    WantList: field {} wire_type {}", field.field_number, field.wire_type);

            match field.field_number {
                1 => {
                    entries.push(Entry::from_pb(&field.data.to_bytes()?)?);
                },
                2 => {
                    full = field.data.to_bool()?;
                }
                _ => (),
            }
        }

        Ok(WantList {
            entries,
            full,
        })
    }
}

#[derive(Debug)]
pub struct Block {
    pub prefix: Vec<u8>,
    pub data: Vec<u8>,
}

impl Block {
    pub fn from_pb(raw_data: &[u8]) -> Result<Block, Box<dyn Error>> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum BlockPresenceType {
    Have,
    DontHave,
}

#[derive(Debug)]
pub struct BlockPresence {
    pub cid: Vec<u8>,
    pub type_: BlockPresenceType,
}

impl BlockPresence {
    pub fn from_pb(raw_data: &[u8]) -> Result<BlockPresence, Box<dyn Error>> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct Message {
    pub wantlist: Option<WantList>,
    pub blocks: Vec<Block>,
    pub payload: Vec<Block>,
    pub block_presence: Vec<BlockPresence>,
    pub pending_bytes: Option<u32>,
}

impl Message {
    pub fn from_pb(raw_data: &[u8]) -> Result<Message, Box<dyn Error>> {
        let mut wantlist: Option<WantList> = None;
        let mut blocks: Vec<Block> = Vec::new();
        let mut payload: Vec<Block> = Vec::new();
        let mut block_presence: Vec<BlockPresence> = Vec::new();
        let mut pending_bytes: Option<u32> = None;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            println!("Message: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &wantlist {
                    Some(_) => return Err(error!("duplicate wantlist")),
                    None => wantlist = Some(WantList::from_pb(&field.data.to_bytes()?)?),
                },
                _ => (),
            }
        }

        Ok(Message {
            wantlist,
            blocks,
            payload,
            block_presence,
            pending_bytes,
        })

    }
}
