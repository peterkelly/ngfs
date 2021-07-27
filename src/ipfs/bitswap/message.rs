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
    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.block.0);
        writer.write_int32(2, self.priority);
        if self.cancel {
            writer.write_bool(3, self.cancel);
        }
        match self.want_type {
            WantType::Block => writer.write_int32(4, 0),
            WantType::Have => writer.write_int32(4, 1),
        }
        if self.send_dont_have {
            writer.write_bool(5, self.send_dont_have);
        }
        writer.data
    }

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
    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        for entry in self.entries.iter() {
            writer.write_bytes(1, &entry.to_pb());
        }
        if self.full {
            writer.write_bool(2, self.full);
        }
        writer.data
    }

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

// #[derive(Debug)]
pub struct Block {
    pub prefix: Vec<u8>,
    pub data: Vec<u8>,
}

impl Block {
    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.prefix);
        writer.write_bytes(2, &self.data);
        writer.data
    }

    pub fn from_pb(raw_data: &[u8]) -> Result<Block, Box<dyn Error>> {
        let mut prefix: Option<Vec<u8>> = None;
        let mut data: Option<Vec<u8>> = None;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            println!("    Block: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &prefix {
                    Some(_) => return Err(error!("duplicate prefix")),
                    None => prefix = Some(Vec::from(field.data.to_bytes()?)),
                },
                2 => match &data {
                    Some(_) => return Err(error!("duplicate data")),
                    None => data = Some(Vec::from(field.data.to_bytes()?)),
                },
                _ => (),
            }
        }

        let prefix = prefix.ok_or_else(|| error!("Missing field: prefix"))?;
        let data = data.ok_or_else(|| error!("Missing field: data"))?;

        Ok(Block {
            prefix,
            data,
        })
    }
}

impl fmt::Debug for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Block")
            .field("prefix", &BinaryData(&self.prefix))
            .field("data", &BinaryData(&self.data))
            .finish()
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
    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        if let Some(wantlist) = &self.wantlist {
            writer.write_bytes(1, &wantlist.to_pb());
        }
        for block in self.blocks.iter() {
            writer.write_bytes(3, &block.to_pb());
        }
        writer.data
    }

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
                3 => blocks.push(Block::from_pb(&field.data.to_bytes()?)?),
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
