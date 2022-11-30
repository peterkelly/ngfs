use std::fmt;
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, ToPB, FromPB, FromPBError};
use crate::ipfs::types::cid::{CID, RawCID};
use crate::util::util::BinaryData;

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

impl ToPB for Entry {
    fn to_pb(&self) -> Vec<u8> {
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
}

impl FromPB for Entry {
    fn from_pb(raw_data: &[u8]) -> Result<Entry, FromPBError> {

        let mut opt_block: Option<Vec<u8>> = None;
        let mut priority: i32 = 1;
        let mut cancel: bool = false;
        let mut want_type: WantType = WantType::Block;
        let mut send_dont_have: bool = false;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            println!("        Entry: field {} wire_type {}", field.field_number, field.wire_type);

            match field.field_number {
                1 => {
                    opt_block = Some(Vec::from(field.data.to_bytes()?));
                },
                2 => {
                    priority = field.data.to_int32()?;
                }
                3 => {
                    cancel = field.data.to_bool()?;
                }
                4 => {
                    let v = field.data.to_uint64()?;
                    match v {
                        0 => want_type = WantType::Block,
                        1 => want_type = WantType::Have,
                        _ => return Err(FromPBError::Plain("Invalid want_type")),
                    }
                }
                5 => {
                    send_dont_have = field.data.to_bool()?;
                }
                _ => (),
            }

        }

        let block = opt_block.ok_or(FromPBError::MissingField("block"))?;
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

impl ToPB for WantList {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        for entry in self.entries.iter() {
            writer.write_bytes(1, &entry.to_pb());
        }
        if self.full {
            writer.write_bool(2, self.full);
        }
        writer.data
    }
}

impl FromPB for WantList {
    fn from_pb(raw_data: &[u8]) -> Result<WantList, FromPBError> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut full: bool = false;


        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            println!("    WantList: field {} wire_type {}", field.field_number, field.wire_type);

            match field.field_number {
                1 => {
                    entries.push(Entry::from_pb(field.data.to_bytes()?)?);
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

impl ToPB for Block {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.prefix);
        writer.write_bytes(2, &self.data);
        writer.data
    }
}

impl FromPB for Block {
    fn from_pb(raw_data: &[u8]) -> Result<Block, FromPBError> {
        let mut prefix: Option<Vec<u8>> = None;
        let mut data: Option<Vec<u8>> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            println!("    Block: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &prefix {
                    Some(_) => return Err(FromPBError::DuplicateField("prefix")),
                    None => prefix = Some(Vec::from(field.data.to_bytes()?)),
                },
                2 => match &data {
                    Some(_) => return Err(FromPBError::DuplicateField("data")),
                    None => data = Some(Vec::from(field.data.to_bytes()?)),
                },
                _ => (),
            }
        }

        let prefix = prefix.ok_or(FromPBError::MissingField("prefix"))?;
        let data = data.ok_or(FromPBError::MissingField("data"))?;

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

impl FromPB for BlockPresence {
    fn from_pb(_raw_data: &[u8]) -> Result<BlockPresence, FromPBError> {
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

impl ToPB for Message {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        if let Some(wantlist) = &self.wantlist {
            writer.write_bytes(1, &wantlist.to_pb());
        }
        for block in self.blocks.iter() {
            writer.write_bytes(3, &block.to_pb());
        }
        writer.data
    }
}

impl FromPB for Message {
    fn from_pb(raw_data: &[u8]) -> Result<Message, FromPBError> {
        let mut wantlist: Option<WantList> = None;
        let mut blocks: Vec<Block> = Vec::new();
        let payload: Vec<Block> = Vec::new();
        let block_presence: Vec<BlockPresence> = Vec::new();
        let pending_bytes: Option<u32> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            println!("Message: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &wantlist {
                    Some(_) => return Err(FromPBError::DuplicateField("wantlist")),
                    None => wantlist = Some(WantList::from_pb(field.data.to_bytes()?)?),
                },
                3 => blocks.push(Block::from_pb(field.data.to_bytes()?)?),
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
