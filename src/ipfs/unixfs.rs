// https://github.com/ipfs/specs/blob/master/UNIXFS.md

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
use crate::cid::CID;

#[derive(Debug)]
pub enum DataType {
    Raw,       // = 0;
    Directory, // = 1;
    File,      // = 2;
    Metadata,  // = 3;
    Symlink,   // = 4;
    HAMTShard, // = 5;
}

impl DataType {
    pub fn from_u8(code: u8) -> Option<DataType> {
        match code {
            0 => Some(DataType::Raw),
            1 => Some(DataType::Directory),
            2 => Some(DataType::File),
            3 => Some(DataType::Metadata),
            4 => Some(DataType::Symlink),
            5 => Some(DataType::HAMTShard),
            _ => None,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            DataType::Raw => 0,
            DataType::Directory => 1,
            DataType::File => 2,
            DataType::Metadata => 3,
            DataType::Symlink => 4,
            DataType::HAMTShard => 5,
        }
    }
}

// #[derive(Debug)]
pub struct Data {
    pub type_: DataType,         // 1
    pub data: Option<Vec<u8>>,   // 2
    pub filesize: Option<u64>,   // 3
    pub blocksizes: Vec<u64>,    // 4
    pub hash_type: Option<u64>,  // 5
    pub fanout: Option<u64>,     // 6
    pub mode: Option<u32>,       // 7
    pub mtime: Option<UnixTime>, // 8
}

impl fmt::Debug for Data {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Data");
        let mut d = d.field("type_", &self.type_);
        let mut d = match &self.data {
            Some(data) => d.field("data len", &data.len()),
            None => d.field("data", &Option::<()>::None),
        };
        let mut d = d.field("filesize", &self.filesize);
        let mut d = d.field("blocksizes", &self.blocksizes);
        let mut d = d.field("hash_type", &self.hash_type);
        let mut d = d.field("fanout", &self.fanout);
        let mut d = d.field("mode", &self.mode);
        let mut d = d.field("mtime", &self.mtime);
        d.finish()
    }
}

impl Data {
    pub fn from_pb(raw_data: &[u8]) -> Result<Data, Box<dyn Error>> {
        let mut opt_type_: Option<DataType> = None;
        let mut data: Option<Vec<u8>> = None;
        let mut filesize: Option<u64> = None;
        let mut blocksizes: Vec<u64> = Vec::new();
        let mut hash_type: Option<u64> = None;
        let mut fanout: Option<u64> = None;
        let mut mode: Option<u32> = None;
        let mut mtime: Option<UnixTime> = None;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("    Data: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &opt_type_ {
                    Some(_) => return Err(error!("duplicate opt_type_")),
                    None => {
                        match DataType::from_u8(field.data.to_uint64()? as u8) {
                            Some(type_) => opt_type_ = Some(type_),
                            None => return Err(error!("unknown data type")),
                        }
                    }
                },
                2 => match &data {
                    Some(_) => return Err(error!("duplicate data")),
                    None => data = Some(Vec::from(field.data.to_bytes()?)),
                },
                3 => match &filesize {
                    Some(_) => return Err(error!("duplicate filesize")),
                    None => filesize = Some(field.data.to_uint64()?),
                },
                4 => blocksizes.push(field.data.to_uint64()?),
                5 => match &hash_type {
                    Some(_) => return Err(error!("duplicate hash_type")),
                    None => hash_type = Some(field.data.to_uint64()?),
                },
                6 => match &fanout {
                    Some(_) => return Err(error!("duplicate fanout")),
                    None => fanout = Some(field.data.to_uint64()?),
                },
                7 => match &mode {
                    Some(_) => return Err(error!("duplicate mode")),
                    None => mode = Some(field.data.to_uint32()?),
                },
                8 => match &mtime {
                    Some(_) => return Err(error!("duplicate mtime")),
                    None => mtime = Some(UnixTime::from_pb(&field.data.to_bytes()?)?),
                },

                _ => (),
            }
        }

        let type_ = opt_type_.ok_or_else(|| error!("Missing field: type"))?;
        Ok(Data {
            type_,
            data,
            filesize,
            blocksizes,
            hash_type,
            fanout,
            mode,
            mtime,
        })
    }

}

#[derive(Debug)]
pub struct Metadata {
    pub mime_type: Option<String>, // 1
}

#[derive(Debug)]
pub struct UnixTime {
    pub seconds: i64, // 1
    pub fractional_nanoseconds: Option<u32>, // 2
}

impl UnixTime {
    pub fn from_pb(raw_data: &[u8]) -> Result<UnixTime, Box<dyn Error>> {
        let mut seconds: Option<i64> = None;
        let mut fractional_nanoseconds: Option<u32> = None;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("    UnixTime: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &seconds {
                    Some(_) => return Err(error!("duplicate seconds")),
                    None => seconds = Some(field.data.to_int64()?),
                },
                2 => match &fractional_nanoseconds {
                    Some(_) => return Err(error!("duplicate fractional_nanoseconds")),
                    None => fractional_nanoseconds = Some(field.data.to_fixed32()?),
                },
                _ => (),
            }
        }

        let seconds = seconds.ok_or_else(|| error!("Missing field: seconds"))?;
        Ok(UnixTime { seconds, fractional_nanoseconds })
    }
}
