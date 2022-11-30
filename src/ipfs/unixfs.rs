// https://github.com/ipfs/specs/blob/master/UNIXFS.md

use std::fmt;
use crate::formats::protobuf::protobuf::{PBufReader, FromPB, FromPBError};

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
    pub fn from_u64(code: u64) -> Result<DataType, FromPBError> {
        match code {
            0 => Ok(DataType::Raw),
            1 => Ok(DataType::Directory),
            2 => Ok(DataType::File),
            3 => Ok(DataType::Metadata),
            4 => Ok(DataType::Symlink),
            5 => Ok(DataType::HAMTShard),
            _ => Err(FromPBError::Plain("unknown data type")),
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
        let d = d.field("type_", &self.type_);
        let d = match &self.data {
            Some(data) => d.field("data len", &data.len()),
            None => d.field("data", &Option::<()>::None),
        };
        let d = d.field("filesize", &self.filesize);
        let d = d.field("blocksizes", &self.blocksizes);
        let d = d.field("hash_type", &self.hash_type);
        let d = d.field("fanout", &self.fanout);
        let d = d.field("mode", &self.mode);
        let d = d.field("mtime", &self.mtime);
        d.finish()
    }
}

impl FromPB for Data {
    fn from_pb(raw_data: &[u8]) -> Result<Data, FromPBError> {
        let mut opt_type_: Option<DataType> = None;
        let mut data: Option<Vec<u8>> = None;
        let mut filesize: Option<u64> = None;
        let mut blocksizes: Vec<u64> = Vec::new();
        let mut hash_type: Option<u64> = None;
        let mut fanout: Option<u64> = None;
        let mut mode: Option<u32> = None;
        let mut mtime: Option<UnixTime> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            match field.field_number {
                1 => match &opt_type_ {
                    Some(_) => return Err(FromPBError::DuplicateField("type")),
                    None => opt_type_ = Some(DataType::from_u64(field.data.to_uint64()?)?)
                },
                2 => match &data {
                    Some(_) => return Err(FromPBError::DuplicateField("data")),
                    None => data = Some(Vec::from(field.data.to_bytes()?)),
                },
                3 => match &filesize {
                    Some(_) => return Err(FromPBError::DuplicateField("filesize")),
                    None => filesize = Some(field.data.to_uint64()?),
                },
                4 => blocksizes.push(field.data.to_uint64()?),
                5 => match &hash_type {
                    Some(_) => return Err(FromPBError::DuplicateField("hash_type")),
                    None => hash_type = Some(field.data.to_uint64()?),
                },
                6 => match &fanout {
                    Some(_) => return Err(FromPBError::DuplicateField("fanout")),
                    None => fanout = Some(field.data.to_uint64()?),
                },
                7 => match &mode {
                    Some(_) => return Err(FromPBError::DuplicateField("mode")),
                    None => mode = Some(field.data.to_uint32()?),
                },
                8 => match &mtime {
                    Some(_) => return Err(FromPBError::DuplicateField("duplicate mtime")),
                    None => mtime = Some(UnixTime::from_pb(field.data.to_bytes()?)?),
                },
                _ => (),
            }
        }

        let type_ = opt_type_.ok_or(FromPBError::MissingField("type"))?;
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

impl FromPB for UnixTime {
    fn from_pb(raw_data: &[u8]) -> Result<UnixTime, FromPBError> {
        let mut seconds: Option<i64> = None;
        let mut fractional_nanoseconds: Option<u32> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            match field.field_number {
                1 => match &seconds {
                    Some(_) => return Err(FromPBError::DuplicateField("seconds")),
                    None => seconds = Some(field.data.to_int64()?),
                },
                2 => match &fractional_nanoseconds {
                    Some(_) => return Err(FromPBError::DuplicateField("fractional_nanoseconds")),
                    None => fractional_nanoseconds = Some(field.data.to_fixed32()?),
                },
                _ => (),
            }
        }

        let seconds = seconds.ok_or(FromPBError::MissingField("seconds"))?;
        Ok(UnixTime { seconds, fractional_nanoseconds })
    }
}
