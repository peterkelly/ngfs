#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use super::util::BinaryData;
use super::error;
use super::protobuf::VarInt;
use super::multibase::{decode, encode, encode_noprefix, Base};
use std::error::Error;

// https://github.com/multiformats/multicodec/blob/master/table.csv
#[derive(Debug, Clone)]
pub enum MultiCodec {
    Raw,
    DagPB,
    DagCBOR,
    LibP2PKey,
    Unknown(u64),
}

impl MultiCodec {
    fn from_u64(value: u64) -> MultiCodec {
        match value {
            0x55 => MultiCodec::Raw,
            0x70 => MultiCodec::DagPB,
            0x71 => MultiCodec::DagCBOR,
            0x72 => MultiCodec::LibP2PKey,
            _ => MultiCodec::Unknown(value),
        }
    }
}

#[derive(Debug, Clone)]
pub enum MultiHash {
    Sha1,
    Sha2256,
    Blake2b256,
    Blake3,
    Unknown(u64),
    CID, // v0
}

impl MultiHash {
    pub fn from_u64(value: u64) -> MultiHash {
        match value {
            0x11 => MultiHash::Sha1,
            0x12 => MultiHash::Sha2256,
            0xb220 => MultiHash::Blake2b256,
            0x1e => MultiHash::Blake3, // default 32 byte output length
            _ => MultiHash::Unknown(value),
        }
    }
}

pub struct RawCID(pub Vec<u8>);

impl fmt::Debug for RawCID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &BinaryData(&self.0))
    }
}

pub struct CID {
    pub raw: RawCID,
    pub version: u8,
    pub codec: MultiCodec,
    pub hash_type: MultiHash,
    pub hash: Vec<u8>,
}

impl fmt::Debug for CID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CID")
            .field("raw", &BinaryData(&self.raw.0))
            .field("version", &self.version)
            .field("codec", &self.codec)
            .field("hash_type", &self.hash_type)
            .field("hash", &BinaryData(&self.hash))
            .finish()
    }
}

impl fmt::Display for CID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl CID {
    pub fn to_string(&self) -> String {
        match self.hash_type {
            MultiHash::CID => {
                encode_noprefix(&self.raw.0, Base::Base58BTC)
            }
            _ => {
                encode(&self.raw.0, Base::Base32)
            }
        }
    }

    pub fn from_string(cid_str: &str) -> Result<CID, Box<dyn Error>> {
        let cid_bytes = decode(cid_str)?;
        return CID::from_bytes_v1(&cid_bytes);
    }

    pub fn from_bytes(cid_bytes: &[u8]) -> Result<CID, Box<dyn Error>> {
        if cid_bytes.len() == 34 && cid_bytes[0] == 0x12 && cid_bytes[1] == 0x20 {
            Ok(CID {
                raw: RawCID(Vec::from(cid_bytes)),
                version: 0,
                codec: MultiCodec::DagPB,
                hash_type: MultiHash::CID,
                hash: Vec::from(&cid_bytes[2..]),
            })
        }
        else {
            return CID::from_bytes_v1(cid_bytes);
        }
    }

    pub fn from_bytes_v1(cid_bytes: &[u8]) -> Result<CID, Box<dyn Error>> {

        // println!("cid_bytes = (len {}) {}", cid_bytes.len(), BinaryData(&cid_bytes));
        let version = match cid_bytes.get(0) {
            Some(v) => v,
            None => return Err(error!("Missing CID version")),
        };
        if *version != 1 {
            return Err(error!("Unsupported CID version: {}", version));
        }
        let mut offset: usize = 1;
        let codec_num = match VarInt::read_from(&cid_bytes, &mut offset) {
            Some(v) => v.to_u64(),
            None => return Err(error!("Missing or invalid codec")),
        };
        // let x: () = codec;
        // println!("codec_num = 0x{:x} = {}", codec_num, codec_num);
        // let x: () = cid_str;
        let codec = MultiCodec::from_u64(codec_num);
        // println!("codec = {:?}", codec);
        let hash_num = match VarInt::read_from(&cid_bytes, &mut offset) {
            Some(v) => v.to_u64(),
            None => return Err(error!("Missing or invalid hash type")),
        };
        // println!("hash_num = 0x{:x} = {}", hash_num, hash_num);
        let hash_type = MultiHash::from_u64(hash_num);
        // println!("hash_type = {:?}", hash_type);

        let hash_size = match VarInt::read_from(&cid_bytes, &mut offset) {
            Some(v) => v.to_usize(),
            None => return Err(error!("Missing or invalid hash size")),
        };
        // println!("hash_size = 0x{:x} = {}", hash_size, hash_size);
        // println!("offset = {}", offset);

        // let other_size = usize::max_value() - 1;
        let hash_start: usize = offset;
        let hash_end: usize = match hash_start.checked_add(hash_size) {
                Some(v) => v,
                None => return Err(error!("Overflow when computing hash end")),
            };
        // println!("hash_start = {}", hash_start);
        // println!("hash_end   = {}", hash_end);
        if hash_end != cid_bytes.len() {
            return Err(error!("Unexpected hash length; expected {}, got {}",
                cid_bytes.len() - hash_start, hash_size));
        }

        Ok(CID {
            raw: RawCID(Vec::from(cid_bytes)),
            version: *version,
            codec: codec,
            hash_type: hash_type,
            hash: Vec::from(&cid_bytes[hash_start..hash_end]),
        })
    }

}
