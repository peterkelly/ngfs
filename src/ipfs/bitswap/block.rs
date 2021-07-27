#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]


use std::error::Error;
use sha2::{Sha256, Digest as Sha2Digest};
use blake2::{Blake2b, Digest as Blake2Digest};
use crate::cid::{CID, CIDPrefix, RawCID, MultiHash};
use crate::error;

pub fn get_block_cid(prefix: &CIDPrefix, data: &[u8]) -> Result<CID, Box<dyn Error>> {
    match prefix.hash_type {
        MultiHash::Sha1 => {
            return Err(error!("Unsupported hash algorithm: Sha1"));
        }
        MultiHash::Sha2256 => {
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(CID {
                version: prefix.version,
                codec: prefix.codec,
                hash_type: MultiHash::Sha2256,
                hash: Vec::from(&hasher.finalize()[..]),
            })
        }
        MultiHash::Blake2b256 => {
            let mut hasher = Blake2b::new();
            hasher.update(data);
            Ok(CID {
                version: prefix.version,
                codec: prefix.codec,
                hash_type: MultiHash::Blake2b256,
                hash: Vec::from(&hasher.finalize()[..]),
            })
        }
        MultiHash::Blake3 => {
            return Err(error!("Unsupported hash algorithm: Blake3"));
        }
        MultiHash::Unknown(code) => {
            return Err(error!("Unsupported hash algorithm: Unknown {}", code));
        }
    }
}
