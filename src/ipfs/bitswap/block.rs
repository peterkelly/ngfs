use std::error::Error;
use sha2::{Sha256, Digest as Sha2Digest};
use blake2::Blake2b;
use crate::ipfs::types::cid::{CID, CIDPrefix, MultiHash};
use crate::error;

pub fn get_block_cid(prefix: &CIDPrefix, data: &[u8]) -> Result<CID, Box<dyn Error>> {
    match prefix.hash_type {
        MultiHash::Sha1 => {
            Err(error!("Unsupported hash algorithm: Sha1"))
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
            Err(error!("Unsupported hash algorithm: Blake3"))
        }
        MultiHash::Unknown(code) => {
            Err(error!("Unsupported hash algorithm: Unknown {}", code))
        }
    }
}
