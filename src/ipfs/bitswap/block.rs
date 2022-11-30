use std::fmt;
use sha2::{Sha256, Digest as Sha2Digest};
use blake2::Blake2b;
use crate::ipfs::types::cid::{CID, CIDPrefix, MultiHash};

pub struct GetBlockCIDError(&'static str);

impl std::error::Error for GetBlockCIDError {}

impl fmt::Display for GetBlockCIDError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for GetBlockCIDError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

pub fn get_block_cid(prefix: &CIDPrefix, data: &[u8]) -> Result<CID, GetBlockCIDError> {
    match prefix.hash_type {
        MultiHash::Sha1 => {
            Err(GetBlockCIDError("Unsupported hash algorithm: Sha1"))
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
            Err(GetBlockCIDError("Unsupported hash algorithm: Blake3"))
        }
        MultiHash::Unknown(_) => {
            Err(GetBlockCIDError("Unsupported hash algorithm: Unknown"))
        }
    }
}
