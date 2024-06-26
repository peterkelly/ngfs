use std::fmt;
use crate::util::util::BinaryData;
use crate::formats::protobuf::protobuf::VarInt;
use crate::formats::protobuf::varint;
use super::multibase::{decode, decode_noprefix, encode, encode_noprefix, Base, DecodeError};
use std::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CIDVersion {
    CIDv0,
    CIDv1,
}

// https://github.com/multiformats/multicodec/blob/master/table.csv
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            _    => MultiCodec::Unknown(value),
        }
    }

    fn to_u64(self) -> u64 {
        match self {
            MultiCodec::Raw            => 0x55,
            MultiCodec::DagPB          => 0x70,
            MultiCodec::DagCBOR        => 0x71,
            MultiCodec::LibP2PKey      => 0x72,
            MultiCodec::Unknown(value) => value,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiHash {
    Sha1,
    Sha2256,
    Blake2b256,
    Blake3,
    Unknown(u64),
}

impl MultiHash {
    pub fn from_u64(value: u64) -> MultiHash {
        match value {
            0x11   => MultiHash::Sha1,
            0x12   => MultiHash::Sha2256,
            0xb220 => MultiHash::Blake2b256,
            0x1e   => MultiHash::Blake3, // default 32 byte output length
            _      => MultiHash::Unknown(value),
        }
    }

    fn to_u64(self) -> u64 {
        match self {
            MultiHash::Sha1           => 0x11,
            MultiHash::Sha2256        => 0x12,
            MultiHash::Blake2b256     => 0xb220,
            MultiHash::Blake3         => 0x1e,
            MultiHash::Unknown(value) => value,
        }
    }
}


pub struct RawCID(pub Vec<u8>);

impl fmt::Debug for RawCID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &BinaryData(&self.0))
    }
}

#[derive(Debug, Clone)]
pub enum CIDParseError {
    DecodeError(DecodeError),
    Empty,
    UnsupportedVersion,
    InvalidCodec,
    InvalidHashType,
    InvalidHashSize,
    HashSizeMismatch,
}

impl fmt::Display for CIDParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CIDParseError::DecodeError(e) => {
                write!(f, "{}", e)
            }
            CIDParseError::Empty => {
                write!(f, "Empty CID")
            }
            CIDParseError::UnsupportedVersion => {
                write!(f, "Unsupported version")
            }
            CIDParseError::InvalidCodec => {
                write!(f, "Missing or invalid codec")
            }
            CIDParseError::InvalidHashType => {
                write!(f, "Missing or invalid hash type")
            }
            CIDParseError::InvalidHashSize => {
                write!(f, "Missing or invalid hash size")
            }
            CIDParseError::HashSizeMismatch => {
                write!(f, "Hash size mismatch")
            }
        }
    }
}

impl Error for CIDParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

pub struct CID {
    pub version: CIDVersion,
    pub codec: MultiCodec,
    pub hash_type: MultiHash,
    pub hash: Vec<u8>,
}

impl fmt::Debug for CID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CID")
            .field("version", &self.version)
            .field("codec", &self.codec)
            .field("hash_type", &self.hash_type)
            .field("hash", &BinaryData(&self.hash))
            .finish()
    }
}

impl fmt::Display for CID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        if Self::is_cid_v0(&bytes) {
            write!(f, "{}", encode_noprefix(&bytes, Base::Base58BTC))
        }
        else {
            write!(f, "{}", encode(&bytes, Base::Base32))
        }
    }
}

impl CID {
    pub fn is_cid_v0(cid_bytes: &[u8]) -> bool {
        cid_bytes.len() == 34 && cid_bytes[0] == 0x12 && cid_bytes[1] == 0x20
    }

    pub fn from_string(cid_str: &str) -> Result<CID, CIDParseError> {
        if cid_str.len() == 46 && cid_str.starts_with("Qm") {
            let cid_bytes = decode_noprefix(cid_str, Base::Base58BTC)
                .map_err(CIDParseError::DecodeError)?;
            Self::from_bytes(&cid_bytes)
        }
        else {
            let cid_bytes = decode(cid_str).map_err(CIDParseError::DecodeError)?;
            Ok(CID::from_bytes_v1(&cid_bytes)?)
        }
    }

    pub fn from_bytes(cid_bytes: &[u8]) -> Result<CID, CIDParseError> {
        if Self::is_cid_v0(cid_bytes) {
            Ok(CID {
                version: CIDVersion::CIDv0,
                codec: MultiCodec::DagPB,
                hash_type: MultiHash::Sha2256,
                hash: Vec::from(&cid_bytes[2..]),
            })
        }
        else {
            CID::from_bytes_v1(cid_bytes)
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match (&self.version, &self.codec, &self.hash_type, self.hash.len()) {
            (CIDVersion::CIDv0, MultiCodec::DagPB, MultiHash::Sha2256, 32) => {
                let mut result: Vec<u8> = Vec::new();
                result.push(0x12);
                result.push(0x20);
                result.extend_from_slice(&self.hash);
                result
            }
            (_, _, _, _) => {
                self.to_bytes_v1()
            }
        }
    }

    pub fn to_bytes_v1(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        result.push(1);
        varint::encode_u64(self.codec.to_u64(), &mut result);
        varint::encode_u64(self.hash_type.to_u64(), &mut result);
        varint::encode_usize(self.hash.len(), &mut result);
        result.extend_from_slice(&self.hash);
        result
    }

    pub fn from_bytes_v1(cid_bytes: &[u8]) -> Result<CID, CIDParseError> {
        // CID version
        let version = match cid_bytes.first() {
            Some(v) => v,
            None => return Err(CIDParseError::Empty),
        };
        if *version != 1 {
            return Err(CIDParseError::UnsupportedVersion);
        }

        // Codec
        let mut offset: usize = 1;
        let codec_num = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_u64().map_err(|_| CIDParseError::InvalidCodec)?,
            None => return Err(CIDParseError::InvalidCodec),
        };
        let codec = MultiCodec::from_u64(codec_num);

        // Hash type
        let hash_num = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_u64().map_err(|_| CIDParseError::InvalidHashType)?,
            None => return Err(CIDParseError::InvalidHashType),
        };
        let hash_type = MultiHash::from_u64(hash_num);

        // Hash size
        let hash_size = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_usize().map_err(|_| CIDParseError::InvalidHashSize)?,
            None => return Err(CIDParseError::InvalidHashSize),
        };

        // Hash
        let hash_start: usize = offset;
        let hash_end: usize = match hash_start.checked_add(hash_size) {
            Some(v) => v,
            None => return Err(CIDParseError::HashSizeMismatch),
        };
        if hash_end != cid_bytes.len() {
            return Err(CIDParseError::HashSizeMismatch);
        }

        Ok(CID {
            version: CIDVersion::CIDv1,
            codec,
            hash_type,
            hash: Vec::from(&cid_bytes[hash_start..hash_end]),
        })
    }
}

// Used in Bitswap block objects
#[derive(Debug, Clone)]
pub struct CIDPrefix {
    pub version: CIDVersion,
    pub codec: MultiCodec,
    pub hash_type: MultiHash,
    pub hash_size: usize,
}

impl CIDPrefix {
    pub fn from_bytes(cid_bytes: &[u8]) -> Result<CIDPrefix, CIDParseError> {
        // CID version
        let version = match cid_bytes.first() {
            Some(0) => CIDVersion::CIDv0,
            Some(1) => CIDVersion::CIDv1,
            Some(_) => return Err(CIDParseError::UnsupportedVersion),
            None => return Err(CIDParseError::Empty),
        };

        // Codec
        let mut offset: usize = 1;
        let codec_num = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_u64().map_err(|_| CIDParseError::InvalidCodec)?,
            None => return Err(CIDParseError::InvalidCodec),
        };
        let codec = MultiCodec::from_u64(codec_num);

        // Hash type
        let hash_num = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_u64().map_err(|_| CIDParseError::InvalidHashType)?,
            None => return Err(CIDParseError::InvalidHashType),
        };
        let hash_type = MultiHash::from_u64(hash_num);

        // Hash size
        let hash_size = match VarInt::read_from(cid_bytes, &mut offset) {
            Some(v) => v.to_usize().map_err(|_| CIDParseError::InvalidHashSize)?,
            None => return Err(CIDParseError::InvalidHashSize),
        };

        Ok(CIDPrefix { version, codec, hash_type, hash_size })
    }
}

#[cfg(test)]
mod tests {
    use super::{CID, CIDVersion, MultiCodec, MultiHash};

    #[test]
    fn cid_from_string_v0() {
        let s = "QmbWqxBEKC3P8tqsKc98xmWNzrzDtRLMiMPL8wBuTGsMnR";
        let cid = CID::from_string(s).unwrap();
        assert!(cid.version == CIDVersion::CIDv0);
        assert!(cid.codec == MultiCodec::DagPB);
        assert!(cid.hash_type == MultiHash::Sha2256);
        assert!(cid.hash == [0xc3, 0xc4, 0x73, 0x3e, 0xc8, 0xaf, 0xfd, 0x06,
                             0xcf, 0x9e, 0x9f, 0xf5, 0x0f, 0xfc, 0x6b, 0xcd,
                             0x2e, 0xc8, 0x5a, 0x61, 0x70, 0x00, 0x4b, 0xb7,
                             0x09, 0x66, 0x9c, 0x31, 0xde, 0x94, 0x39, 0x1a]);
        assert!(format!("{}", cid) == s);
    }

    #[test]
    fn cid_from_string_v1() {
        let s = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let cid = CID::from_string(s).unwrap();
        assert!(cid.version == CIDVersion::CIDv1);
        assert!(cid.codec == MultiCodec::DagPB);
        assert!(cid.hash_type == MultiHash::Sha2256);
        assert!(cid.hash == [0xc3, 0xc4, 0x73, 0x3e, 0xc8, 0xaf, 0xfd, 0x06,
                             0xcf, 0x9e, 0x9f, 0xf5, 0x0f, 0xfc, 0x6b, 0xcd,
                             0x2e, 0xc8, 0x5a, 0x61, 0x70, 0x00, 0x4b, 0xb7,
                             0x09, 0x66, 0x9c, 0x31, 0xde, 0x94, 0x39, 0x1a]);
        assert!(format!("{}", cid) == s);
    }
}
