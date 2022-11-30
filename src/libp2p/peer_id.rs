// https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md

use std::fmt;
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, FromPB, FromPBError};
use crate::util::util::{BinaryData};

#[derive(Debug, Clone)]
pub enum KeyType {
    RSA = 0,
    Ed25519 = 1,
    Secp256k1 = 2,
    ECDSA = 3,
}

impl KeyType {
    pub fn from_u64(key_type_int: u64) -> Result<KeyType, FromPBError> {
        match key_type_int {
            0 => Ok(KeyType::RSA),
            1 => Ok(KeyType::Ed25519),
            2 => Ok(KeyType::Secp256k1),
            3 => Ok(KeyType::ECDSA),
            _ => Err(FromPBError::Plain("Unknown key type")),
        }
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("key_type", &self.key_type)
            .field("data", &BinaryData(&self.data))
            .finish()
    }
}

impl FromPB for PublicKey {
    fn from_pb(raw_data: &[u8]) -> Result<PublicKey, FromPBError> {
        let mut key_type: Option<KeyType> = None;
        let mut data: Option<Vec<u8>> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            match field.field_number {
                1 => key_type = Some(KeyType::from_u64(field.data.to_uint64()?)?),
                2 => data = Some(Vec::from(field.data.to_bytes()?)),
                _ => (), // ignore
            }
        }

        Ok(PublicKey {
            key_type: key_type.ok_or(FromPBError::MissingField("key_type"))?,
            data: data.ok_or(FromPBError::MissingField("data"))?,
        })
    }
}

impl PublicKey {
    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_uint64(1, self.key_type.clone() as u64);
        writer.write_bytes(2, &self.data);
        writer.data
    }
}

pub struct PrivateKey {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

impl FromPB for PrivateKey {
    fn from_pb(raw_data: &[u8]) -> Result<PrivateKey, FromPBError> {
        let k = PublicKey::from_pb(raw_data)?;
        Ok(PrivateKey { key_type: k.key_type, data: k.data })
    }
}
