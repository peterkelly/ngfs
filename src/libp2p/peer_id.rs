// https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md

use std::fmt;
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, FromPBError};
use crate::util::util::{BinaryData};

#[derive(Debug, Clone)]
pub enum KeyType {
    RSA = 0,
    Ed25519 = 1,
    Secp256k1 = 2,
    ECDSA = 3,
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

impl PublicKey {
    pub fn from_pb(raw_data: &[u8]) -> Result<PublicKey, FromPBError> {
        let mut key_type: Option<KeyType> = None;
        let mut data: Option<Vec<u8>> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            //     field.offset, field.field_number, field.data);
            match field.field_number {
                1 => {
                    let key_type_int = field.data.to_uint64()?;
                    key_type = match key_type_int {
                        0 => Some(KeyType::RSA),
                        1 => Some(KeyType::Ed25519),
                        2 => Some(KeyType::Secp256k1),
                        3 => Some(KeyType::ECDSA),
                        _ => {
                            return Err(FromPBError::Plain("Unknown key type"));
                        }
                    }
                }
                2 => {
                    data = Some(Vec::from(field.data.to_bytes()?));
                }
                _ => {
                }
            }
        }

        let key_type: KeyType = key_type.ok_or(FromPBError::MissingField("key_type"))?;
        let data: Vec<u8> = data.ok_or(FromPBError::MissingField("data"))?;

        Ok(PublicKey {
            key_type,
            data,
        })
    }

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

impl PrivateKey {
    pub fn from_pb(raw_data: &[u8]) -> Result<PrivateKey, FromPBError> {
        let k = PublicKey::from_pb(raw_data)?;
        Ok(PrivateKey { key_type: k.key_type, data: k.data })
    }
}

pub fn encode_libp2p_public_key(dalek_public_key: &ed25519_dalek::PublicKey) -> Vec<u8> {
    let libp2p_public_key = PublicKey {
        key_type: KeyType::Ed25519,
        data: Vec::from(dalek_public_key.to_bytes()),
    };
    let libp2p_public_key_bytes: Vec<u8> = libp2p_public_key.to_pb();
    libp2p_public_key_bytes
}
