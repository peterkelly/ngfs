// https://github.com/ipld/specs/blob/master/block-layer/codecs/dag-pb.md

use std::fmt;
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, ToPB, FromPB, FromPBError};
use crate::ipfs::types::cid::CID;
use crate::util::util::OptBinaryDataLen;

pub struct PBLink {
    pub hash: CID,
    pub name: Option<String>,
    pub tsize: Option<u64>,
}

impl fmt::Debug for PBLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PBLink")
            .field("hash", &self.hash.to_string())
            .field("name", &self.name)
            .field("tsize", &self.tsize)
            .finish()
    }
}

impl ToPB for PBLink {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.hash.to_bytes());
        if let Some(name) = &self.name {
            writer.write_string(2, name);
        }
        if let Some(tsize) = self.tsize {
            writer.write_uint64(3, tsize);
        }
        writer.data
    }
}

impl FromPB for PBLink {
    fn from_pb(raw_data: &[u8]) -> Result<PBLink, FromPBError> {
        // TODO: Enforce ordering as per spec
        let mut hash: Option<Vec<u8>> = None;
        let mut name: Option<String> = None;
        let mut tsize: Option<u64> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("    PBLink: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                1 => match &hash {
                    Some(_) => return Err(FromPBError::DuplicateField("hash")),
                    None => hash = Some(Vec::from(field.data.to_bytes()?)),
                },

                2 => match &name {
                    Some(_) => return Err(FromPBError::DuplicateField("name")),
                    None => name = Some(field.data.to_string()?),
                },

                3 => match &tsize {
                    Some(_) => return Err(FromPBError::DuplicateField("tsize")),
                    None => tsize = Some(field.data.to_uint64()?),
                },
                _ => (),
            }
        }

        let hash = hash.ok_or(FromPBError::MissingField("hash"))?;
        let hash = CID::from_bytes(&hash).map_err(|_| FromPBError::Plain("Invalid cid"))?;

        Ok(PBLink { hash, name, tsize })
    }
}

pub struct PBNode {
    pub links: Vec<PBLink>,
    pub bytes: Option<Vec<u8>>,
}

impl fmt::Debug for PBNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PBNode")
            .field("links", &self.links)
            .field("bytes", &OptBinaryDataLen(&self.bytes))
            .finish()
    }
}

impl ToPB for PBNode {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        for link in self.links.iter() {
            writer.write_bytes(2, &link.to_pb());
        }
        if let Some(bytes) = &self.bytes {
            writer.write_bytes(1, bytes);
        }
        writer.data
    }
}

impl FromPB for PBNode {
    fn from_pb(raw_data: &[u8]) -> Result<PBNode, FromPBError> {
        // Zero length data block is considered valid
        if raw_data.is_empty() {
            return Ok(PBNode { links: vec![], bytes: None });
        }

        let mut links: Vec<PBLink> = Vec::new();
        let mut bytes: Option<Vec<u8>> = None;


        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("    PBNode: field {} wire_type {}", field.field_number, field.wire_type);
            match field.field_number {
                2 => {
                    links.push(PBLink::from_pb(field.data.to_bytes()?)?);
                },
                1 => match &bytes {
                    Some(_) => return Err(FromPBError::DuplicateField("bytes")),
                    None => bytes = Some(Vec::from(field.data.to_bytes()?)),
                },
                _ => (),
            }
        }

        Ok(PBNode { links, bytes })
    }
}
