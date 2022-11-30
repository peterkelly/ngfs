use std::fmt;
// use std::error::Error;
// use crate::error;
use crate::util::util::BinaryData;
use crate::libp2p::peer_id::PublicKey;
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, ToPB, FromPB, FromPBError};
use super::multiaddr::MultiAddr;

#[derive(Clone)]
pub struct SignedPeerRecord(pub Vec<u8>);

impl fmt::Debug for SignedPeerRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", &BinaryData(&self.0))
    }
}

#[derive(Clone, Debug)]
pub struct Identify {
    pub protocol_version: String, // 5
    pub agent_version: String, // 6
    pub public_key: PublicKey, // 1
    pub listen_addrs: Vec<MultiAddr>, // 2
    pub observed_addr: MultiAddr, // 4
    pub protocols: Vec<String>, // 3
    pub signed_peer_record: Option<SignedPeerRecord>, // 8
}

impl FromPB for Identify {
    fn from_pb(raw_data: &[u8]) -> Result<Identify, FromPBError> {
        let mut opt_protocol_version: Option<String> = None;
        let mut opt_agent_version: Option<String> = None;
        let mut opt_public_key: Option<PublicKey> = None;
        let mut opt_observed_addr: Option<MultiAddr> = None;
        let mut listen_addrs: Vec<MultiAddr> = Vec::new();
        let mut protocols: Vec<String> = Vec::new();
        let mut signed_peer_record: Option<SignedPeerRecord> = None;

        let mut reader = PBufReader::new(raw_data);
        while let Some(field) = reader.read_field()? {
            match field.field_number {
                5 => match &opt_protocol_version {
                    Some(_) => return Err(FromPBError::DuplicateField("protocol_version")),
                    None => opt_protocol_version = Some(field.data.to_string()?),
                }
                6 => match &opt_agent_version {
                    Some(_) => return Err(FromPBError::DuplicateField("agent_version")),
                    None => opt_agent_version = Some(field.data.to_string()?),
                }
                3 => protocols.push(field.data.to_string()?),
                1 => match &opt_public_key {
                    Some(_) => return Err(FromPBError::DuplicateField("public_key")),
                    None => opt_public_key = Some(PublicKey::from_pb(field.data.to_bytes()?)?),
                }
                2 => listen_addrs.push(MultiAddr::from_bytes(field.data.to_bytes()?)),
                4 => match &opt_observed_addr {
                    Some(_) => return Err(FromPBError::DuplicateField("observed_addr")),
                    None => opt_observed_addr = Some(MultiAddr::from_bytes(field.data.to_bytes()?)),
                }
                8 => match &signed_peer_record {
                    Some(_) => return Err(FromPBError::DuplicateField("duplicate signed_peer_record")),
                    None => signed_peer_record = Some(SignedPeerRecord(Vec::from(field.data.to_bytes()?))),
                }
                _ => (),
            }
        }

        let protocol_version = opt_protocol_version.ok_or(FromPBError::MissingField("protocol_version"))?;
        let agent_version = opt_agent_version.ok_or(FromPBError::MissingField("agent_version"))?;
        let public_key = opt_public_key.ok_or(FromPBError::MissingField("public_key"))?;
        let observed_addr = opt_observed_addr.ok_or(FromPBError::MissingField("observed_addr"))?;

        Ok(Identify {
            protocol_version,
            agent_version,
            public_key,
            listen_addrs,
            observed_addr,
            protocols,
            signed_peer_record,
        })
    }
}

impl ToPB for Identify {
    fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.public_key.to_pb());
        for addr in self.listen_addrs.iter() {
            writer.write_bytes(2, &addr.to_bytes());
        }
        for protocol in self.protocols.iter() {
            writer.write_string(3, protocol);
        }
        writer.write_bytes(4, &self.observed_addr.to_bytes());
        writer.write_string(5, &self.protocol_version);
        writer.write_string(6, &self.agent_version);
        if let Some(signed_peer_record) = &self.signed_peer_record {
            writer.write_bytes(8, &signed_peer_record.0);
        }
        writer.data
    }
}
