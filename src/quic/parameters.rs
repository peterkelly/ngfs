use std::fmt;
use std::error::Error;
use crate::util::binary::{BinaryReader, BinaryWriter, BinaryError};
use crate::util::util::BinaryData;
use super::spec::ConnectionId;

pub fn quic_varint_from_bytes(data: &[u8]) -> Result<u64, BinaryError> {
    let mut reader = BinaryReader::new(data);
    let res = reader.read_quic_varint()?;
    reader.expect_eof()?;
    Ok(res)
}

pub enum TransportParameter {
    OriginalDstConnectionId(ConnectionId),   // 0x00 TODO
    MaxIdleTimeout(u64),                     // 0x01
    MaxUDPPayloadSize(u64),                  // 0x03
    InitialMaxData(u64),                     // 0x04
    InitialMaxStreamDataBidiLocal(u64),      // 0x05
    InitialMaxStreamDataBidiRemote(u64),     // 0x06
    InitialMaxStreamDataUni(u64),            // 0x07
    InitialMaxStreamsBidi(u64),              // 0x08
    InitialMaxStreamsUni(u64),               // 0x09
    ActiveConnectionIdLimit(u64),            // 0x0e
    InitialSourceConnectionId(ConnectionId), // 0x0f
    Invalid(u64, Vec<u8>),
    Unknown(u64, Vec<u8>),
}

impl fmt::Debug for TransportParameter {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use TransportParameter::*;
        match self {
            OriginalDstConnectionId(v) => write!(f, "original_destination_connection_id = {}", v),
            MaxIdleTimeout(v) => write!(f, "max_idle_timeout = {}", v),
            MaxUDPPayloadSize(v) => write!(f, "max_udp_payload_size = {}", v),
            InitialMaxData(v) => write!(f, "initial_max_data = {}", v),
            InitialMaxStreamDataBidiLocal(v) => write!(f, "initial_max_stream_data_bidi_local = {}", v),
            InitialMaxStreamDataBidiRemote(v) => write!(f, "initial_max_stream_data_bidi_remote = {}", v),
            InitialMaxStreamDataUni(v) => write!(f, "initial_max_stream_data_uni = {}", v),
            InitialMaxStreamsBidi(v) => write!(f, "initial_max_streams_bidi = {}", v),
            InitialMaxStreamsUni(v) => write!(f, "initial_max_streams_uni = {}", v),
            ActiveConnectionIdLimit(v) => write!(f, "active_connection_id_limit = {}", v),
            InitialSourceConnectionId(v) => write!(f, "initial_source_connection_id = {}", v),
            Invalid(id, v) => write!(f, "invalid({:#x}) = {}", id, BinaryData(v)),
            Unknown(id, v) => write!(f, "unknown({:#x}) = {}", id, BinaryData(v)),
        }
    }
}


impl TransportParameter {
    pub fn decode(id: u64, raw: &[u8]) -> Result<TransportParameter, Box<dyn Error>> {
        use TransportParameter::*;
        match id {
            0x01 => Ok(MaxIdleTimeout(quic_varint_from_bytes(raw)?)),
            0x03 => Ok(MaxUDPPayloadSize(quic_varint_from_bytes(raw)?)),
            0x04 => Ok(InitialMaxData(quic_varint_from_bytes(raw)?)),
            0x05 => Ok(InitialMaxStreamDataBidiLocal(quic_varint_from_bytes(raw)?)),
            0x06 => Ok(InitialMaxStreamDataBidiRemote(quic_varint_from_bytes(raw)?)),
            0x07 => Ok(InitialMaxStreamDataUni(quic_varint_from_bytes(raw)?)),
            0x08 => Ok(InitialMaxStreamsBidi(quic_varint_from_bytes(raw)?)),
            0x09 => Ok(InitialMaxStreamsUni(quic_varint_from_bytes(raw)?)),
            0x0e => Ok(ActiveConnectionIdLimit(quic_varint_from_bytes(raw)?)),
            0x0f => Ok(InitialSourceConnectionId(ConnectionId::from_raw(raw)?)),
            _ => Ok(Unknown(id, Vec::from(raw))),
        }
    }

    pub fn encode(&self, out: &mut BinaryWriter) {
        use TransportParameter::*;
        match self {
            OriginalDstConnectionId(v) => Self::encode_raw(out, 0x00, &v.0),
            MaxIdleTimeout(v) => Self::encode_varint(out, 0x01, *v),
            MaxUDPPayloadSize(v) => Self::encode_varint(out, 0x03, *v),
            InitialMaxData(v) => Self::encode_varint(out, 0x04, *v),
            InitialMaxStreamDataBidiLocal(v) => Self::encode_varint(out, 0x05, *v),
            InitialMaxStreamDataBidiRemote(v) => Self::encode_varint(out, 0x06, *v),
            InitialMaxStreamDataUni(v) => Self::encode_varint(out, 0x07, *v),
            InitialMaxStreamsBidi(v) => Self::encode_varint(out, 0x08, *v),
            InitialMaxStreamsUni(v) => Self::encode_varint(out, 0x09, *v),
            ActiveConnectionIdLimit(v) => Self::encode_varint(out, 0x0e, *v),
            InitialSourceConnectionId(v) => Self::encode_raw(out, 0x0f, &v.0),
            Invalid(id, v) => Self::encode_raw(out, *id, v),
            Unknown(id, v) => Self::encode_raw(out, *id, v),
        }
    }

    fn encode_varint(out: &mut BinaryWriter, id: u64, value: u64) {
        // out.write_quic_varint(id);
        // out.write_quic_varint(value);
        let mut inner = BinaryWriter::new();
        inner.write_quic_varint(value);
        Self::encode_raw(out, id, inner.as_ref())
    }

    fn encode_raw(out: &mut BinaryWriter, id: u64, value: &[u8]) {
        out.write_quic_varint(id);
        out.write_quic_varint(value.len() as u64);
        out.write_raw(value);
    }

    pub fn decode_list(data: &[u8]) -> Result<Vec<TransportParameter>, BinaryError> {
        let mut decoded_params: Vec<TransportParameter> = Vec::new();
        let mut reader = BinaryReader::new(data);

        while reader.remaining() > 0 {
            let id = reader.read_quic_varint()?;
            let length = reader.read_quic_varint()? as usize;
            let value = reader.read_fixed(length)?.to_vec();
            match TransportParameter::decode(id, &value) {
                Ok(param) => decoded_params.push(param),
                Err(_) => decoded_params.push(TransportParameter::Invalid(id, value)),
            }
        }
        Ok(decoded_params)
    }

    pub fn encode_list(params: &[TransportParameter]) -> Vec<u8> {
        let mut writer = BinaryWriter::new();
        for param in params {
            param.encode(&mut writer);
        }
        Vec::from(writer)
    }
}
