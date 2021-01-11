#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;

// The record layer fragments information blocks into TLSPlaintext records carrying data in chunks of 2^14
const TLS_RECORD_SIZE: usize = 16384;

#[derive(Debug, Eq, PartialEq)]
pub enum ContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl ContentType {
    pub fn from_raw(byte: u8) -> ContentType {
        match byte {
            0 => ContentType::Invalid,
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            _ => ContentType::Unknown(byte),
        }
    }

    pub fn to_raw(&self) -> u8 {
        match self {
            ContentType::Invalid => 0,
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
            ContentType::Unknown(byte) => *byte,
        }
    }
}

pub enum TLSPlaintextError {
    InsufficientData,
    InvalidLength,
}

impl fmt::Display for TLSPlaintextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TLSPlaintextError::InsufficientData => write!(f, "InsufficientData"),
            TLSPlaintextError::InvalidLength => write!(f, "InvalidLength"),
        }
    }
}

impl fmt::Debug for TLSPlaintextError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for TLSPlaintextError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub struct TLSPlaintext {
    pub content_type: ContentType,
    pub legacy_record_version: u16,
    pub fragment: Vec<u8>,
}

impl TLSPlaintext {
    pub fn from_raw_data(data: &[u8]) -> Result<(TLSPlaintext, usize), TLSPlaintextError> {
        if data.len() < 5 {
            return Err(TLSPlaintextError::InsufficientData);
        }

        let content_type = ContentType::from_raw(data[0]);

        let mut legacy_record_version_bytes: [u8; 2] = Default::default();
        legacy_record_version_bytes.copy_from_slice(&data[1..3]);
        let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);


        let mut length_bytes: [u8; 2] = Default::default();
        length_bytes.copy_from_slice(&data[3..5]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length > TLS_RECORD_SIZE {
            return Err(TLSPlaintextError::InvalidLength);
        }

        if 5 + length > data.len() {
            return Err(TLSPlaintextError::InsufficientData);
        }

        let fragment = Vec::from(&data[5..5 + length]);

        let record = TLSPlaintext {
            content_type,
            legacy_record_version,
            fragment,
        };
        let consumed = 5 + length;
        Ok((record, consumed))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.push(self.content_type.to_raw());
        res.extend_from_slice(&self.legacy_record_version.to_be_bytes());
        res.extend_from_slice(&(self.fragment.len() as u16).to_be_bytes());
        res.extend_from_slice(&self.fragment);
        res
    }
}