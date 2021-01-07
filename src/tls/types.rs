#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use super::super::binary::BinaryReader;

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
}

pub enum HandshakeType {
    HelloRequestReserved,
    ClientHello,
    ServerHello,
    HelloVerifyRequestReserved,
    NewSessionTicket,
    EndOfEarlyData,
    HelloRetryRequestReserved,
    EncryptedExtensions,
    Certificate,
    ServerKeyExchangeReserved,
    CertificateRequest,
    ServerHelloDoneReserved,
    CertificateVerify,
    ClientKeyExchangeReserved,
    Finished,
    CertificateUrlReserved,
    CertificateStatusReserved,
    SupplementalDataReserved,
    KeyUpdate,
    MessageHash,
    Unknown(u8),
}

impl HandshakeType {
    pub fn from_raw(byte: u8) -> HandshakeType {
        match byte {
            0 => HandshakeType::HelloRequestReserved,
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            3 => HandshakeType::HelloVerifyRequestReserved,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            6 => HandshakeType::HelloRetryRequestReserved,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            12 => HandshakeType::ServerKeyExchangeReserved,
            13 => HandshakeType::CertificateRequest,
            14 => HandshakeType::ServerHelloDoneReserved,
            15 => HandshakeType::CertificateVerify,
            16 => HandshakeType::ClientKeyExchangeReserved,
            20 => HandshakeType::Finished,
            21 => HandshakeType::CertificateUrlReserved,
            22 => HandshakeType::CertificateStatusReserved,
            23 => HandshakeType::SupplementalDataReserved,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            _ => HandshakeType::Unknown(byte),
        }
    }
}


pub enum Handshake {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData(EndOfEarlyData),
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    NewSessionTicket(NewSessionTicket),
    KeyUpdate(KeyUpdate),
    Unknown(Vec<u8>),
}

impl Handshake {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let handshake_type = reader.read_u8()?;
        unimplemented!()
    }
}

pub struct ClientHello {
}

impl ClientHello {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct ServerHello {
}

impl ServerHello {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct EndOfEarlyData {
}

impl EndOfEarlyData {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct EncryptedExtensions {
}

impl EncryptedExtensions {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct CertificateRequest {
}

impl CertificateRequest {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct Certificate {
}

impl Certificate {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct CertificateVerify {
}

impl CertificateVerify {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct Finished {
}

impl Finished {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct NewSessionTicket {
}

impl NewSessionTicket {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}

pub struct KeyUpdate {
}

impl KeyUpdate {
    pub fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}


pub struct TLSPlaintext {
    pub content_type: ContentType,
    pub legacy_record_version: u16,
    pub fragment: Vec<u8>,
}
