#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;
use super::super::super::binary::{BinaryReader, FromBinary};
use super::super::super::result::GeneralError;
use super::super::super::util::{DebugHexDump, BinaryData, escape_string};
use super::extension::*;

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

#[derive(Debug)]
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
    Unknown(u8, Vec<u8>),
}

impl FromBinary for Handshake {
    type Output = Self;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let handshake_type = reader.read_u8()?;
        let length = reader.read_u24()? as usize;
        match handshake_type {
            1 => Ok(Handshake::ClientHello(reader.read_item()?)),
            2 => Ok(Handshake::ServerHello(reader.read_item()?)),
            5 => Ok(Handshake::EndOfEarlyData(reader.read_item()?)),
            8 => Ok(Handshake::EncryptedExtensions(reader.read_item()?)),
            13 => Ok(Handshake::CertificateRequest(reader.read_item()?)),
            11 => Ok(Handshake::Certificate(reader.read_item()?)),
            15 => Ok(Handshake::CertificateVerify(reader.read_item()?)),
            20 => Ok(Handshake::Finished(reader.read_item()?)),
            4 => Ok(Handshake::NewSessionTicket(reader.read_item()?)),
            24 => Ok(Handshake::KeyUpdate(reader.read_item()?)),
            _ => Ok(Handshake::Unknown(handshake_type, Vec::from(reader.read_fixed(length)?))),
        }
    }
}


#[allow(non_camel_case_types)]
pub enum CipherSuite {
    TLS_AES_128_GCM_SHA256, // {0x13,0x01} |
    TLS_AES_256_GCM_SHA384, // {0x13,0x02} |
    TLS_CHACHA20_POLY1305_SHA256, // {0x13,0x03} |
    TLS_AES_128_CCM_SHA256, // {0x13,0x04} |
    TLS_AES_128_CCM_8_SHA256, // {0x13,0x05} |
    Unknown(u16),
}

impl FromBinary for CipherSuite {
    type Output = Self;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        match reader.read_u16()? {
            0x1301 => Ok(CipherSuite::TLS_AES_128_GCM_SHA256),
            0x1302 => Ok(CipherSuite::TLS_AES_256_GCM_SHA384),
            0x1303 => Ok(CipherSuite::TLS_CHACHA20_POLY1305_SHA256),
            0x1304 => Ok(CipherSuite::TLS_AES_128_CCM_SHA256),
            0x1305 => Ok(CipherSuite::TLS_AES_128_CCM_8_SHA256),
            code => Ok(CipherSuite::Unknown(code)),
        }
    }
}

impl fmt::Debug for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CipherSuite::TLS_AES_128_GCM_SHA256 => write!(f, "TLS_AES_128_GCM_SHA256"),
            CipherSuite::TLS_AES_256_GCM_SHA384 => write!(f, "TLS_AES_256_GCM_SHA384"),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => write!(f, "TLS_CHACHA20_POLY1305_SHA256"),
            CipherSuite::TLS_AES_128_CCM_SHA256 => write!(f, "TLS_AES_128_CCM_SHA256"),
            CipherSuite::TLS_AES_128_CCM_8_SHA256 => write!(f, "TLS_AES_128_CCM_8_SHA256"),
            CipherSuite::Unknown(code) => write!(f, "0x{:04x}", code),
        }
    }
}

pub struct ClientHello {
    pub legacy_version: u16,
    pub random: Vec<u8>,
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl FromBinary for ClientHello {
    type Output = ClientHello;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let legacy_version = reader.read_u16()?;
        let random = Vec::from(reader.read_fixed(32)?);

        let legacy_session_id_len = reader.read_u8()? as usize;
        let legacy_session_id = Vec::from(reader.read_fixed(legacy_session_id_len)?);

        let cipher_suites = reader.read_len16_list::<CipherSuite>()?;


        let legacy_compression_methods_len = reader.read_u8()? as usize;
        let mut legacy_compression_methods_reader = reader.read_nested(legacy_compression_methods_len)?;
        let mut legacy_compression_methods = Vec::new();
        for i in 0..legacy_compression_methods_len {
            legacy_compression_methods.push(legacy_compression_methods_reader.read_u8()?);
        }

        let extensions = reader.read_len16_list::<Extension>()?;


        let res = ClientHello {
            legacy_version: legacy_version, // should be 0x0303 or 0x0301
            random: random,
            legacy_session_id: legacy_session_id,
            cipher_suites: cipher_suites,
            legacy_compression_methods: legacy_compression_methods,
            extensions: extensions,
        };

        Ok(res)
    }
}

impl fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ClientHello")
            .field("legacy_version", &self.legacy_version)
            .field("random", &BinaryData(&self.random))
            .field("legacy_session_id", &BinaryData(&self.legacy_session_id))
            .field("cipher_suites", &self.cipher_suites)
            .field("legacy_compression_methods", &self.legacy_compression_methods)
            .field("extensions", &self.extensions)
            .finish()
    }
}

#[derive(Debug)]
pub struct ServerHello {
}

impl FromBinary for ServerHello {
    type Output = ServerHello;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("ServerHello::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct EndOfEarlyData {
}

impl FromBinary for EndOfEarlyData {
    type Output = EndOfEarlyData;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("EndOfEarlyData::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct EncryptedExtensions {
}

impl FromBinary for EncryptedExtensions {
    type Output = EncryptedExtensions;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("EncryptedExtensions::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct CertificateRequest {
}

impl FromBinary for CertificateRequest {
    type Output = CertificateRequest;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("CertificateRequest::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct Certificate {
}

impl FromBinary for Certificate {
    type Output = Certificate;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("Certificate::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct CertificateVerify {
}

impl FromBinary for CertificateVerify {
    type Output = CertificateVerify;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("CertificateVerify::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct Finished {
}

impl FromBinary for Finished {
    type Output = Finished;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("Finished::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct NewSessionTicket {
}

impl FromBinary for NewSessionTicket {
    type Output = NewSessionTicket;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("NewSessionTicket::from_binary(): Not implemented"))
    }
}

#[derive(Debug)]
pub struct KeyUpdate {
}

impl FromBinary for KeyUpdate {
    type Output = KeyUpdate;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        unimplemented!()
    }
}


pub struct TLSPlaintext {
    pub content_type: ContentType,
    pub legacy_record_version: u16,
    pub fragment: Vec<u8>,
}
