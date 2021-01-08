#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;
use super::super::binary::{BinaryReader, FromBinary};
use super::super::result::GeneralError;
use super::super::util::{DebugHexDump, BinaryData, escape_string};

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

#[derive(Debug)]
pub struct ProtocolName {
    pub data: Vec<u8>,
}

impl FromBinary for ProtocolName {
    type Output = ProtocolName;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let name_len = reader.read_u8()? as usize;
        let name_data = reader.read_fixed(name_len)?;
        Ok(ProtocolName { data: name_data.to_vec() })
    }
}

#[derive(Debug)]
pub enum Extension {
    ApplicationLayerProtocolNegotiation(Vec<ProtocolName>),
    Unknown(u16, Vec<u8>),
}

impl FromBinary for Extension {
    type Output = Extension;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let extension_type = reader.read_u16()?;
        let extension_len = reader.read_u16()? as usize;
        let mut nested_reader = reader.read_nested(extension_len)?;

        match extension_type {
            16 => {
                let list_len = nested_reader.read_u16()? as usize;
                let mut list_reader = nested_reader.read_nested(list_len)?;
                let mut names: Vec<ProtocolName> = Vec::new();
                while list_reader.remaining() > 0 {
                    // names.push(list_reader.read_item())?
                    let name_len = list_reader.read_u8()? as usize;
                    let name_data = list_reader.read_fixed(name_len)?;
                    names.push(ProtocolName { data: name_data.to_vec() });
                }
                Ok(Extension::ApplicationLayerProtocolNegotiation(names))
            }
            _ => {
                Ok(Extension::Unknown(extension_type, nested_reader.remaining_data().to_vec()))
            }
        }
    }
}

impl fmt::Display for Extension {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Extension::ApplicationLayerProtocolNegotiation(names) => {
                write!(f, "protocols ({})", names.len())?;
                for (i, name) in names.iter().enumerate() {
                    if i == 0 {
                        write!(f, " ")?;
                    }
                    else {
                        write!(f, ", ")?;
                    }
                    let s: String = String::from_utf8_lossy(&name.data).into();
                    write!(f, "{}", escape_string(&s))?;

                }
                Ok(())
            }
            Extension::Unknown(type_, data) => {
                write!(f, "type {} = 0x{:04x} data {}", type_, type_, BinaryData(&data))
            }
        }
    }
}

#[derive(Debug)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: Vec<u8>,
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl FromBinary for ClientHello {
    type Output = ClientHello;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let legacy_version = reader.read_u16()?;
        let random = Vec::from(reader.read_fixed(32)?);

        let legacy_session_id_len = reader.read_u8()? as usize;
        println!("legacy_session_id_len = {:02x}", legacy_session_id_len);
        let legacy_session_id = Vec::from(reader.read_fixed(legacy_session_id_len)?);

        let cipher_suites_len = reader.read_u16()? as usize;
        let mut cipher_suites_reader = reader.read_nested(cipher_suites_len)?;
        let mut cipher_suites: Vec<u16> = Vec::new();
        for i in 0..cipher_suites_len / 2 {
            cipher_suites.push(cipher_suites_reader.read_u16()?);
        }

        let legacy_compression_methods_len = reader.read_u8()? as usize;
        let mut legacy_compression_methods_reader = reader.read_nested(legacy_compression_methods_len)?;
        let mut legacy_compression_methods = Vec::new();
        for i in 0..legacy_compression_methods_len {
            legacy_compression_methods.push(legacy_compression_methods_reader.read_u8()?);
        }

        println!("Before reading extension list; offset = {}", reader.abs_offset());
        let extensions_len = reader.read_u16()? as usize;
        let mut extensions_reader = reader.read_nested(extensions_len)?;
        let mut extensions: Vec<Extension> = Vec::new();

        while extensions_reader.remaining() > 0 {
            println!("Before extension; offset = {}", extensions_reader.abs_offset());
            extensions.push(extensions_reader.read_item()?);
        }


        let res = ClientHello {
            legacy_version: legacy_version, // should be 0x0303 or 0x0301
            random: random,
            legacy_session_id: legacy_session_id,
            cipher_suites: cipher_suites,
            legacy_compression_methods: legacy_compression_methods,
            extensions: extensions,
        };


        println!("ClientHello: {:?}", res);
        res.dump("");

        Ok(res)

        // Err(GeneralError::new("ClientHello::from_binary(): Not implemented"))
    }
}

impl ClientHello {
    pub fn dump(&self, indent: &str) {
        println!("legacy_version = {:04x}", self.legacy_version);
        println!("random = {}", BinaryData(&self.random));
        println!("legacy_session_id = {}", BinaryData(&self.legacy_session_id));
        print!("cipher_suites =");
        for cs in self.cipher_suites.iter() {
            print!(" {:04x}", cs);
        }
        println!();

        print!("legacy_compression_methods =");
        for cm in self.legacy_compression_methods.iter() {
            print!(" {:02x}", cm);
        }
        println!();
        println!("Extensions:");
        for ext in self.extensions.iter() {
            println!("    {}", ext);
        }
    }
}

pub struct ServerHello {
}

impl FromBinary for ServerHello {
    type Output = ServerHello;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("ServerHello::from_binary(): Not implemented"))
    }
}

pub struct EndOfEarlyData {
}

impl FromBinary for EndOfEarlyData {
    type Output = EndOfEarlyData;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("EndOfEarlyData::from_binary(): Not implemented"))
    }
}

pub struct EncryptedExtensions {
}

impl FromBinary for EncryptedExtensions {
    type Output = EncryptedExtensions;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("EncryptedExtensions::from_binary(): Not implemented"))
    }
}

pub struct CertificateRequest {
}

impl FromBinary for CertificateRequest {
    type Output = CertificateRequest;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("CertificateRequest::from_binary(): Not implemented"))
    }
}

pub struct Certificate {
}

impl FromBinary for Certificate {
    type Output = Certificate;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("Certificate::from_binary(): Not implemented"))
    }
}

pub struct CertificateVerify {
}

impl FromBinary for CertificateVerify {
    type Output = CertificateVerify;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("CertificateVerify::from_binary(): Not implemented"))
    }
}

pub struct Finished {
}

impl FromBinary for Finished {
    type Output = Finished;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("Finished::from_binary(): Not implemented"))
    }
}

pub struct NewSessionTicket {
}

impl FromBinary for NewSessionTicket {
    type Output = NewSessionTicket;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Err(GeneralError::new("NewSessionTicket::from_binary(): Not implemented"))
    }
}

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
