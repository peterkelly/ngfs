#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;
use super::super::super::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use super::super::super::result::GeneralError;
use super::super::super::util::{DebugHexDump, BinaryData, escape_string};
use super::extension::*;

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

impl ToBinary for Handshake {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Handshake::ClientHello(client_hello) => {
                writer.write_u8(1);
                let mut temp_writer = BinaryWriter::new();
                client_hello.to_binary(&mut temp_writer)?;
                let temp_data: Vec<u8> = temp_writer.into();
                writer.write_u24(temp_data.len() as u32);
                writer.write_raw(&temp_data);
                Ok(())
            }
            _ => unimplemented!(), // TODO
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

impl ToBinary for CipherSuite {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            CipherSuite::TLS_AES_128_GCM_SHA256 => writer.write_u16(0x1301),
            CipherSuite::TLS_AES_256_GCM_SHA384 => writer.write_u16(0x1302),
            CipherSuite::TLS_CHACHA20_POLY1305_SHA256 => writer.write_u16(0x1303),
            CipherSuite::TLS_AES_128_CCM_SHA256 => writer.write_u16(0x1304),
            CipherSuite::TLS_AES_128_CCM_8_SHA256 => writer.write_u16(0x1305),
            CipherSuite::Unknown(code) => writer.write_u16(*code),
        };
        Ok(())
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
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub cipher_suites: Vec<CipherSuite>,
    pub legacy_compression_methods: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl FromBinary for ClientHello {
    type Output = ClientHello;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let legacy_version = reader.read_u16()?;
        let random_slice = reader.read_fixed(32)?;
        let mut random: [u8; 32] = Default::default();
        random.copy_from_slice(random_slice);
        let legacy_session_id = Vec::from(reader.read_len8_bytes()?);

        let cipher_suites = reader.read_len16_list::<CipherSuite>()?;


        let legacy_compression_methods_len = reader.read_u8()? as usize;
        let mut legacy_compression_methods_reader = reader.read_nested(legacy_compression_methods_len)?;
        let mut legacy_compression_methods = Vec::new();
        for i in 0..legacy_compression_methods_len {
            legacy_compression_methods.push(legacy_compression_methods_reader.read_u8()?);
        }

        // let extensions = reader.read_len16_list::<Extension>()?;
        let mut extensions: Vec<Extension> = Vec::new();
        let extensions_len = reader.read_u16()? as usize;
        let mut extensions_reader = reader.read_nested(extensions_len)?;
        while extensions_reader.remaining() > 0 {
            extensions.push(Extension::from_binary2(&mut extensions_reader, ExtensionContext::ClientHello)?);
        }


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

impl ToBinary for ClientHello {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        writer.write_u16(self.legacy_version);
        writer.write_raw(&self.random);
        writer.write_len8_bytes(&self.legacy_session_id)?;
        writer.write_len16_list(&self.cipher_suites)?;
        writer.write_len8_bytes(&self.legacy_compression_methods)?;
        writer.write_len16_list(&self.extensions)?;
        Ok(())
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

// #[derive(Debug)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub legacy_compression_method: u8,
    pub extensions: Vec<Extension>,
}

impl fmt::Debug for ServerHello {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("ServerHello")
            .field("legacy_version", &self.legacy_version)
            .field("random", &BinaryData(&self.random))
            .field("legacy_session_id_echo", &BinaryData(&self.legacy_session_id_echo))
            .field("cipher_suite", &self.cipher_suite)
            .field("legacy_compression_method", &self.legacy_compression_method)
            .field("extensions", &self.extensions)
            .finish()
    }
}

impl FromBinary for ServerHello {
    type Output = ServerHello;

    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        println!("ServerHello start: offset = 0x{:x}", reader.abs_offset());
        let legacy_version = reader.read_u16()?;
        let random_slice = reader.read_fixed(32)?;
        let mut random: [u8; 32] = Default::default();
        random.copy_from_slice(random_slice);
        let legacy_session_id_echo = Vec::from(reader.read_len8_bytes()?);
        let cipher_suite = reader.read_item::<CipherSuite>()?;

        let legacy_compression_method = reader.read_u8()?;



        let mut extensions: Vec<Extension> = Vec::new();
        let extensions_len = reader.read_u16()? as usize;
        let mut extensions_reader = reader.read_nested(extensions_len)?;
        while extensions_reader.remaining() > 0 {
            extensions.push(Extension::from_binary2(&mut extensions_reader, ExtensionContext::ServerHello)?);
        }

        Ok(ServerHello {
            legacy_version,
            random,
            legacy_session_id_echo,
            cipher_suite,
            legacy_compression_method,
            extensions,
        })
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


