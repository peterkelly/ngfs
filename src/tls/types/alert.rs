#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;
use crate::util::binary::{BinaryReader, BinaryWriter, FromBinary, ToBinary};
use crate::StringError;
use crate::util::util::{DebugHexDump, BinaryData, escape_string};

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum AlertLevel {
    Warning, // (1),
    Fatal, // (2),
    Unknown(u8),
}

impl AlertLevel {
    pub fn from_raw(code: u8) -> AlertLevel {
        match code {
            1 => AlertLevel::Warning,
            2 => AlertLevel::Fatal,
            _ => AlertLevel::Unknown(code),
        }
    }

    pub fn to_raw(&self) -> u8 {
        match self {
            AlertLevel::Warning => 1,
            AlertLevel::Fatal => 2,
            AlertLevel::Unknown(code) => *code,
        }
    }
}

impl FromBinary for AlertLevel {
    type Output = AlertLevel;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Ok(AlertLevel::from_raw(reader.read_u8()?))
    }
}

impl ToBinary for AlertLevel {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        writer.write_u8(self.to_raw());
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum AlertDescription {
    CloseNotify, // (0),
    UnexpectedMessage, // (10),
    BadRecordMac, // (20),
    RecordOverflow, // (22),
    HandshakeFailure, // (40),
    BadCertificate, // (42),
    UnsupportedCertificate, // (43),
    CertificateRevoked, // (44),
    CertificateExpired, // (45),
    CertificateUnknown, // (46),
    IllegalParameter, // (47),
    UnknownCa, // (48),
    AccessDenied, // (49),
    DecodeError, // (50),
    DecryptError, // (51),
    ProtocolVersion, // (70),
    InsufficientSecurity, // (71),
    InternalError, // (80),
    InappropriateFallback, // (86),
    UserCanceled, // (90),
    MissingExtension, // (109),
    UnsupportedExtension, // (110),
    UnrecognizedName, // (112),
    BadCertificateStatusResponse, // (113),
    UnknownPskIdentity, // (115),
    CertificateRequired, // (116),
    NoApplicationProtocol, // (120),
    Unknown(u8),
}

impl AlertDescription {
    pub fn from_raw(code: u8) -> AlertDescription {
        match code {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            44 => AlertDescription::CertificateRevoked,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            48 => AlertDescription::UnknownCa,
            49 => AlertDescription::AccessDenied,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            71 => AlertDescription::InsufficientSecurity,
            80 => AlertDescription::InternalError,
            86 => AlertDescription::InappropriateFallback,
            90 => AlertDescription::UserCanceled,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            113 => AlertDescription::BadCertificateStatusResponse,
            115 => AlertDescription::UnknownPskIdentity,
            116 => AlertDescription::CertificateRequired,
            120 => AlertDescription::NoApplicationProtocol,
            _ => AlertDescription::Unknown(code),
        }
    }

    pub fn to_raw(&self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::RecordOverflow => 22,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateRevoked => 44,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::UnknownCa => 48,
            AlertDescription::AccessDenied => 49,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InsufficientSecurity => 71,
            AlertDescription::InternalError => 80,
            AlertDescription::InappropriateFallback => 86,
            AlertDescription::UserCanceled => 90,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::BadCertificateStatusResponse => 113,
            AlertDescription::UnknownPskIdentity => 115,
            AlertDescription::CertificateRequired => 116,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Unknown(code) => *code,
        }
    }
}

impl FromBinary for AlertDescription {
    type Output = AlertDescription;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Ok(AlertDescription::from_raw(reader.read_u8()?))
    }
}

impl ToBinary for AlertDescription {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        writer.write_u8(self.to_raw());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub level: AlertLevel,
    pub description: AlertDescription,
}

impl Alert {
    pub fn name(&self) -> &'static str {
        match self.description {
            AlertDescription::CloseNotify => "Alert.CloseNotify",
            AlertDescription::UnexpectedMessage => "Alert.UnexpectedMessage",
            AlertDescription::BadRecordMac => "Alert.BadRecordMac",
            AlertDescription::RecordOverflow => "Alert.RecordOverflow",
            AlertDescription::HandshakeFailure => "Alert.HandshakeFailure",
            AlertDescription::BadCertificate => "Alert.BadCertificate",
            AlertDescription::UnsupportedCertificate => "Alert.UnsupportedCertificate",
            AlertDescription::CertificateRevoked => "Alert.CertificateRevoked",
            AlertDescription::CertificateExpired => "Alert.CertificateExpired",
            AlertDescription::CertificateUnknown => "Alert.CertificateUnknown",
            AlertDescription::IllegalParameter => "Alert.IllegalParameter",
            AlertDescription::UnknownCa => "Alert.UnknownCa",
            AlertDescription::AccessDenied => "Alert.AccessDenied",
            AlertDescription::DecodeError => "Alert.DecodeError",
            AlertDescription::DecryptError => "Alert.DecryptError",
            AlertDescription::ProtocolVersion => "Alert.ProtocolVersion",
            AlertDescription::InsufficientSecurity => "Alert.InsufficientSecurity",
            AlertDescription::InternalError => "Alert.InternalError",
            AlertDescription::InappropriateFallback => "Alert.InappropriateFallback",
            AlertDescription::UserCanceled => "Alert.UserCanceled",
            AlertDescription::MissingExtension => "Alert.MissingExtension",
            AlertDescription::UnsupportedExtension => "Alert.UnsupportedExtension",
            AlertDescription::UnrecognizedName => "Alert.UnrecognizedName",
            AlertDescription::BadCertificateStatusResponse => "Alert.BadCertificateStatusResponse",
            AlertDescription::UnknownPskIdentity => "Alert.UnknownPskIdentity",
            AlertDescription::CertificateRequired => "Alert.CertificateRequired",
            AlertDescription::NoApplicationProtocol => "Alert.NoApplicationProtocol",
            AlertDescription::Unknown(_) => "Alert.Unknown",
        }
    }
}

impl FromBinary for Alert {
    type Output = Alert;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let level = reader.read_item::<AlertLevel>()?;
        let description = reader.read_item::<AlertDescription>()?;
        Ok(Alert { level, description })
    }
}

impl ToBinary for Alert {
    fn to_binary(&self, writer: &mut BinaryWriter) -> Result<(), Box<dyn std::error::Error>> {
        writer.write_item(&self.level)?;
        writer.write_item(&self.description)?;
        Ok(())
    }
}
