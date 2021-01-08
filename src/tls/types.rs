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

impl fmt::Debug for ProtocolName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s: String = String::from_utf8_lossy(&self.data).into();
        write!(f, "{}", escape_string(&s))
    }
}

pub enum SignatureScheme {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPkcs1Sha512,
    EcdsaSecp256r1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
    RsaPssRsaeSha256,
    RsaPssRsaeSha384,
    RsaPssRsaeSha512,
    Ed25519,
    Ed448,
    RsaPssPssSha256,
    RsaPssPssSha384,
    RsaPssPssSha512,
    RsaPkcs1Sha1,
    EcdsaSha1,
    Unknown(u16),
}

impl SignatureScheme {
    pub fn from_raw(code: u16) -> SignatureScheme {
        match code {
            0x0401 => SignatureScheme::RsaPkcs1Sha256,
            0x0501 => SignatureScheme::RsaPkcs1Sha384,
            0x0601 => SignatureScheme::RsaPkcs1Sha512,

            0x0403 => SignatureScheme::EcdsaSecp256r1Sha256,
            0x0503 => SignatureScheme::EcdsaSecp384r1Sha384,
            0x0603 => SignatureScheme::EcdsaSecp521r1Sha512,

            0x0804 => SignatureScheme::RsaPssRsaeSha256,
            0x0805 => SignatureScheme::RsaPssRsaeSha384,
            0x0806 => SignatureScheme::RsaPssRsaeSha512,

            0x0807 => SignatureScheme::Ed25519,
            0x0808 => SignatureScheme::Ed448,

            0x0809 => SignatureScheme::RsaPssPssSha256,
            0x080a => SignatureScheme::RsaPssPssSha384,
            0x080b => SignatureScheme::RsaPssPssSha512,

            0x0201 => SignatureScheme::RsaPkcs1Sha1,
            0x0203 => SignatureScheme::EcdsaSha1,
            _ => SignatureScheme::Unknown(code),
        }
    }
}

impl fmt::Debug for SignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignatureScheme::RsaPkcs1Sha256 => write!(f, "RsaPkcs1Sha256"),
            SignatureScheme::RsaPkcs1Sha384 => write!(f, "RsaPkcs1Sha384"),
            SignatureScheme::RsaPkcs1Sha512 => write!(f, "RsaPkcs1Sha512"),
            SignatureScheme::EcdsaSecp256r1Sha256 => write!(f, "EcdsaSecp256r1Sha256"),
            SignatureScheme::EcdsaSecp384r1Sha384 => write!(f, "EcdsaSecp384r1Sha384"),
            SignatureScheme::EcdsaSecp521r1Sha512 => write!(f, "EcdsaSecp521r1Sha512"),
            SignatureScheme::RsaPssRsaeSha256 => write!(f, "RsaPssRsaeSha256"),
            SignatureScheme::RsaPssRsaeSha384 => write!(f, "RsaPssRsaeSha384"),
            SignatureScheme::RsaPssRsaeSha512 => write!(f, "RsaPssRsaeSha512"),
            SignatureScheme::Ed25519 => write!(f, "Ed25519"),
            SignatureScheme::Ed448 => write!(f, "Ed448"),
            SignatureScheme::RsaPssPssSha256 => write!(f, "RsaPssPssSha256"),
            SignatureScheme::RsaPssPssSha384 => write!(f, "RsaPssPssSha384"),
            SignatureScheme::RsaPssPssSha512 => write!(f, "RsaPssPssSha512"),
            SignatureScheme::RsaPkcs1Sha1 => write!(f, "RsaPkcs1Sha1"),
            SignatureScheme::EcdsaSha1 => write!(f, "EcdsaSha1"),
            SignatureScheme::Unknown(code) => write!(f, "{:04x}", code),
        }
    }
}

impl FromBinary for SignatureScheme {
    type Output = SignatureScheme;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        Ok(SignatureScheme::from_raw(reader.read_u16()?))
    }
}

pub enum ServerName {
    HostName(String),
    Other(u8, Vec<u8>),
}

impl FromBinary for ServerName {
    type Output = ServerName;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let name_type = reader.read_u8()?;
        let name_len = reader.read_u16()? as usize;
        let mut name_reader = reader.read_nested(name_len)?;
        match name_type {
            0 => {
                let data = name_reader.read_fixed(name_len)?;
                let s = String::from_utf8(data.to_vec())?;
                Ok(ServerName::HostName(s))
            }
            _ => {
                let data = name_reader.read_fixed(name_len)?;
                Ok(ServerName::Other(name_type, data.to_vec()))
            }
        }
    }
}

impl fmt::Debug for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ServerName::HostName(name) => write!(f, "{}", escape_string(&name)),
            ServerName::Other(name_type, data) => write!(f, "<other {}>", name_type),
        }
    }
}


pub enum NamedGroup {
    // Unallocated_RESERVED, // (0x0000),

    /* Elliptic Curve Groups (ECDHE) */
    // Obsolete_RESERVED1(u16), // (0x0001..0x0016),
    Secp256r1, // (0x0017),
    Secp384r1, // (0x0018),
    Secp521r1, // (0x0019),
    // Obsolete_RESERVED2(u16), // (0x001A..0x001C),
    X25519, // (0x001D),
    X448, // (0x001E),

    /* Finite Field Groups (DHE) */
    Ffdhe2048, // (0x0100),
    Ffdhe3072, // (0x0101),
    Ffdhe4096, // (0x0102),
    Ffdhe6144, // (0x0103),
    Ffdhe8192, // (0x0104),

    /* Reserved Code Points */
    // Ffdhe_private_use, // (0x01FC..0x01FF),
    // Ecdhe_private_use, // (0xFE00..0xFEFF),
    // Obsolete_RESERVED3, // (0xFF01..0xFF02),
    Unknown(u16),
}

impl FromBinary for NamedGroup {
    type Output = NamedGroup;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let code = reader.read_u16()?;
        match code {
            0x0017 => Ok(NamedGroup::Secp256r1),
            0x0018 => Ok(NamedGroup::Secp384r1),
            0x0019 => Ok(NamedGroup::Secp521r1),
            0x001D => Ok(NamedGroup::X25519),
            0x001E => Ok(NamedGroup::X448),
            0x0100 => Ok(NamedGroup::Ffdhe2048),
            0x0101 => Ok(NamedGroup::Ffdhe3072),
            0x0102 => Ok(NamedGroup::Ffdhe4096),
            0x0103 => Ok(NamedGroup::Ffdhe6144),
            0x0104 => Ok(NamedGroup::Ffdhe8192),
            _ => Ok(NamedGroup::Unknown(code)),
        }
    }
}

impl fmt::Debug for NamedGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            NamedGroup::Secp256r1 => write!(f, "Secp256r1"),
            NamedGroup::Secp384r1 => write!(f, "Secp384r1"),
            NamedGroup::Secp521r1 => write!(f, "Secp521r1"),
            NamedGroup::X25519 => write!(f, "X25519"),
            NamedGroup::X448 => write!(f, "X448"),
            NamedGroup::Ffdhe2048 => write!(f, "Ffdhe2048"),
            NamedGroup::Ffdhe3072 => write!(f, "Ffdhe3072"),
            NamedGroup::Ffdhe4096 => write!(f, "Ffdhe4096"),
            NamedGroup::Ffdhe6144 => write!(f, "Ffdhe6144"),
            NamedGroup::Ffdhe8192 => write!(f, "Ffdhe8192"),
            NamedGroup::Unknown(code) => write!(f, "{}", code),
        }
    }
}

#[derive(Debug)]
pub enum NamedCurve {
    Sect163k1, // (1) - defined in rfc4492, deprecated by rfc8422
    Sect163r1, // (2) - defined in rfc4492, deprecated by rfc8422
    Sect163r2, // (3) - defined in rfc4492, deprecated by rfc8422
    Sect193r1, // (4) - defined in rfc4492, deprecated by rfc8422
    Sect193r2, // (5) - defined in rfc4492, deprecated by rfc8422
    Sect233k1, // (6) - defined in rfc4492, deprecated by rfc8422
    Sect233r1, // (7) - defined in rfc4492, deprecated by rfc8422
    Sect239k1, // (8) - defined in rfc4492, deprecated by rfc8422
    Sect283k1, // (9) - defined in rfc4492, deprecated by rfc8422
    Sect283r1, // (10) - defined in rfc4492, deprecated by rfc8422
    Sect409k1, // (11) - defined in rfc4492, deprecated by rfc8422
    Sect409r1, // (12) - defined in rfc4492, deprecated by rfc8422
    Sect571k1, // (13) - defined in rfc4492, deprecated by rfc8422
    Sect571r1, // (14) - defined in rfc4492, deprecated by rfc8422
    Secp160k1, // (15) - defined in rfc4492, deprecated by rfc8422
    Secp160r1, // (16) - defined in rfc4492, deprecated by rfc8422
    Secp160r2, // (17) - defined in rfc4492, deprecated by rfc8422
    Secp192k1, // (18) - defined in rfc4492, deprecated by rfc8422
    Secp192r1, // (19) - defined in rfc4492, deprecated by rfc8422
    Secp224k1, // (20) - defined in rfc4492, deprecated by rfc8422
    Secp224r1, // (21) - defined in rfc4492, deprecated by rfc8422
    Secp256k1, // (22) - defined in rfc4492, deprecated by rfc8422
    Secp256r1, // (23)
    Secp384r1, // (24)
    Secp521r1, // (25)
    X25519, // (29),
    X448, // (30),
    ArbitraryExplicitPrimeCurves, // (0xFF01) - defined in rfc4492, deprecated by rfc8422
    ArbitraryExplicitChar2Curves, // (0xFF02) - defined in rfc4492, deprecated by rfc8422
    Other(u16),
}

impl FromBinary for NamedCurve {
    type Output = NamedCurve;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let code = reader.read_u16()?;
        match code {
            1 => Ok(NamedCurve::Sect163k1),
            2 => Ok(NamedCurve::Sect163r1),
            3 => Ok(NamedCurve::Sect163r2),
            4 => Ok(NamedCurve::Sect193r1),
            5 => Ok(NamedCurve::Sect193r2),
            6 => Ok(NamedCurve::Sect233k1),
            7 => Ok(NamedCurve::Sect233r1),
            8 => Ok(NamedCurve::Sect239k1),
            9 => Ok(NamedCurve::Sect283k1),
            10 => Ok(NamedCurve::Sect283r1),
            11 => Ok(NamedCurve::Sect409k1),
            12 => Ok(NamedCurve::Sect409r1),
            13 => Ok(NamedCurve::Sect571k1),
            14 => Ok(NamedCurve::Sect571r1),
            15 => Ok(NamedCurve::Secp160k1),
            16 => Ok(NamedCurve::Secp160r1),
            17 => Ok(NamedCurve::Secp160r2),
            18 => Ok(NamedCurve::Secp192k1),
            19 => Ok(NamedCurve::Secp192r1),
            20 => Ok(NamedCurve::Secp224k1),
            21 => Ok(NamedCurve::Secp224r1),
            22 => Ok(NamedCurve::Secp256k1),
            23 => Ok(NamedCurve::Secp256r1),
            24 => Ok(NamedCurve::Secp384r1),
            25 => Ok(NamedCurve::Secp521r1),
            29 => Ok(NamedCurve::X25519),
            30 => Ok(NamedCurve::X448),
            0xFF01 => Ok(NamedCurve::ArbitraryExplicitPrimeCurves),
            0xFF02 => Ok(NamedCurve::ArbitraryExplicitChar2Curves),
            _ => Ok(NamedCurve::Other(code))
        }
    }
}

#[derive(Debug)]
pub enum ECPointFormat {
    Uncompressed, // (0)
    ANSIX962CompressedPrime, // (1), defined in rfc4492 but now deprecated
    ANSIX962CompressedChar2, // (2), defined in rfc4492 but now deprecated
    Other(u8),
}

impl FromBinary for ECPointFormat {
    type Output = ECPointFormat;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let code = reader.read_u8()?;
        match code {
            0 => Ok(ECPointFormat::Uncompressed),
            1 => Ok(ECPointFormat::ANSIX962CompressedPrime),
            2 => Ok(ECPointFormat::ANSIX962CompressedChar2),
            _ => Ok(ECPointFormat::Other(code)),
        }
    }
}

pub enum PskKeyExchangeMode {
    PskKe, // (0),
    PskDheKe, // (1),
    Unknown(u8),
}

impl FromBinary for PskKeyExchangeMode {
    type Output = PskKeyExchangeMode;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let code = reader.read_u8()?;
        match code {
            0 => Ok(PskKeyExchangeMode::PskKe),
            1 => Ok(PskKeyExchangeMode::PskDheKe),
            _ => Ok(PskKeyExchangeMode::Unknown(code)),
        }
    }
}

impl fmt::Debug for PskKeyExchangeMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PskKeyExchangeMode::PskKe => write!(f, "PSK-only key establishment"),
            PskKeyExchangeMode::PskDheKe => write!(f, "PSK with (EC)DHE key establishment"),
            PskKeyExchangeMode::Unknown(code) => write!(f, "{}", code),
        }
    }
}

pub struct KeyShareEntry {
    pub group: NamedGroup,
    pub key_exchange: Vec<u8>,
}

impl FromBinary for KeyShareEntry {
    type Output = KeyShareEntry;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let group = reader.read_item::<NamedGroup>()?;
        let key_exchange_len = reader.read_u16()? as usize;
        let key_exchange = reader.read_fixed(key_exchange_len)?.to_vec();
        Ok(KeyShareEntry { group, key_exchange })
    }
}

impl fmt::Debug for KeyShareEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?} {}", self.group, BinaryData(&self.key_exchange))
    }
}


// https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
#[derive(Debug)]
pub enum Extension {
    ApplicationLayerProtocolNegotiation(Vec<ProtocolName>),
    SignatureAlgorithms(Vec<SignatureScheme>),
    ServerName(Vec<ServerName>),
    EllipticCurves(Vec<NamedCurve>),
    ECPointFormats(Vec<ECPointFormat>),
    Unknown(u16, Vec<u8>),
    EncryptThenMac, // (22) RFC7366
    ExtendedMasterSecret, // (23) RFC7627
    NextProtocolNegotiation(Vec<u8>), // (13172), https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html
    PostHandshakeAuth, // (49) rfc8446
    SupportedVersions(Vec<u8>), // (43) rfc8446
    PskKeyExchangeModes(Vec<PskKeyExchangeMode>), // (45) rfc8446
    KeyShareClientHello(Vec<KeyShareEntry>), // (51), rfc8446
}

impl FromBinary for Extension {
    type Output = Extension;
    fn from_binary(reader: &mut BinaryReader) -> Result<Self, Box<dyn Error>> {
        let extension_type = reader.read_u16()?;
        let extension_len = reader.read_u16()? as usize;
        let mut nested_reader = reader.read_nested(extension_len)?;

        match extension_type {
            0 => {
                let server_name = nested_reader.read_len16_list::<ServerName>()?;
                Ok(Extension::ServerName(server_name))
            }
            10 => {
                let named_curve = nested_reader.read_len16_list::<NamedCurve>()?;
                Ok(Extension::EllipticCurves(named_curve))

                // Ok(Extension::EllipticCurves(Vec::new()))
            }
            11 => {
                let ec_point_formats = nested_reader.read_len8_list::<ECPointFormat>()?;
                Ok(Extension::ECPointFormats(ec_point_formats))
                // Ok(Extension::ECPointFormats(Vec::new()))
            }
            16 => {
                let mut names = nested_reader.read_len16_list::<ProtocolName>()?;
                Ok(Extension::ApplicationLayerProtocolNegotiation(names))
            }
            13 => {
                let schemes = nested_reader.read_len16_list::<SignatureScheme>()?;
                Ok(Extension::SignatureAlgorithms(schemes))
            }
            22 => {
                nested_reader.expect_eof()?;
                Ok(Extension::EncryptThenMac)
            }
            23 => {
                nested_reader.expect_eof()?;
                Ok(Extension::ExtendedMasterSecret)
            }
            49 => {
                nested_reader.expect_eof()?;
                Ok(Extension::PostHandshakeAuth)
            }
            43 => {
                Ok(Extension::SupportedVersions(nested_reader.remaining_data().to_vec()))
            }
            13172 => {
                Ok(Extension::NextProtocolNegotiation(nested_reader.remaining_data().to_vec()))
            }
            45 => {
                Ok(Extension::PskKeyExchangeModes(nested_reader.read_len8_list::<PskKeyExchangeMode>()?))
            }
            51 => {
                let entries = nested_reader.read_len16_list::<KeyShareEntry>()?;
                Ok(Extension::KeyShareClientHello(entries))
            }
            _ => {
                Ok(Extension::Unknown(extension_type, nested_reader.remaining_data().to_vec()))
            }
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

impl CipherSuite {
    pub fn from_raw(code: u16) -> CipherSuite {
        match code {
            0x1301 => CipherSuite::TLS_AES_128_GCM_SHA256,
            0x1302 => CipherSuite::TLS_AES_256_GCM_SHA384,
            0x1303 => CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
            0x1304 => CipherSuite::TLS_AES_128_CCM_SHA256,
            0x1305 => CipherSuite::TLS_AES_128_CCM_8_SHA256,
            _ => CipherSuite::Unknown(code),
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
        println!("legacy_session_id_len = {:02x}", legacy_session_id_len);
        let legacy_session_id = Vec::from(reader.read_fixed(legacy_session_id_len)?);

        let cipher_suites_len = reader.read_u16()? as usize;
        let mut cipher_suites_reader = reader.read_nested(cipher_suites_len)?;
        let mut cipher_suites: Vec<CipherSuite> = Vec::new();
        for i in 0..cipher_suites_len / 2 {
            cipher_suites.push(CipherSuite::from_raw(cipher_suites_reader.read_u16()?));
        }

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


        // println!("ClientHello: {:?}", res);
        // res.print("|");


        println!();
        println!("{:#?}", res);

        Ok(res)

        // Err(GeneralError::new("ClientHello::from_binary(): Not implemented"))
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
