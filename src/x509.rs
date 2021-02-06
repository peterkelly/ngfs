// https://tools.ietf.org/html/rfc5280

#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use super::util::{BinaryData, DebugHexDump, Indent, escape_string};
use super::binary::BinaryReader;
use super::result::GeneralError;
use super::asn1::ObjectIdentifier;

// Certificate  ::=  SEQUENCE  {
//        tbsCertificate       TBSCertificate,
//        signatureAlgorithm   AlgorithmIdentifier,
//        signatureValue       BIT STRING  }

pub struct AlgorithmIdentifier {
}

pub struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

pub enum Version {
    V1,
    V2,
    V3,
}

pub struct CertificateSerialNumber {
    bytes: Vec<u8>,
}

pub struct Name {
    // TODO
}

pub struct UTCTime {
    // TODO
}

pub struct GeneralizedTime {
    // TODO
}

pub enum Time {
    UTCTime(UTCTime),
    GeneralizedTime(GeneralizedTime),
}

pub struct Validity {
    not_before: Time,
    not_after: Time,
}

pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: Vec<u8>,
}

pub struct UniqueIdentifier {
    bytes: Vec<u8>,
}

pub struct Extension {
    id: ObjectIdentifier,
    critical: bool,
    value: Vec<u8>,
}

pub struct TBSCertificate {
    pub version: Version,
    pub serial_number: CertificateSerialNumber,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id: Option<UniqueIdentifier>,
    pub subject_unique_id: Option<UniqueIdentifier>,
    pub extensions: Vec<Extension>,
}
