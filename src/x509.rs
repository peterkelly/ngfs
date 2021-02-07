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
use super::asn1::value::ObjectIdentifier;
use super::asn1::printer::ObjectRegistry;

pub const X509_COMMON_NAME: [u64; 4] = [2, 5, 4, 3]; // [other identifier: cn]
pub const X509_SURNAME: [u64; 4] = [2, 5, 4, 4]; // [other identifier: sn]
pub const X509_COUNTRY_NAME: [u64; 4] = [2, 5, 4, 6]; // [other identifier: c]
pub const X509_LOCALITY_NAME: [u64; 4] = [2, 5, 4, 7]; // [other identifiers: locality, l]
pub const X509_STATE_OR_PROVINCE_NAME: [u64; 4] = [2, 5, 4, 8]; // [other identifier: st]
pub const X509_STREET_ADDRESS: [u64; 4] = [2, 5, 4, 9]; // [other identifier: street]
pub const X509_ORGANIZATION_NAME: [u64; 4] = [2, 5, 4, 10]; // [other identifier: o]
pub const X509_ORGANIZATIONAL_UNIT_NAME: [u64; 4] = [2, 5, 4, 11]; // [other identifier: ou]

pub const X509_AUTHORITY_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 35];
pub const X509_SUBJECT_KEY_IDENTIFIER: [u64; 4] = [2, 5, 29, 14];
pub const X509_SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];
pub const X509_KEY_USAGE: [u64; 4] = [2, 5, 29, 15];
pub const X509_EXT_KEY_USAGE: [u64; 4] = [2, 5, 29, 37];
pub const X509_CRL_DISTRIBUTION_POINTS: [u64; 4] = [2, 5, 29, 31];
pub const X509_CERTIFICATE_POLICIES: [u64; 4] = [2, 5, 29, 32];
pub const X509_BASIC_CONSTRAINTS: [u64; 4] = [2, 5, 29, 19];
pub const X509_AUTHORITY_INFO_ACCESS: [u64; 9] = [1, 3, 6, 1, 5, 5, 7, 1, 1];

pub const CRYPTO_SHA_256_WITH_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 11];
pub const CRYPTO_SHA_384_WITH_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 12];
pub const CRYPTO_SHA_512_WITH_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 13];
pub const CRYPTO_SHA_224_WITH_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 14];
pub const CRYPTO_RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];

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

pub fn populate_registry(registry: &mut ObjectRegistry) {
    registry.add2(&X509_COMMON_NAME, "commonName", "cn");
    registry.add2(&X509_SURNAME, "surname", "sn");
    registry.add2(&X509_COUNTRY_NAME, "countryName", "c");
    registry.add2(&X509_LOCALITY_NAME, "localityName", "l");
    registry.add2(&X509_STATE_OR_PROVINCE_NAME, "stateOrProvinceName", "st");
    registry.add2(&X509_STREET_ADDRESS, "streetAddress", "street");
    registry.add2(&X509_ORGANIZATION_NAME, "organizationName", "o");
    registry.add2(&X509_ORGANIZATIONAL_UNIT_NAME, "organizationalUnitName", "ou");

    registry.add(&X509_AUTHORITY_KEY_IDENTIFIER, "authorityKeyIdentifier");
    registry.add(&X509_SUBJECT_KEY_IDENTIFIER, "subjectKeyIdentifier");
    registry.add(&X509_SUBJECT_ALT_NAME, "subjectAltName");
    registry.add(&X509_KEY_USAGE, "keyUsage");
    registry.add(&X509_EXT_KEY_USAGE, "extKeyUsage");
    registry.add(&X509_CRL_DISTRIBUTION_POINTS, "cRLDistributionPoints");
    registry.add(&X509_CERTIFICATE_POLICIES, "certificatePolicies");
    registry.add(&X509_BASIC_CONSTRAINTS, "basicConstraints");
    registry.add(&X509_AUTHORITY_INFO_ACCESS, "authorityInfoAccess");
    registry.add(&CRYPTO_SHA_256_WITH_RSA_ENCRYPTION, "sha256WithRSAEncryption");
    registry.add(&CRYPTO_SHA_384_WITH_RSA_ENCRYPTION, "sha384WithRSAEncryption");
    registry.add(&CRYPTO_SHA_512_WITH_RSA_ENCRYPTION, "sha512WithRSAEncryption");
    registry.add(&CRYPTO_SHA_224_WITH_RSA_ENCRYPTION, "sha224WithRSAEncryption");
    registry.add(&CRYPTO_RSA_ENCRYPTION, "rsaEncryption");
}
