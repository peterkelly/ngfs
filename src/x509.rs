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
use super::asn1::value::{ObjectIdentifier, BitString, Integer, Value};
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
    algorithm: ObjectIdentifier,
    parameters: Value,
}

impl AlgorithmIdentifier {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let items = value.as_exact_sequence(2)?;
        Ok(AlgorithmIdentifier {
            algorithm: items[0].as_object_identifier()?.clone(),
            parameters: items[1].clone(),
        })
    }
}

pub struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

impl Certificate {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        // let items = match value {
        //     Value::Sequence(items) => items,
        //     _ => return Err(GeneralError::new("Certificate: Expected a sequence")),
        // };
        // if items.len() != 3 {
        //     return Err(GeneralError::new("Certificate: Expected a sequence of 3 items"));
        // }
        let items = value.as_exact_sequence(3)?;

        let tbs_certificate = TBSCertificate::from_asn1(&items[0])?;
        let signature_algorithm = AlgorithmIdentifier::from_asn1(&items[1])?;
        let signature_value: Vec<u8> = match &items[2] {
            Value::BitString(bit_string) => {
                bit_string.bytes.clone()
            }
            _ => {
                return Err(GeneralError::new("Certificate: Expected items[2] to be a bit string"));
            }
        };

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        })
    }
}

pub enum Version {
    V1,
    V2,
    V3,
}

pub struct RelativeDistinguishedName {
    pub id: ObjectIdentifier,
    pub value: Value,
}

impl RelativeDistinguishedName {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let set_items = value.as_exact_set(1)?;
        let items = set_items[0].as_exact_sequence(2)?;
        let id = items[0].as_object_identifier()?.clone();
        let value = items[1].clone();
        Ok(RelativeDistinguishedName { id, value })
    }
}

pub struct Name {
    pub parts: Vec<RelativeDistinguishedName>,
}

impl Name {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let items = value.as_sequence()?;
        let mut parts: Vec<RelativeDistinguishedName> = Vec::new();
        for item in items.iter() {
            parts.push(RelativeDistinguishedName::from_asn1(item)?);
        }
        Ok(Name { parts })
    }
}

pub struct UTCTime {
    data: String,
}

pub struct GeneralizedTime {
    data: String,
}

pub enum Time {
    UTCTime(UTCTime),
    GeneralizedTime(GeneralizedTime),
}

impl Time {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        match value {
            Value::UTCTime(s) => Ok(Time::UTCTime(UTCTime { data: s.clone() })),
            Value::GeneralizedTime(s) => Ok(Time::GeneralizedTime(GeneralizedTime { data: s.clone() })),
            _ => Err(GeneralError::new("Expected a UTCTime or GeneralizedTime")),
        }
    }
}

pub struct Validity {
    pub not_before: Time,
    pub not_after: Time,
}

impl Validity {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let items = value.as_exact_sequence(2)?;
        let not_before = Time::from_asn1(&items[0])?;
        let not_after = Time::from_asn1(&items[1])?;
        Ok(Validity { not_before, not_after })
    }
}

pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let items = value.as_exact_sequence(2)?;
        let algorithm = AlgorithmIdentifier::from_asn1(&items[0])?;
        let subject_public_key = items[1].as_bit_string()?.clone();
        Ok(SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        })
    }
}

pub struct UniqueIdentifier {
    pub bytes: Vec<u8>,
}

pub struct Extension {
    pub id: ObjectIdentifier,
    pub critical: bool,
    pub value: Vec<u8>,
}

pub struct TBSCertificate {
    pub version: Version,
    pub serial_number: Integer,
    pub signature: AlgorithmIdentifier,
    pub issuer: Name,
    pub validity: Validity,
    pub subject: Name,
    pub subject_public_key_info: SubjectPublicKeyInfo,
    pub issuer_unique_id: Option<UniqueIdentifier>,
    pub subject_unique_id: Option<UniqueIdentifier>,
    pub extensions: Vec<Extension>,
}

impl TBSCertificate {
    pub fn from_asn1(value: &Value) -> Result<Self, Box<dyn Error>> {
        let items = value.as_exact_sequence(8)?;
        let version: Version = Version::V3; // TODO
        let serial_number = items[1].as_integer()?.clone();
        let signature = AlgorithmIdentifier::from_asn1(&items[2])?;
        let issuer = Name::from_asn1(&items[3])?;
        let validity = Validity::from_asn1(&items[4])?;
        let subject = Name::from_asn1(&items[5])?;
        let subject_public_key_info = SubjectPublicKeyInfo::from_asn1(&items[6])?;
        let extensions: Vec<Extension> = Vec::new(); // TODO

        Ok(TBSCertificate {
            version,
            serial_number,
            signature,
            issuer,
            validity,
            subject,
            subject_public_key_info,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions,
        })
    }
}

pub fn name_to_simple_string(registry: &ObjectRegistry, name: &Name) -> String {
    let mut result = String::new();
    for (i, part) in name.parts.iter().enumerate() {
        let mut name: String = String::from("?");
        let mut value: &str = &"?";

        value = match part.value.as_string() {
            Ok(s) => s,
            Err(e) => value,
        };

        if let Some(short_name) = registry.lookup_short_name(&part.id.0) {
            name = short_name.to_uppercase();
        }
        else if let Some(long_name) = registry.lookup_long_name(&part.id.0) {
            name = String::from(long_name);
        }

        if i > 0 {
            result.push_str(", ");
        }
        result.push_str(&format!("{}={}", name, value));
    }
    result
}

pub fn time_to_str(time: &Time) -> &str {
    match time {
        Time::UTCTime(inner) => &inner.data,
        Time::GeneralizedTime(inner) => &inner.data,
    }
}

pub fn print_certificate(registry: &ObjectRegistry, certificate: &Certificate) {
    println!("Certificate");
    println!("    TBSCertificate");
    println!("        serial_number = {}", BinaryData(&certificate.tbs_certificate.serial_number.0));
    println!("        issuer = {}", name_to_simple_string(registry, &certificate.tbs_certificate.issuer));
    println!("        subject = {}", name_to_simple_string(registry, &certificate.tbs_certificate.subject));
    println!("        not before = {}", time_to_str(&certificate.tbs_certificate.validity.not_before));
    println!("        not after = {}", time_to_str(&certificate.tbs_certificate.validity.not_after));

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
