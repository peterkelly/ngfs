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
use super::asn1::value::{ObjectIdentifier, BitString, Integer, Value, Item};
use super::asn1::printer::ObjectRegistry;
use super::asn1;

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
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<Item>,
}

impl AlgorithmIdentifier {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let mut it = item.as_sequence_iter()?;

        let mut elem = it.next().ok_or("Missing algorithm")?;
        let algorithm = elem.as_object_identifier()?.clone();

        let parameters = match it.next() {
            Some(elem) => Some(elem.clone()),
            None => None,
        };

        match it.next() {
            Some(_) => return Err(GeneralError::new("Unexpected value")),
            None => {},
        };

        Ok(AlgorithmIdentifier {
            algorithm,
            parameters,
        })
    }
}

impl AlgorithmIdentifier {
    pub fn to_string(&self, reg: &ObjectRegistry) -> String {
        match &self.parameters {
            Some(parameters) => {
                format!("{} {}", reg.get_long_name(&self.algorithm), parameters.type_str())
            }
            None => {
                format!("{} None", reg.get_long_name(&self.algorithm))
            }
        }
    }
}

pub struct Certificate {
    pub tbs_certificate: TBSCertificate,
    pub signature_algorithm: AlgorithmIdentifier,
    pub signature_value: Vec<u8>,
}

impl Certificate {
    pub fn from_bytes(data: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut certificate_reader = BinaryReader::new(&data);
        let item = asn1::reader::read_item(&mut certificate_reader)?;
        Certificate::from_asn1(&item)
    }

    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let elements = item.as_exact_sequence(3)?;

        let tbs_certificate = TBSCertificate::from_asn1(&elements[0])?;
        let signature_algorithm = AlgorithmIdentifier::from_asn1(&elements[1])?;
        let signature_value: Vec<u8> = match &elements[2].value {
            Value::BitString(bit_string) => {
                bit_string.bytes.clone()
            }
            _ => {
                return Err(GeneralError::new("Certificate: Expected elements[2] to be a bit string"));
            }
        };

        Ok(Certificate {
            tbs_certificate,
            signature_algorithm,
            signature_value,
        })
    }
}

#[derive(Debug)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let int_value = item.as_integer()?;
        if int_value.0.len() != 1 {
            return Err(GeneralError::new("Invalid version"));
        }
        match int_value.0[0] {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(GeneralError::new("Invalid version")),
        }
    }
}

pub struct RelativeDistinguishedName {
    pub id: ObjectIdentifier,
    pub value: Item,
}

impl RelativeDistinguishedName {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let set_elements = item.as_exact_set(1)?;
        let elements = set_elements[0].as_exact_sequence(2)?;
        Ok(RelativeDistinguishedName {
            id: elements[0].as_object_identifier()?.clone(),
            value: elements[1].clone(),
        })
    }
}

pub struct Name {
    pub parts: Vec<RelativeDistinguishedName>,
}

impl Name {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let elements = item.as_sequence()?;
        let mut parts: Vec<RelativeDistinguishedName> = Vec::new();
        for elem in elements.iter() {
            parts.push(RelativeDistinguishedName::from_asn1(elem)?);
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
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        match &item.value {
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
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let elements = item.as_exact_sequence(2)?;
        let not_before = Time::from_asn1(&elements[0])?;
        let not_after = Time::from_asn1(&elements[1])?;
        Ok(Validity { not_before, not_after })
    }
}

pub struct SubjectPublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let elements = item.as_exact_sequence(2)?;
        let algorithm = AlgorithmIdentifier::from_asn1(&elements[0])?;
        let subject_public_key = elements[1].as_bit_string()?.clone();
        Ok(SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        })
    }

    pub fn print(&self, reg: &ObjectRegistry, indent: &str) {
        println!("{}algorithm = {}", indent, self.algorithm.to_string(reg));
        println!("{}subject_public_key = <{} bytes>", indent, self.subject_public_key.bytes.len());
    }
}

pub struct UniqueIdentifier {
    pub bytes: Vec<u8>,
}

pub struct Extension {
    pub id: ObjectIdentifier,
    pub critical: bool,
    pub data: Vec<u8>,
}

impl Extension {
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let mut it = item.as_sequence_iter()?;
        let mut element = it.next().ok_or("Missing element")?;
        let id = element.as_object_identifier()?.clone();

        element = it.next().ok_or("Missing element")?;
        let mut critical = false;
        if let Value::Boolean(b) = &element.value {
            critical = *b;
            element = it.next().ok_or("Missing element")?;
        }

        let data = element.as_octet_string()?.clone();
        Ok(Extension { id, critical, data })
    }

    pub fn print(&self, reg: &ObjectRegistry, indent: &str) {
        println!("{}id = {}", indent, reg.get_long_name(&self.id));
        println!("{}critical = {}", indent, self.critical);
        println!("{}value = <{} bytes>", indent, self.data.len());
    }
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
    pub fn from_asn1(item: &Item) -> Result<Self, Box<dyn Error>> {
        let mut it = item.as_sequence_iter()?;

        let mut elem = it.next().ok_or("Missing version")?;
        let mut version = Version::V1;
        match &elem.value {
            Value::ContextSpecific(0, children) => {
                if children.len() != 1 {
                    return Err(GeneralError::new("Expected one item for version"));
                }
                else {
                    version = Version::from_asn1(&children[0])?;
                }
                elem = it.next().ok_or("Missing serial_number")?;
            }
            _ => {
            }
        }

        let serial_number = elem.as_integer()?.clone();

        let elem = it.next().ok_or("Missing signature")?;
        let signature = AlgorithmIdentifier::from_asn1(&elem)?;

        let elem = it.next().ok_or("Missing issuer")?;
        let issuer = Name::from_asn1(&elem)?;

        let elem = it.next().ok_or("Missing validity")?;
        let validity = Validity::from_asn1(&elem)?;

        let elem = it.next().ok_or("Missing subject")?;
        let subject = Name::from_asn1(&elem)?;

        let elem = it.next().ok_or("Missing subject_public_key_info")?;
        let subject_public_key_info = SubjectPublicKeyInfo::from_asn1(&elem)?;

        let mut extensions: Vec<Extension> = Vec::new();

        match it.next() {
            Some(elem) => {
                match &elem.value {
                    Value::ContextSpecific(3, ext_elements) => {
                        match ext_elements.get(0) {
                            Some(ext_elements2) => {
                                let ext_elements3 = ext_elements2.as_sequence()?;
                                for ext_elem in ext_elements3 {
                                    extensions.push(Extension::from_asn1(ext_elem)?);
                                }
                            }
                            None => {
                            }
                        }
                    }
                    _ => {
                        return Err(GeneralError::new("Unexpected value for extension"));
                    }
                }
            }
            None => {
            }
        };

        match it.next() {
            Some(_) => return Err(GeneralError::new("Unexpected value")),
            None => {},
        };

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

pub fn print_tbs_certificate(tbs: &TBSCertificate, reg: &ObjectRegistry, indent: &str) {
    let child_indent: &str = &format!("{}    ", indent);
    println!("{}version = {:?}", indent, tbs.version);
    println!("{}serial_number = {}", indent, BinaryData(&tbs.serial_number.0));
    // TODO pub signature: AlgorithmIdentifier,
    println!("{}signature = {}", indent, tbs.signature.to_string(reg));
    println!("{}issuer = {}", indent, name_to_simple_string(reg, &tbs.issuer));
    println!("{}validity =", indent);
    println!("{}    not before = {}", indent, time_to_str(&tbs.validity.not_before));
    println!("{}    not after = {}", indent, time_to_str(&tbs.validity.not_after));
    println!("{}subject = {}", indent, name_to_simple_string(reg, &tbs.subject));
    println!("{}subject_public_key_info =", indent);
    tbs.subject_public_key_info.print(reg, child_indent);
    // TODO pub issuer_unique_id: Option<UniqueIdentifier>,
    // TODO pub subject_unique_id: Option<UniqueIdentifier>,
    for (i, ext) in tbs.extensions.iter().enumerate() {
        println!("{}extensions[{}] =", indent, i);
        ext.print(reg, child_indent);
    }
}

pub fn print_certificate(reg: &ObjectRegistry, certificate: &Certificate) {
    let tbs: &TBSCertificate = &certificate.tbs_certificate;
    println!("Certificate");
    println!("    tbs_certificate");
    let child_indent: &str = &"        ";
    print_tbs_certificate(tbs, reg, child_indent);
    println!("    signature_algorithm = {}", certificate.signature_algorithm.to_string(reg));
    println!("    signature_value = <{} bytes>", certificate.signature_value.len());
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
