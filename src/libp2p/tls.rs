use std::fmt;
use ring::signature::{RsaKeyPair, KeyPair};
use crate::util::util::from_hex;
use crate::formats::asn1::value::{Integer, ObjectIdentifier, BitString, Value, Item};
use crate::formats::asn1::writer::encode_item;
use super::peer_id::encode_libp2p_public_key;
use crate::crypto::x509;
use crate::crypto::x509::{
    TBSCertificate,
    Version,
    AlgorithmIdentifier,
    Name,
    Validity,
    SubjectPublicKeyInfo,
    Time,
    UTCTime,
    RelativeDistinguishedName,
    CRYPTO_SHA_256_WITH_RSA_ENCRYPTION,
    CRYPTO_RSA_ENCRYPTION,
    X509_COUNTRY_NAME,
    X509_ORGANIZATION_NAME,
    X509_COMMON_NAME,
    X509_AUTHORITY_KEY_IDENTIFIER,
    X509_BASIC_CONSTRAINTS,
    X509_KEY_USAGE,
};

pub enum GenerateError {
    Plain(&'static str),
    IO(std::io::Error),
}

impl std::error::Error for GenerateError {}

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GenerateError::Plain(e) => write!(f, "{}", e),
            GenerateError::IO(e) => write!(f, "{}", e),
        }
    }
}

impl fmt::Debug for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl From<&'static str> for GenerateError {
    fn from(msg: &'static str) -> Self {
        GenerateError::Plain(msg)
    }
}

impl From<std::io::Error> for GenerateError {
    fn from(e: std::io::Error) -> Self {
        GenerateError::IO(e)
    }
}

pub fn generate_certificate(
    rsa_key_pair: &ring::signature::RsaKeyPair,
    dalek_keypair: &ed25519_dalek::Keypair,
) -> Result<Vec<u8>, GenerateError> {
    let signature: ed25519_dalek::Signature = make_signature(rsa_key_pair, dalek_keypair)?;
    let libp2p_ext_bytes = generate_libp2p_ext(&dalek_keypair.public, &signature)?;
    let certificate: Vec<u8> = generate_certificate_inner(rsa_key_pair, &libp2p_ext_bytes)?;
    Ok(certificate)
}

fn generate_libp2p_ext(
    libp2p_ext_public_key: &ed25519_dalek::PublicKey,
    libp2p_ext_signature: &ed25519_dalek::Signature,
) -> Result<Vec<u8>, GenerateError> {
    let libp2p_ext_item = Item::from(Value::Sequence(vec![
        Item::from(Value::OctetString(encode_libp2p_public_key(libp2p_ext_public_key))),
        Item::from(Value::OctetString(Vec::from(libp2p_ext_signature.to_bytes()))),
    ]));
    let mut libp2p_ext_bytes: Vec<u8> = Vec::new();
    encode_item(&libp2p_ext_item, &mut libp2p_ext_bytes)?;
    Ok(libp2p_ext_bytes)
}

fn make_signature(
    rsa_key_pair: &ring::signature::RsaKeyPair,
    dalek_keypair: &ed25519_dalek::Keypair,
) -> Result<ed25519_dalek::Signature, GenerateError> {
    let p2p_subject_public_key_info = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier(Vec::from(CRYPTO_RSA_ENCRYPTION)),
            parameters: Some(Item::from(Value::Null)),
        },
        subject_public_key: BitString {
            unused_bits: 0,
            bytes: Vec::from(rsa_key_pair.public_key().as_ref()),
        },
    };
    let p2p_subject_public_key_info_item = p2p_subject_public_key_info.to_asn1();
    let mut p2p_subject_public_key_info_bytes: Vec<u8> = Vec::new();
    encode_item(&p2p_subject_public_key_info_item, &mut p2p_subject_public_key_info_bytes)?;


    let mut signature_input: Vec<u8> = Vec::new();
    signature_input.extend_from_slice(b"libp2p-tls-handshake:");
    signature_input.extend_from_slice(&p2p_subject_public_key_info_bytes);
    let signature: ed25519_dalek::Signature = ed25519_dalek::Signer::sign(dalek_keypair, &signature_input);
    Ok(signature)
}

fn generate_certificate_inner(
    certificate_key_pair: &RsaKeyPair,
    libp2p_ext_bytes: &[u8],
) -> Result<Vec<u8>, GenerateError> {

    // TODO: Randomly generate these
    let serial_number = from_hex("00fece0a9eaa3eddc3")
        .ok_or(GenerateError::Plain("Invalid hex string: serial_number"))?;

    let authority_key_identifier = from_hex(
        &format!("{}{}",
        "3050a143a441303f310b300906035504061302555331173015060355040a0c0e4d7920506572736f6e",
        "616c2043413117301506035504030c0e6d792e706572736f6e616c2e6361820900d7c3d885fa68751d"))
        .ok_or(GenerateError::Plain("Invalid hex string: authority_key_identifier"))?;
    let basic_constraints = from_hex("3000")
        .ok_or(GenerateError::Plain("Invalid hex string: basic_constraints"))?;
    let key_usage = from_hex("030204f0")
        .ok_or(GenerateError::Plain("Invalid hex string: key_usage"))?;


    let subject_public_key: Vec<u8> = Vec::from(certificate_key_pair.public_key().as_ref());



    let tbs_certificate = TBSCertificate {
        version: Version::V3,
        serial_number: Integer(serial_number),
        signature: AlgorithmIdentifier {
            algorithm: ObjectIdentifier(Vec::from(CRYPTO_SHA_256_WITH_RSA_ENCRYPTION)),
            parameters: Some(Item::from(Value::Null)),
        },
        issuer: Name { parts: vec![
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COUNTRY_NAME)),
                value: Item::from(Value::PrintableString(String::from("US"))),
            },
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_ORGANIZATION_NAME)),
                value: Item::from(Value::UTF8String(String::from("My Personal CA"))),
            },
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COMMON_NAME)),
                value: Item::from(Value::UTF8String(String::from("my.personal.ca"))),
            } ] },
        validity: Validity {
            not_before: Time::UTCTime(UTCTime { data: String::from("210515162539Z") }),
            not_after: Time::UTCTime(UTCTime {  data: String::from("240312162539Z") }),
        },
        subject: Name { parts: vec![
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COMMON_NAME)),
                value: Item::from(Value::UTF8String(String::from("client"))),
            } ] },
        subject_public_key_info: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier(Vec::from(CRYPTO_RSA_ENCRYPTION)),
                parameters: Some(Item::from(Value::Null)),
            },
            subject_public_key: BitString {
                unused_bits: 0,
                bytes: subject_public_key,
            },
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: vec![
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_AUTHORITY_KEY_IDENTIFIER)),
                critical: false,
                data: authority_key_identifier,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_BASIC_CONSTRAINTS)),
                critical: false,
                data: basic_constraints,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_KEY_USAGE)),
                critical: false,
                data: key_usage,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from([1, 3, 6, 1, 4, 1, 53594, 1, 1])),
                critical: true,
                data: Vec::from(libp2p_ext_bytes),
            }
        ],
    };

    let output_data = sign_tbs_certificate(&tbs_certificate, certificate_key_pair)?;
    Ok(output_data)
}

fn sign_tbs_certificate(
    tbs_certificate: &x509::TBSCertificate,
    signer_key_pair: &ring::signature::RsaKeyPair) -> Result<Vec<u8>, GenerateError> {


    let mut encoded_tbs_certificate: Vec<u8> = Vec::new();
    encode_item(&tbs_certificate.to_asn1(), &mut encoded_tbs_certificate)?;

    let mut signature = vec![0; signer_key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();

    let encoding = &ring::signature::RSA_PKCS1_SHA256;
    signer_key_pair.sign(encoding, &rng, &encoded_tbs_certificate, &mut signature)
        .map_err(|_| GenerateError::Plain("Signing failed"))?;


    let signature_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier(Vec::from(CRYPTO_SHA_256_WITH_RSA_ENCRYPTION)),
        parameters: Some(Item::from(Value::Null)),
    };
    let signature_value = BitString {
        unused_bits: 0,
        bytes: signature,
    };

    wrap_signature(tbs_certificate, &signature_algorithm, &signature_value)
}

fn wrap_signature(
    tbs_certificate: &TBSCertificate,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &BitString,
) -> Result<Vec<u8>, GenerateError> {
    let item = Item::from(Value::Sequence(vec![
        tbs_certificate.to_asn1(),
        signature_algorithm.to_asn1(),
        Item::from(Value::BitString(signature_value.clone())),
    ]));

    let mut output_data: Vec<u8> = Vec::new();
    encode_item(&item, &mut output_data)?;
    Ok(output_data)
}
