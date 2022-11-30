// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]
// #![allow(non_upper_case_globals)]

use std::error::Error;
use clap::{Parser, Subcommand, ValueHint};
use torrent::util::util::from_hex;
use torrent::util::binary::BinaryReader;
use torrent::formats::asn1;
use torrent::formats::asn1::value::{Integer, ObjectIdentifier, BitString, Value, Item};
use torrent::formats::asn1::writer::encode_item;
use torrent::crypto::x509::{
    Certificate,
    TBSCertificate,
    Version,
    AlgorithmIdentifier,
    Name,
    Validity,
    SubjectPublicKeyInfo,
    Time,
    UTCTime,
    RelativeDistinguishedName,
    Extension,
    populate_registry,
    print_certificate,
    CRYPTO_SHA_256_WITH_RSA_ENCRYPTION,
    CRYPTO_RSA_ENCRYPTION,
    X509_COUNTRY_NAME,
    X509_ORGANIZATION_NAME,
    X509_COMMON_NAME,
    X509_AUTHORITY_KEY_IDENTIFIER,
    X509_BASIC_CONSTRAINTS,
    X509_KEY_USAGE,
};

#[derive(Parser)]
#[command(name="x509")]
struct Opt {
    #[command(subcommand)]
    subcmd: SubCommand,
}

#[derive(Subcommand)]
enum SubCommand {
    Print(Print),
    Generate(Generate),
}

#[derive(Parser)]
struct Print {
    #[arg(index = 1, value_name = "INFILE", value_hint=ValueHint::FilePath,
        help = "DER-encoded file to read certificate from")]
    infile: String,
}

#[derive(Parser)]
struct Generate {
    #[arg(long, value_name = "FILE")]
    subject_private_key: String,

    #[arg(long, value_name = "FILE")]
    signer_private_key: String,

    #[arg(long, value_name = "FILE")]
    output: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    match opt.subcmd {
        SubCommand::Print(s) => print(&s),
        SubCommand::Generate(s) => generate(&s)
    }
}

use ring::signature::{RsaKeyPair, KeyPair};

fn generate(subcmd: &Generate) -> Result<(), Box<dyn Error>> {
    // pub serial_number: Integer,
    let serial_number = from_hex("00fece0a9eaa3eddc3")
        .ok_or("Invalid hex string: serial_number")?;

    let authority_key_identifier = from_hex(
        &format!("{}{}",
        "3050a143a441303f310b300906035504061302555331173015060355040a0c0e4d7920506572736f6e",
        "616c2043413117301506035504030c0e6d792e706572736f6e616c2e6361820900d7c3d885fa68751d"))
        .ok_or("Invalid hex string: authority_key_identifier")?;
    let basic_constraints = from_hex("3000")
        .ok_or("Invalid hex string: basic_constraints")?;
    let key_usage = from_hex("030204f0")
        .ok_or("Invalid hex string: key_usage")?;


    let subject_key_pair = std::fs::read(&subcmd.subject_private_key)
        .map_err(|e| format!("{}: {}", subcmd.subject_private_key, e))?;
    println!("Got subject_key_pair");
    let subject_key_pair = RsaKeyPair::from_der(&subject_key_pair)?;
    println!("Got subject_key_pair");
    let subject_public_key: Vec<u8> = Vec::from(subject_key_pair.public_key().as_ref());



    let signer_key_pair_bytes = std::fs::read(&subcmd.signer_private_key)
        .map_err(|e| format!("{}: {}", subcmd.signer_private_key, e))?;
    println!("Got signer_key_pair");
    let signer_key_pair = RsaKeyPair::from_der(&signer_key_pair_bytes)?;
    // println!("Got signer_key_pair");
    // let signer_public_key: Vec<u8> = Vec::from(signer_key_pair.public_key().as_ref());



    // println!("generate: subject_key = {:?}", subcmd.subject_key);
    // println!("generate: signing_key = {:?}", subcmd.signing_key);
    // println!("generate: output = {:?}", subcmd.output);
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
            not_after: Time::UTCTime(UTCTime {  data: String::from("220312162539Z") }),
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
            Extension {
                id: ObjectIdentifier(Vec::from(X509_AUTHORITY_KEY_IDENTIFIER)),
                critical: false,
                data: authority_key_identifier,
            },
            Extension {
                id: ObjectIdentifier(Vec::from(X509_BASIC_CONSTRAINTS)),
                critical: false,
                data: basic_constraints,
            },
            Extension {
                id: ObjectIdentifier(Vec::from(X509_KEY_USAGE)),
                critical: false,
                data: key_usage,
            },
        ],
    };

    let output_data = sign_tbs_certificate(&tbs_certificate, &signer_key_pair)?;
    std::fs::write(&subcmd.output, &output_data).map_err(|e| format!("{}: {}", subcmd.output, e))?;
    println!("Wrote {}", subcmd.output);

    Ok(())
}

fn sign_tbs_certificate(
    tbs_certificate: &TBSCertificate,
    signer_key_pair: &RsaKeyPair) -> Result<Vec<u8>, Box<dyn Error>> {


    let mut encoded_tbs_certificate: Vec<u8> = Vec::new();
    encode_item(&tbs_certificate.to_asn1(), &mut encoded_tbs_certificate)?;

    let mut signature = vec![0; signer_key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();

    let encoding = &ring::signature::RSA_PKCS1_SHA256;
    // let encoding = &ring::signature::RSA_PSS_SHA256; // bad
    signer_key_pair.sign(encoding, &rng, &encoded_tbs_certificate, &mut signature)
        .map_err(|e| format!("Signing failed: {}", e))?;


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
    signature_value: &BitString) -> Result<Vec<u8>, Box<dyn Error>> {

    let item = Item::from(Value::Sequence(vec![
        tbs_certificate.to_asn1(),
        signature_algorithm.to_asn1(),
        Item::from(Value::BitString(signature_value.clone())),
    ]));

    let mut output_data: Vec<u8> = Vec::new();
    encode_item(&item, &mut output_data)?;
    Ok(output_data)
}

fn print(subcmd: &Print) -> Result<(), Box<dyn Error>> {
    // Read ASN.1 structure from file
    let data: Vec<u8> = std::fs::read(&subcmd.infile)?;
    let mut reader = BinaryReader::new(&data);
    let item = asn1::reader::read_item(&mut reader)?;

    // Parse ASN.1 structure to create certificate
    let certificate = Certificate::from_asn1(&item)?;

    // Print certificate
    let mut registry = asn1::printer::ObjectRegistry::new();
    populate_registry(&mut registry);
    print_certificate(&registry, &certificate);

    Ok(())
}
