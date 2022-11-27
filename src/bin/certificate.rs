#![allow(unused_variables)]
#![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use openssl::x509::{X509Builder, X509, X509NameEntryRef, X509NameBuilder, X509Extension};
use openssl::asn1::Asn1Time;
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
// use ring::{
//     rand,
//     signature::{self, KeyPair},
// };
use ring::rand;
use ring::signature::{Ed25519KeyPair, KeyPair};
use torrent::error;
use torrent::util::util::{BinaryData, from_hex};

use std::error::Error;

fn name_entry_ref_to_string(entry: &X509NameEntryRef) -> Result<String, Box<dyn Error>> {
    Ok(format!("{} = {}",
        // entry.object().nid().short_name()?,
        entry.object().nid().long_name()?,
        // entry.object().nid().as_raw(),
        entry.data().as_utf8()?))
}

fn test_generate_key_pair() -> Result<(), Box<dyn Error>> {
    let rng = rand::SystemRandom::new();
    let seed: [u8; 32] = rand::generate(&rng)?.expose();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)?;
    println!("Generated key pair");
    println!("seed = {}", BinaryData(&seed));
    let public_key_bytes_ref = key_pair.public_key().as_ref();
    if public_key_bytes_ref.len() != 32 {
        return Err(error!("Public key has invalid encoding"));
    }
    let mut public_key: [u8; 32] = [0; 32];
    public_key.copy_from_slice(public_key_bytes_ref);
    println!("public key = {}", BinaryData(&public_key));
    Ok(())
}

fn test_load_key_pair() -> Result<(), Box<dyn Error>> {
    let test_private_key = match from_hex("f1022fd88c113ded2aaacfd9b6e7f23f99139909b38a6f948b3b5c628a21e3a5") {
        Some(v) => v,
        None => return Err(error!("Invalid hex data")),
    };
    let test_public_key = match from_hex("23f4afccd285e8228f4a191bc787ef454a4d1e8f4d733481f78a16faf78c2fb4") {
        Some(v) => v,
        None => return Err(error!("Invalid hex data")),
    };

    // let test_key_pair = match Ed25519KeyPair::from_seed_unchecked(&test_private_key) {
    //     Ok(v) => v,
    //     Err(e) => return Err(error!("from_seed_unchecked() failed: {}", e)),
    // };

    let test_key_pair = Ed25519KeyPair::from_seed_and_public_key(&test_private_key, &test_public_key)?;

    println!("Computed public key = {}", BinaryData(test_key_pair.public_key().as_ref()));
    Ok(())
}

fn colon_hex_str(data: &[u8]) -> String {
    let mut res = String::new();
    for (i, b) in data.iter().enumerate() {
        res.push_str(&format!("{:02x}", b));
        if i + 1 < data.len() {
            res.push(':');
        }
    }
    res
}

fn show_certificate(filename: &str) -> Result<(), Box<dyn Error>> {
    // let der_filename = std::env::args().nth(1).ok_or_else(|| "No filename specified")?;
    let der_data = std::fs::read(filename)?;
    let certificate = X509::from_der(&der_data)?;

    // println!("subject_name = {:?}", certificate.subject_name());
    // println!("Got certificate");

    println!("subject_name");
    for entry in certificate.subject_name().entries() {
        println!("    {}", name_entry_ref_to_string(entry)?);
    }

    if let Some(subject_alt_names) = certificate.subject_alt_names() {
        println!("    alt_name");
        for alt_name in subject_alt_names.iter() {
            println!("        email {:?}", alt_name.email());
            println!("        dnsname {:?}", alt_name.dnsname());
            println!("        uri {:?}", alt_name.uri());
            println!("        ipaddress {:?}", alt_name.ipaddress());
        }
    }


    println!("issuer_name");
    for entry in certificate.issuer_name().entries() {
        println!("    {}", name_entry_ref_to_string(entry)?);
    }

    println!("version = {}", certificate.version());
    // println!("serial = {}", certificate.serial_number().to_bn()?.to_hex_str()?);
    println!("serial = {}", colon_hex_str(&certificate.serial_number().to_bn()?.to_vec()));
    println!("signature_algorithm = {:?}", certificate.signature_algorithm().object().nid());

    let public_key = certificate.public_key()?;

    match public_key.id() {
        openssl::pkey::Id::RSA => {
            println!("Public key: RSA");
            let rsa = public_key.rsa()?;

            let rsa_der_bytes = rsa.public_key_to_der()?;
            println!("    size = {}", rsa.size());
            // println!("{:?}", DebugHexDump(&rsa_der_bytes));
            println!("{:?}", colon_hex_str(&rsa.n().to_vec()));
            println!("Got rsa key");
        }
        openssl::pkey::Id::HMAC => {
            println!("Public key: HMAC");
        }
        openssl::pkey::Id::DSA => {
            println!("Public key: DSA");
        }
        openssl::pkey::Id::DH => {
            println!("Public key: DH");
        }
        openssl::pkey::Id::EC => {
            println!("Public key: EC");
        }
        _ => {
            println!("Public key: Unknown type");
        }
    }


    // println!("RSA = {:?}", openssl::pkey::Id::RSA);
    // println!("HMAC = {:?}", openssl::pkey::Id::HMAC);
    // println!("DSA = {:?}", openssl::pkey::Id::DSA);
    // println!("DH = {:?}", openssl::pkey::Id::DH);
    // println!("EC = {:?}", openssl::pkey::Id::EC);

    Ok(())
}

fn generate_certificate() -> Result<(), Box<dyn Error>> {
    let rng = rand::SystemRandom::new();
    let seed: [u8; 32] = rand::generate(&rng)?.expose();
    let key_pair = Ed25519KeyPair::from_seed_unchecked(&seed)?;
    println!("Generated key pair");
    println!("seed = {}", BinaryData(&seed));
    let public_key_bytes_ref = key_pair.public_key().as_ref();
    if public_key_bytes_ref.len() != 32 {
        return Err(error!("Public key has invalid encoding"));
    }
    let mut public_key: [u8; 32] = [0; 32];
    public_key.copy_from_slice(public_key_bytes_ref);
    println!("public key = {}", BinaryData(&public_key));


    let rsa = Rsa::generate(2048)?;
    let pkey = PKey::from_rsa(rsa)?;

    let mut issuer_name_builder = X509NameBuilder::new()?;
    issuer_name_builder.append_entry_by_text("C", "UK")?;

    let mut subject_name_builder = X509NameBuilder::new()?;
    subject_name_builder.append_entry_by_text("C", "US")?;
    subject_name_builder.append_entry_by_text("ST", "California")?;
    subject_name_builder.append_entry_by_text("L", "Los Angeles")?;
    subject_name_builder.append_entry_by_text("CN", "mydomain")?;

    let libp2p_oid = "1.3.6.1.4.1.53594.1.1";
    let libp2p_value = "the value";
    let ext = X509Extension::new(None, None, libp2p_oid, libp2p_value)?;


    let mut builder = X509Builder::new()?;
    builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
    builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
    builder.set_pubkey(&pkey)?;
    builder.set_subject_name(&subject_name_builder.build())?;
    builder.set_issuer_name(&issuer_name_builder.build())?;
    builder.append_extension(ext)?;
    builder.sign(&pkey, MessageDigest::sha256())?;
    let certificate: X509 = builder.build();

    let der_data = certificate.to_der()?;
    let pem_data = certificate.to_pem()?;
    std::fs::write("cert.der", der_data)?;
    std::fs::write("cert.pem", pem_data)?;
    println!("Done");

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let command = std::env::args().nth(1).ok_or("No command specified")?;
    match command.as_str() {
        "show" => {
            let filename = std::env::args().nth(2).ok_or("No filename specified")?;
            show_certificate(&filename)?;
        }
        "generate" => {
            generate_certificate()?;
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    };

    Ok(())



    // test_generate_key_pair()?;
    // test_load_key_pair()?;

}
