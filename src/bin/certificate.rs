#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use openssl::x509::{X509Builder, X509, X509NameRef, X509NameEntryRef};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
// use ring::{
//     rand,
//     signature::{self, KeyPair},
// };
use ring::rand;
use ring::signature::{Ed25519KeyPair, KeyPair};
use torrent::result::GeneralError;
use torrent::util::{BinaryData, from_hex};

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
        return Err(GeneralError::new(format!("Public key has invalid encoding")));
    }
    let mut public_key: [u8; 32] = [0; 32];
    public_key.copy_from_slice(public_key_bytes_ref);
    println!("public key = {}", BinaryData(&public_key));
    Ok(())
}

fn test_load_key_pair() -> Result<(), Box<dyn Error>> {
    let test_private_key = match from_hex("f1022fd88c113ded2aaacfd9b6e7f23f99139909b38a6f948b3b5c628a21e3a5") {
        Some(v) => v,
        None => return Err(GeneralError::new("Invalid hex data")),
    };
    let test_public_key = match from_hex("23f4afccd285e8228f4a191bc787ef454a4d1e8f4d733481f78a16faf78c2fb4") {
        Some(v) => v,
        None => return Err(GeneralError::new("Invalid hex data")),
    };

    // let test_key_pair = match Ed25519KeyPair::from_seed_unchecked(&test_private_key) {
    //     Ok(v) => v,
    //     Err(e) => return Err(GeneralError::new(format!("from_seed_unchecked() failed: {}", e))),
    // };

    let test_key_pair = Ed25519KeyPair::from_seed_and_public_key(&test_private_key, &test_public_key)?;

    println!("Computed public key = {}", BinaryData(test_key_pair.public_key().as_ref()));
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    // let der_filename = std::env::args().nth(1).ok_or_else(|| "No filename specified")?;
    // let der_data = std::fs::read(der_filename)?;
    // let certificate = X509::from_der(&der_data)?;

    // // println!("subject_name = {:?}", certificate.subject_name());
    // // println!("Got certificate");

    // println!("subject_name");
    // for entry in certificate.subject_name().entries() {
    //     println!("    {}", name_entry_ref_to_string(entry)?);
    // }

    // if let Some(subject_alt_names) = certificate.subject_alt_names() {
    //     println!("    alt_name");
    //     for alt_name in subject_alt_names.iter() {
    //         println!("        email {:?}", alt_name.email());
    //         println!("        dnsname {:?}", alt_name.dnsname());
    //         println!("        uri {:?}", alt_name.uri());
    //         println!("        ipaddress {:?}", alt_name.ipaddress());
    //     }
    // }


    // println!("issuer_name");
    // for entry in certificate.issuer_name().entries() {
    //     println!("    {}", name_entry_ref_to_string(entry)?);
    // }



    test_generate_key_pair()?;
    test_load_key_pair()?;

    // let mut builder = X509Builder::new()?;
    // builder.set_not_before(&Asn1Time::days_from_now(0)?.as_ref())?;
    // builder.set_not_after(&Asn1Time::days_from_now(365)?.as_ref())?;
    // let certificate: X509 = builder.build();

    // let der_data = certificate.to_der()?;
    // let pem_data = certificate.to_pem()?;
    // std::fs::write("cert.der", der_data)?;
    // std::fs::write("cert.pem", pem_data)?;
    // println!("Done");
    Ok(())
}
