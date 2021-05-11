#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::net::SocketAddr;
use std::fmt;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ring::agreement::{PublicKey, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use torrent::result::GeneralError;
use torrent::util::{from_hex, escape_string, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::crypt::HashAlgorithm;
// use torrent::tls::types::alert::*;
use torrent::tls::types::handshake::{
    CipherSuite,
    Handshake,
    ClientHello,
    ServerHello,
    Finished,
};
use torrent::tls::types::extension::{
    ECPointFormat,
    NamedCurve,
    Extension,
    SignatureScheme,
    PskKeyExchangeMode,
    NamedGroup,
    ServerName,
    ProtocolName,
    KeyShareEntry,
};
use torrent::tls::types::record::{
    ContentType,
    Message,
    TLSPlaintext,
    TLSPlaintextError,
    TLSCiphertext,
};

fn test_hexdump() -> Result<(), Box<dyn Error>> {
    let len_str: String = match std::env::args().nth(2) {
        Some(v) => v,
        None => {
            eprintln!("Please specify length");
            std::process::exit(1);
        }
    };

    let len = len_str.parse::<usize>()?;
    let mut data: Vec<u8> = Vec::new();
    for i in 0..len {
        data.push(i as u8);
    }
    println!("{:#?}--", DebugHexDump(&data));
    Ok(())
}

fn test_aes() -> Result<(), Box<dyn Error>> {
    let key_bytes: Vec<u8> = from_hex("573f321bc48531ac0340c91e4eb90ceb8da128255da285def0529f01a547034f").unwrap();
    assert!(key_bytes.len() == 32);

    use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

    // println!("AES_128_GCM       key_len = {}, tag_len = {}, nonce_len = {}",
    //          AES_128_GCM.key_len(), AES_128_GCM.tag_len(), AES_128_GCM.nonce_len());

    // println!("AES_256_GCM       key_len = {}, tag_len = {}, nonce_len = {}",
    //          AES_256_GCM.key_len(), AES_256_GCM.tag_len(), AES_256_GCM.nonce_len());

    // println!("CHACHA20_POLY1305 key_len = {}, tag_len = {}, nonce_len = {}",
    //          CHACHA20_POLY1305.key_len(), CHACHA20_POLY1305.tag_len(), CHACHA20_POLY1305.nonce_len());

    // AES_128_GCM       key_len = 16, tag_len = 16, nonce_len = 12
    // AES_256_GCM       key_len = 32, tag_len = 16, nonce_len = 12
    // CHACHA20_POLY1305 key_len = 32, tag_len = 16, nonce_len = 12

    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key_bytes)?);
    let nonce_bytes: [u8; 12] = [1; 12];
    let enc_nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let input_plaintext: &[u8] = b"The quick brown fox jumps over the lazy dog";
    let input_plaintext_len = input_plaintext.len();
    println!("input_plaintext ({} bytes) =\n{:#?}",
             input_plaintext.len(),
             Indent(&DebugHexDump(&input_plaintext)));

    let enc_aad = Aad::from(b"hello");
    let mut work: Vec<u8> = Vec::new();
    work.extend_from_slice(&input_plaintext);
    key.seal_in_place_append_tag(enc_nonce, enc_aad, &mut work)?;
    println!("ciphertext ({} bytes) =\n{:#?}",
             work.len(),
             Indent(&DebugHexDump(&work)));

    let dec_nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let dec_aad = Aad::from(b"hello");
    key.open_in_place(dec_nonce, dec_aad, &mut work)?;
    work.truncate(work.len() - AES_256_GCM.tag_len());
    println!("output_plaintext ({} bytes) =\n{:#?}",
             work.len(),
             Indent(&DebugHexDump(&work)));
    println!("output == input ? {}", work == input_plaintext);

    Ok(())
}

fn test_dh() -> Result<(), Box<dyn Error>> {
    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));

    let their_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let their_public_key = their_private_key.compute_public_key()?;
    let their_public_key_bytes: &[u8] = their_public_key.as_ref();
    println!("their_public_key_bytes = {}", BinaryData(their_public_key_bytes));

    let my_unparsed_public_key = UnparsedPublicKey::new(&X25519, my_public_key_bytes);
    let their_unparsed_public_key = UnparsedPublicKey::new(&X25519, their_public_key_bytes);

    let key_material1 = ring::agreement::agree_ephemeral(
        my_private_key,
        &their_unparsed_public_key,
        ring::error::Unspecified,
        |key_material| Ok(Vec::from(key_material)))?;

    let key_material2 = ring::agreement::agree_ephemeral(
        their_private_key,
        &my_unparsed_public_key,
        ring::error::Unspecified,
        |key_material| Ok(Vec::from(key_material)))?;

    println!("key_material1 = {}", BinaryData(&key_material1));
    println!("key_material2 = {}", BinaryData(&key_material2));

    let hash_alg = HashAlgorithm::SHA384;
    let test_prk: Vec<u8> = Vec::new();
    let test_info: Vec<u8> = Vec::new();
    let mut test_okm: [u8; 32] = [0; 32];
    hash_alg.hkdf_expand(&test_prk, &test_info, &mut test_okm)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = match std::env::args().nth(1) {
        Some(command) => command,
        None => {
            eprintln!("No command specified");
            std::process::exit(1);
        }
    };

    match command.as_str() {
        // "server" => test_server().await,
        "dh" => test_dh(),
        "aes" => test_aes(),
        "hexdump" => test_hexdump(),
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
