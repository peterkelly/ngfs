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
use torrent::util::{escape_string, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::tls::types::handshake::*;
use torrent::tls::types::extension::*;
use torrent::tls::types::record::*;
use torrent::util::from_hex;
use crypto::digest::Digest;
use crypto::sha2::Sha384;
// use crypto::hkdf::{hkdf_extract, hkdf_expand};
use crypto::aes_gcm::AesGcm;
use ring::agreement::{PublicKey, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use ring::hkdf::{Prk, Okm, Salt};
use ring::hkdf;

fn make_client_hello(my_public_key_bytes: &[u8]) -> ClientHello {
    let random = from_hex("1a87a2e2f77536fcfa071500af3c7dffa5830e6c61214e2dee7623c2b925aed8").unwrap();
    let session_id = from_hex("7d954b019486e0dffaa7769a4b9d27d796eaee44b710f18d630f3292b6dc7560").unwrap();
    println!("random.len() = {}", random.len());
    println!("session_id.len() = {}", session_id.len());
    assert!(random.len() == 32);
    assert!(session_id.len() == 32);

    let mut random_fixed: [u8; 32] = Default::default();
    random_fixed.copy_from_slice(&random);

    let mut cipher_suites = Vec::<CipherSuite>::new();
    cipher_suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
    cipher_suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    cipher_suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
    cipher_suites.push(CipherSuite::Unknown(0x00ff));

    let mut extensions = vec![
        Extension::ServerName(vec![ServerName::HostName(String::from("localhost"))]),
        Extension::ECPointFormats(vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedPrime,
            ECPointFormat::ANSIX962CompressedChar2]),
        Extension::SupportedGroups(vec![
            NamedCurve::X25519,
            NamedCurve::Secp256r1,
            NamedCurve::X448,
            NamedCurve::Secp521r1,
            NamedCurve::Secp384r1]),
        Extension::NextProtocolNegotiation(vec![]),
        Extension::ApplicationLayerProtocolNegotiation(vec![
            ProtocolName { data: Vec::from("h2".as_bytes()) },
            ProtocolName { data: Vec::from("http/1.1".as_bytes()) },
            ]),
        Extension::EncryptThenMac,
        Extension::ExtendedMasterSecret,
        Extension::PostHandshakeAuth,
        Extension::SignatureAlgorithms(vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::Ed25519,
            SignatureScheme::Ed448,
            SignatureScheme::RsaPssPssSha256,
            SignatureScheme::RsaPssPssSha384,
            SignatureScheme::RsaPssPssSha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512]),
        Extension::SupportedVersions(vec![2, 3, 4]),
        Extension::PskKeyExchangeModes(vec![PskKeyExchangeMode::PskDheKe]),
        Extension::KeyShareClientHello(vec![
            KeyShareEntry {
                group: NamedGroup::X25519,
                // key_exchange: from_hex("13676e955e3f1e389274ffb25c6adb258a549c56779fd593613a73ea85acc669").unwrap().to_vec()
                key_exchange: Vec::from(my_public_key_bytes),
            }])
    ];


    ClientHello {
        legacy_version: 0x0303,
        random: random_fixed,
        legacy_session_id: session_id,
        cipher_suites: cipher_suites,
        legacy_compression_methods: vec![0],
        extensions: extensions,
    }
}

fn handshake_to_record(handshake: &Handshake) -> Result<TLSPlaintext, Box<dyn Error>> {

    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };
    Ok(output_record)
}

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
    println!("input_plaintext ({} bytes) =\n{:#?}", input_plaintext.len(), Indent(&DebugHexDump(&input_plaintext)));

    let enc_aad = Aad::from(b"hello");
    let mut work: Vec<u8> = Vec::new();
    work.extend_from_slice(&input_plaintext);
    key.seal_in_place_append_tag(enc_nonce, enc_aad, &mut work)?;
    println!("ciphertext ({} bytes) =\n{:#?}", work.len(), Indent(&DebugHexDump(&work)));

    let dec_nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let dec_aad = Aad::from(b"hello");
    key.open_in_place(dec_nonce, dec_aad, &mut work)?;
    work.truncate(work.len() - AES_256_GCM.tag_len());
    println!("output_plaintext ({} bytes) =\n{:#?}", work.len(), Indent(&DebugHexDump(&work)));
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

    use crypto::sha2::Sha384;
    let digest = crypto::sha2::Sha384::new();
    let test_prk: Vec<u8> = Vec::new();
    let test_info: Vec<u8> = Vec::new();
    let mut test_okm: [u8; 32] = [0; 32];
    crypto::hkdf::hkdf_expand(digest, &test_prk, &test_info, &mut test_okm);

    Ok(())
}

fn hkdf_expand_label(secret: &Prk, label_suffix: &[u8], context: &[u8], okm: &mut [u8]) {
    let digest = Sha384::new();
    let output_bytes = digest.output_bits() / 8;
    let length_field = (output_bytes as u16).to_be_bytes();

    let mut label_field: Vec<u8> = Vec::new();
    label_field.extend_from_slice(&b"tls13 "[..]);
    label_field.extend_from_slice(label_suffix);


    // let mut hkdf_label: Vec<u8> = Vec::new();
    // hkdf_label.extend_from_slice(&length_field);
    // hkdf_label.push(label_field.len() as u8);
    // hkdf_label.extend_from_slice(&label_field);
    // hkdf_label.push(context.len() as u8);
    // hkdf_label.extend_from_slice(context);

    // let parts: &[&[u8]] = &[&hkdf_label];

    println!("hkdf_expand_label {}", String::from_utf8_lossy(label_suffix));
    println!("    output_bytes = {}", output_bytes);
    println!("    label_len    = {}", label_field.len());
    println!("    context_len  = {}", context.len());
    // println!("    info = {:?}", BinaryData(&hkdf_label));

    let parts: &[&[u8]] = &[

        &length_field,
        &[label_field.len() as u8],
        // &label_field,
        &b"tls13 "[..],
        label_suffix,
        &[context.len() as u8],
        context,
        ];


    print!("    info =");
    for a in parts.iter() {
        print!(" ");
        for b in a.iter() {
            print!("{:02x}", b);
        }
    }
    println!();

    // crypto::hkdf::hkdf_expand(digest, secret, &hkdf_label, okm);
    let okm1: Okm<'_, hkdf::Algorithm> = secret.expand(parts, ring::hkdf::HKDF_SHA384).unwrap();
    // let x: ring::hkdf::Okm<'_, ring::hkdf::Algorithm> = okm1;
    // let x: () = okm1;
    okm1.fill(okm).unwrap();
}

fn hkdf_expand_label_prk(secret: &Prk, label_suffix: &[u8], context: &[u8]) -> Prk {
    let digest = Sha384::new();
    let output_bytes = digest.output_bits() / 8;
    let length_field = (output_bytes as u16).to_be_bytes();

    let mut label_field: Vec<u8> = Vec::new();
    label_field.extend_from_slice(&b"tls13 "[..]);
    label_field.extend_from_slice(label_suffix);


    // let mut hkdf_label: Vec<u8> = Vec::new();
    // hkdf_label.extend_from_slice(&length_field);
    // hkdf_label.push(label_field.len() as u8);
    // hkdf_label.extend_from_slice(&label_field);
    // hkdf_label.push(context.len() as u8);
    // hkdf_label.extend_from_slice(context);

    // let parts: &[&[u8]] = &[&hkdf_label];

    println!("hkdf_expand_label {}", String::from_utf8_lossy(label_suffix));
    println!("    output_bytes = {}", output_bytes);
    println!("    label_len    = {}", label_field.len());
    println!("    context_len  = {}", context.len());
    // println!("    info = {:?}", BinaryData(&hkdf_label));

    let parts: &[&[u8]] = &[

        &length_field,
        &[label_field.len() as u8],
        // &label_field,
        &b"tls13 "[..],
        label_suffix,
        &[context.len() as u8],
        context,
        ];


    print!("    info =");
    for a in parts.iter() {
        print!(" ");
        for b in a.iter() {
            print!("{:02x}", b);
        }
    }
    println!();

    // crypto::hkdf::hkdf_expand(digest, secret, &hkdf_label, okm);
    secret.expand(parts, ring::hkdf::HKDF_SHA384).unwrap().into()
}

fn hkdf_expand_label_salt(secret: &Prk, label_suffix: &[u8], context: &[u8]) -> Salt {
    let digest = Sha384::new();
    let output_bytes = digest.output_bits() / 8;
    let length_field = (output_bytes as u16).to_be_bytes();

    let mut label_field: Vec<u8> = Vec::new();
    label_field.extend_from_slice(&b"tls13 "[..]);
    label_field.extend_from_slice(label_suffix);


    // let mut hkdf_label: Vec<u8> = Vec::new();
    // hkdf_label.extend_from_slice(&length_field);
    // hkdf_label.push(label_field.len() as u8);
    // hkdf_label.extend_from_slice(&label_field);
    // hkdf_label.push(context.len() as u8);
    // hkdf_label.extend_from_slice(context);

    // let parts: &[&[u8]] = &[&hkdf_label];

    println!("hkdf_expand_label {}", String::from_utf8_lossy(label_suffix));
    println!("    output_bytes = {}", output_bytes);
    println!("    label_len    = {}", label_field.len());
    println!("    context_len  = {}", context.len());
    // println!("    info = {:?}", BinaryData(&hkdf_label));

    let parts: &[&[u8]] = &[

        &length_field,
        &[label_field.len() as u8],
        // &label_field,
        &b"tls13 "[..],
        label_suffix,
        &[context.len() as u8],
        context,
        ];


    print!("    info =");
    for a in parts.iter() {
        print!(" ");
        for b in a.iter() {
            print!("{:02x}", b);
        }
    }
    println!();

    // crypto::hkdf::hkdf_expand(digest, secret, &hkdf_label, okm);
    secret.expand(parts, ring::hkdf::HKDF_SHA384).unwrap().into()
}

fn transcript_hash(transcript: &[u8]) -> Vec<u8> {
    let mut digest = Sha384::new();
    digest.input(transcript);
    let mut result: Vec<u8> = vec![0; digest.output_bits() / 8];
    digest.result(&mut result);
    result
}

fn derive_secret(secret: &Prk, label: &[u8], messages: &[u8]) -> Vec<u8> {
    let mut result: [u8; 48] = [0; 48];
    let thash = transcript_hash(messages);
    println!("derive_secret begin '{}' {:?}", String::from_utf8_lossy(label), BinaryData(&thash));
    hkdf_expand_label(secret, label, &thash, &mut result);
    println!("derive_secret end '{}'", String::from_utf8_lossy(label));
    Vec::from(result)
}

fn derive_secret_prk(secret: &Prk, label: &[u8], messages: &[u8]) -> Prk {
    let thash = transcript_hash(messages);
    println!("derive_secret_prk begin '{}' {:?}", String::from_utf8_lossy(label), BinaryData(&thash));
    let res = hkdf_expand_label_prk(secret, label, &thash);
    println!("derive_secret_prk end '{}'", String::from_utf8_lossy(label));
    res
}

fn derive_secret_salt(secret: &Prk, label: &[u8], messages: &[u8]) -> Salt {
    let thash = transcript_hash(messages);
    println!("derive_secret_salt begin '{}' {}", String::from_utf8_lossy(label), BinaryData(&thash));
    let res = hkdf_expand_label_salt(secret, label, &thash);
    println!("derive_secret_salt end '{}'", String::from_utf8_lossy(label));
    res
}

#[derive(Debug, Eq, PartialEq)]
enum State {
    ClientHelloSent,
    ServerHelloReceived,
    Unknown1,
}

fn get_client_hello_x25519_key_share(client_hello: &ClientHello) -> Option<Vec<u8>> {
    for extension in client_hello.extensions.iter() {
        if let Extension::KeyShareClientHello(key_shares) = extension {
            for ks in key_shares.iter() {
                if ks.group == NamedGroup::X25519 {
                    return Some(ks.key_exchange.clone());
                }
            }
        }
    }
    return None;
}

fn get_server_hello_x25519_key_share(server_hello: &ServerHello) -> Option<Vec<u8>> {
    for extension in server_hello.extensions.iter() {
        if let Extension::KeyShareServerHello(ks) = extension {
            if ks.group == NamedGroup::X25519 {
                return Some(ks.key_exchange.clone());
            }
        }
    }
    return None;
}

fn get_x25519_shared_secret(my_private_key: EphemeralPrivateKey/*, client_hello: &ClientHello*/, server_hello: &ServerHello) -> Option<Vec<u8>> {
    // let client_share = match get_client_hello_x25519_key_share(client_hello) {
    //     Some(v) => v,
    //     None => return None,
    // };

    let server_share = match get_server_hello_x25519_key_share(server_hello) {
        Some(v) => v,
        None => return None,
    };


    let their_unparsed_public_key = UnparsedPublicKey::new(&X25519, server_share);

    let key_material1 = match ring::agreement::agree_ephemeral(
        my_private_key,
        &their_unparsed_public_key,
        ring::error::Unspecified,
        |key_material| Ok(Vec::from(key_material))) {
        Ok(r) => r,
        Err(e) => {
            println!("**** DH agreement failure: {} ****", e);
            return None;
        }
    };

    return Some(key_material1);
}

fn test_expand(prefix: &str, prk: &Prk) {
    let info: &[&[u8]] = &[b"hello"];
    let okm = prk.expand(info, ring::hkdf::HKDF_SHA384).unwrap();
    let mut data: [u8; 48] = [0; 48];
    okm.fill(&mut data).unwrap();
    print!("test_expand {}: ", prefix);
    for b in data.iter() {
        print!("{:02x}", b);
    }
    println!();
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));
    let mut my_private_key: Option<EphemeralPrivateKey> = Some(my_private_key);

    let client_hello = make_client_hello(my_public_key_bytes);
    let handshake = Handshake::ClientHello(client_hello);
    let client_hello_plaintext_record: TLSPlaintext = handshake_to_record(&handshake)?;
    let client_hello_plaintext_record_bytes: Vec<u8> = client_hello_plaintext_record.to_vec();
    let client_hello_bytes: Vec<u8> = Vec::from(client_hello_plaintext_record.fragment);

    let input_zero: [u8; 48] = [0; 48];
    let input_psk: [u8; 48] = [0; 48];

    // let salt1 = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA384, &input_zero);
    // let prk1 = salt1.extract(&input_psk);

    // let digest = crypto::sha2::Sha384::new();
    // let test_prk: Vec<u8> = Vec::new();
    // let test_info: Vec<u8> = Vec::new();
    // let mut test_okm: [u8; 48] = [0; 48];
    // crypto::hkdf::hkdf_extract(digest, &input_psk, &input_zero, &mut test_okm);

    // let empty_digest = ring::digest::digest(&ring::digest::SHA384, &[]);
    // let empty_digest_bytes: &[u8] = empty_digest.as_ref();
    // println!("empty_digest_bytes = {}", BinaryData(empty_digest_bytes));
    let salt1 = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA384, &input_zero);
    let prk1: Prk = salt1.extract(&input_psk);
    test_expand("prk1", &prk1);

    // let derived1 = derive_secret(&prk1, b"derived", &[]);
    // println!("derived1 = {}", BinaryData(&derived1));
    // let derived1_prk: Prk = Prk::new_less_safe(ring::hkdf::HKDF_SHA384, &derived1);

    // let derived1_prk: Prk = derive_secret_prk(&prk1, b"derived", &[]);
    // test_expand("derived1_prk", &derived1_prk);

    // let derived1_salt: Salt = derive_secret_salt(&prk1, b"derived", &[]);
    // let derived1_prk: Prk = derived1_salt.extract(&input_psk);
    // let derived1_prk: Prk = derived1_salt.extract(&[]);
    // test_expand("derived1_prk", &derived1_prk);

    let serialized_filename = "record-constructed.bin";
    std::fs::write(serialized_filename, &client_hello_plaintext_record_bytes)?;
    println!("Wrote {}", serialized_filename);

    // let mut socket = TcpStream::connect("localhost:443").await?;
    let mut socket = TcpStream::connect("localhost:443").await?;
    socket.write_all(&client_hello_plaintext_record_bytes).await?;

    let mut state = State::ClientHelloSent;
    let mut client_handshake_traffic_secret: Option<Vec<u8>> = None;
    let mut server_handshake_traffic_secret: Option<Vec<u8>> = None;
    // let mut client_sequence_no: u64 = 0;
    let mut server_sequence_no: u64 = 0;

    let mut receiver = Receiver::new();

    let mut cipher_change_bytes: Option<Vec<u8>> = None;

    while let Some((plaintext, plaintext_raw)) = receiver.next(&mut socket).await? {
        // println!("Plaintext: content type {:?}, version 0x{:04x}, fragment length {}, bytes_consumed {}",
        //         plaintext.content_type, plaintext.legacy_record_version, plaintext.fragment.len(), plaintext_raw.len());
        match plaintext.content_type {
            ContentType::Invalid => {
                println!("Unsupported record type: Invalid");
            }
            ContentType::ChangeCipherSpec => {
                cipher_change_bytes = Some(Vec::from(plaintext.fragment));
                println!("now cipher_change_bytes = {:?}", cipher_change_bytes);
                println!("ChangeCipherSpec record: Ignoring");
            }
            ContentType::Alert => {
                println!("Unsupported record type: Alert");
            }
            ContentType::Handshake => {
                println!("Handshake record");
                let mut reader = BinaryReader::new(&plaintext.fragment);
                let count = 0;
                while reader.remaining() > 0 {
                    let old_offset = reader.abs_offset();
                    let server_handshake = reader.read_item::<Handshake>()?;
                    let new_offset = reader.abs_offset();

                    println!("{:#?}", server_handshake);

                    if state == State::ClientHelloSent {
                        match server_handshake {
                            Handshake::ServerHello(server_hello) => {
                                let server_hello_bytes: Vec<u8> = Vec::from(&plaintext.fragment[old_offset..new_offset]);
                                let my_private_key2 = my_private_key.take().unwrap();

                                let secret = match get_x25519_shared_secret(my_private_key2, &server_hello) {
                                    Some(r) => r,
                                    None => {
                                        return Err("Cannot get shared secret".into());
                                    }
                                };
                                println!("Shared secret = {}", BinaryData(&secret));

                                // let derived2_prk: Prk = derive_secret_prk(&derived1_prk, b"derived", &secret);
                                // let derived2_prk: Prk = derive_secret_prk(&prk1, b"derived", &secret);
                                // test_expand("derived2_prk", &derived2_prk);

                                let derived2_salt = derive_secret_salt(&prk1, b"derived", &[]);
                                let derived2_prk: Prk = derived2_salt.extract(&secret);
                                test_expand("derived2_prk", &derived2_prk);


                                println!("Got expected server hello");
                                let mut transcript: Vec<u8> = Vec::new();
                                transcript.extend_from_slice(&client_hello_bytes);
                                if let Some(ccb) = cipher_change_bytes.clone() {
                                    println!("-------------- adding ccb to transcript ---------------");
                                    transcript.extend_from_slice(&ccb);
                                }
                                else {
                                    println!("-------------- NOT adding ccb to transcript ---------------");
                                }
                                transcript.extend_from_slice(&server_hello_bytes);
                                let client_handshake_traffic_secret_b = derive_secret(&derived2_prk, b"c hs traffic", &transcript);
                                let server_handshake_traffic_secret_b = derive_secret(&derived2_prk, b"s hs traffic", &transcript);

                                println!("client hs secret = {}", BinaryData(&client_handshake_traffic_secret_b));
                                println!("server hs secret = {}", BinaryData(&server_handshake_traffic_secret_b));

                                client_handshake_traffic_secret = Some(client_handshake_traffic_secret_b);
                                server_handshake_traffic_secret = Some(server_handshake_traffic_secret_b);


                                state = State::ServerHelloReceived;
                            }
                            _ => {
                                println!("Received unexpected handshake type");
                            }
                        }
                    }
                    else {
                        println!("Received handhake record in state {:?}; don't know what to do", state);
                    }

                }
            }
            ContentType::ApplicationData => {
                let cipher = openssl::symm::Cipher::aes_256_gcm();
                if let Some(secret) = server_handshake_traffic_secret.clone() {
                    let prk = Prk::new_less_safe(ring::hkdf::HKDF_SHA384, &secret);
                    println!("Application data:");
                    println!("{:#?}", Indent(&DebugHexDump(&plaintext_raw)));


                    let sequence_no_bytes: [u8; 8] = server_sequence_no.to_be_bytes();
                    let mut nonce_bytes: [u8; 12] = [0; 12];
                    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);

                    let mut server_write_key: [u8; 12] = [0; 12];
                    let mut server_write_iv: [u8; 12] = [0; 12];


                    // // fn hkdf_expand_label(secret: &[u8], label_suffix: &[u8], context: &[u8], okm: &mut [u8]) {
                    // let key_length = 1; // TODO
                    // let iv_length = 1; // TODO

                    // // 7.3.  Traffic Key Calculation
                    // let mut server_write_key = Vec::new();
                    // for i in 0..key_length {
                    //     server_write_key.push(0);
                    // }

                    // let mut server_write_iv = Vec::new();
                    // for i in 0..iv_length {
                    //     server_write_iv.push(0);
                    // }

                    // hkdf_expand_label(&secret, b"key", b"", &mut server_write_key);
                    // hkdf_expand_label(&secret, b"iv", b"", &mut server_write_iv);
                    // println!("server_write_key = {:?}", DebugHexDump(&server_write_key));
                    // println!("server_write_iv  = {:?}", DebugHexDump(&server_write_iv));

                    let server_write_key_okm = prk.expand(&[b"key", b""], ring::hkdf::HKDF_SHA384);
                    let server_write_iv_okm = prk.expand(&[b"iv", b""], ring::hkdf::HKDF_SHA384);

                    for i in 0..12 {
                        nonce_bytes[i] ^= server_write_iv[i];
                    }

                    println!("plaintext.fragment.len() = {}", plaintext.fragment.len());
                    let (tls_ciphertext, bytes_consumed) = TLSCiphertext::from_raw_data(&plaintext_raw)?;
                    println!("bytes_consumed = {}", bytes_consumed);
                    if bytes_consumed != plaintext_raw.len() {
                        return Err("bytes_consumed != plaintext_raw.len()".into());
                    }

                    let mut additional_data: Vec<u8> = Vec::new();
                    additional_data.extend_from_slice(&plaintext_raw[0..5]); // TODO: verify we have at least 5 bytes

                    use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

                    let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &server_write_key)?);
                    // let nonce_bytes: [u8; 12] = [1; 12];
                    // let enc_nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    // let input_plaintext: &[u8] = b"The quick brown fox jumps over the lazy dog";
                    // let input_plaintext_len = input_plaintext.len();
                    // println!("input_plaintext ({} bytes) =\n{:#?}", input_plaintext.len(), Indent(&DebugHexDump(&input_plaintext)));

                    let aad = Aad::from(additional_data);
                    let mut work: Vec<u8> = Vec::new();
                    work.extend_from_slice(&tls_ciphertext.encrypted_record);
                    // key.seal_in_place_append_tag(enc_nonce, enc_aad, &mut work)?;
                    // println!("ciphertext ({} bytes) =\n{:#?}", work.len(), Indent(&DebugHexDump(&work)));

                    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
                    // let dec_aad = Aad::from(b"hello");
                    key.open_in_place(nonce, aad, &mut work)?;
                    // work.truncate(work.len() - AES_256_GCM.tag_len());
                    // println!("output_plaintext ({} bytes) =\n{:#?}", work.len(), Indent(&DebugHexDump(&work)));
                    // println!("output == input ? {}", work == input_plaintext);



                    println!("Received ApplicationData");
                }
                else {
                    println!("Received ApplicationData but don't have secret");
                }
            }
            ContentType::Unknown(code) => {
                println!("Unsupported record type: {}", code);
            }

        }
    }
    Ok(())
}

fn process_record<'a>(record: &'a TLSPlaintext, record_raw: &'a [u8]) -> Result<(), Box<dyn Error>> {
    let received_filename = "record-received.bin";
    std::fs::write(received_filename, record_raw)?;
    println!("Wrote {}", received_filename);

    let mut reader = BinaryReader::new(&record.fragment);
    let handshake = reader.read_item::<Handshake>()?;

    println!("{:#?}", handshake);

    // println!("--------------------------");
    let mut writer = BinaryWriter::new();
    writer.write_item(&handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };

    let serialized_filename = "record-serialized.bin";
    std::fs::write(serialized_filename, &output_record.to_vec())?;
    println!("Wrote {}", serialized_filename);

    Ok(())
}

pub enum ReceiverError {
    ConnectionClosedByPeer,
    InvalidRecordLength,
    SocketRecv(String),
}

impl fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiverError::ConnectionClosedByPeer => write!(f, "Connection closed by peer"),
            ReceiverError::InvalidRecordLength => write!(f, "Invalid record length"),
            ReceiverError::SocketRecv(msg) => write!(f, "{}", msg),
        }
    }
}

impl fmt::Debug for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for ReceiverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

struct Receiver {
    incoming_data: Vec<u8>,
    to_remove: usize,
}

impl Receiver {
    fn new() -> Self {
        Receiver {
            incoming_data: Vec::new(),
            to_remove: 0,
        }
    }
}

impl Receiver {
    async fn next(&mut self, socket: &mut TcpStream) -> Result<Option<(TLSPlaintext, Vec<u8>)>, ReceiverError> {
        const READ_SIZE: usize = 1024;
        loop {
            if self.to_remove > 0 {
                self.incoming_data = self.incoming_data.split_off(self.to_remove);
                self.to_remove = 0;
            }

            match TLSPlaintext::from_raw_data(&self.incoming_data) {
                Err(TLSPlaintextError::InsufficientData) => {
                    // need to read some more data from the socket before we can decode the record
                    let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
                    let r = match socket.read(&mut buf).await {
                        Err(e) => return Err(ReceiverError::SocketRecv(format!("{}", e))),
                        Ok(0) => return Ok(None),
                        Ok(r) => r,
                    };
                    self.incoming_data.extend_from_slice(&buf[0..r]);
                }
                Err(TLSPlaintextError::InvalidLength) => {
                    return Err(ReceiverError::InvalidRecordLength);
                }
                Ok((record, bytes_consumed)) => {
                    self.to_remove = bytes_consumed;
                    let record_raw = Vec::from(&self.incoming_data[0..bytes_consumed]);
                    return Ok(Some((record, record_raw)));
                }
            }
        }
    }
}

async fn process_connection_inner(receiver: &mut Receiver, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    while let Some((record, record_raw)) = receiver.next(socket).await? {
        process_record(&record, &record_raw)?;
    }
    Ok(())
}

async fn process_connection(mut socket: TcpStream, addr: SocketAddr) {
    println!("Received connection from {}", addr);
    let mut receiver = Receiver::new();

    match process_connection_inner(&mut receiver, &mut socket).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error processing connection: {}", e);
        }
    };
}

async fn test_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.01:8080").await?;
    println!("Listening for connections");
    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(process_connection(socket, addr));
        // let x: TcpStream = socket;
        // let y: SocketAddr = addr;
    }
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
        "client" => test_client().await,
        "server" => test_server().await,
        "dh" => test_dh(),
        "aes" => test_aes(),
        "hexdump" => test_hexdump(),
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
