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
use torrent::util::{escape_string, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::tls::types::alert::*;
use torrent::tls::types::handshake::*;
use torrent::tls::types::extension::*;
use torrent::tls::types::record::*;
use torrent::util::from_hex;
use torrent::result::GeneralError;
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

struct Length(pub usize);

impl ring::hkdf::KeyType for Length {
    fn len(&self) -> usize {
        self.0
    }
}

fn hkdf_expand_label(algorithm: ring::hkdf::Algorithm, secret: &[u8], label_suffix: &[u8], context: &[u8], okm: &mut [u8]) {
    let length_field = (okm.len() as u16).to_be_bytes();

    let mut label_field: Vec<u8> = Vec::new();
    label_field.extend_from_slice(&b"tls13 "[..]);
    label_field.extend_from_slice(label_suffix);


    let mut hkdf_label: Vec<u8> = Vec::new();
    hkdf_label.extend_from_slice(&length_field);
    hkdf_label.push(label_field.len() as u8);
    hkdf_label.extend_from_slice(&label_field);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    let parts: &[&[u8]] = &[&hkdf_label];


    // crypto::hkdf::hkdf_expand(digest, secret, &hkdf_label, okm);
    let prk = Prk::new_less_safe(algorithm, secret);
    let okm1: Okm<'_, Length> = prk.expand(parts, Length(okm.len())).unwrap();
    // let x: ring::hkdf::Okm<'_, ring::hkdf::Algorithm> = okm1;
    // let x: () = okm1;
    okm1.fill(okm).unwrap();
}

fn transcript_hash(transcript: &[u8]) -> Vec<u8> {
    let mut digest = Sha384::new();
    digest.input(transcript);
    let mut result: Vec<u8> = vec![0; digest.output_bits() / 8];
    digest.result(&mut result);
    result
}

fn derive_secret_prk_hash(algorithm: ring::hkdf::Algorithm, secret: &[u8], label: &[u8], thash: &[u8]) -> Vec<u8> {
    let len = hkdf::KeyType::len(&algorithm);
    let mut result: Vec<u8> = vec_with_len(len);
    hkdf_expand_label(algorithm, &secret, label, &thash, &mut result);
    result
}

fn derive_secret3(algorithm: ring::hkdf::Algorithm, secret: &[u8], label: &[u8]) -> Vec<u8> {
    derive_secret_prk_hash(algorithm, secret, label, &[])
}



struct ClientHelloSentData {
    prk: Vec<u8>,
    transcript: Vec<u8>,
}

struct ServerHelloReceivedData {
    prk: Vec<u8>,
    transcript: Vec<u8>,
    handshake_secrets: TrafficSecrets,
    server_sequence_no: u64,
}

struct EstablishedData {
    prk: Vec<u8>,
    application_secrets: TrafficSecrets,
    client_sequence_no: u64,
    server_sequence_no: u64,
}

// #[derive(Debug, Eq, PartialEq)]
enum State {
    ClientHelloSent(ClientHelloSentData),
    ServerHelloReceived(ServerHelloReceivedData),
    Established(EstablishedData),
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

struct TrafficSecrets {
    client: Vec<u8>,
    server: Vec<u8>,
}

fn get_zero_prk(algorithm: ring::hkdf::Algorithm) -> Vec<u8> {
    let algorithm_len = hkdf::KeyType::len(&algorithm);
    let input_zero: &[u8] = &vec_with_len(algorithm_len);
    let input_psk: &[u8] = &vec_with_len(algorithm_len);
    let key = ring::hmac::Key::new(algorithm.hmac_algorithm(), &input_zero);
    ring::hmac::sign(&key, input_psk).as_ref().to_vec()
}

fn get_derived_prk(prbytes: &[u8], hkdf_algorithm: ring::hkdf::Algorithm, secret: &[u8]) -> Vec<u8> {
    let salt_bytes: Vec<u8> = derive_secret_prk_hash(hkdf_algorithm, &prbytes, b"derived", &transcript_hash(&[]));
    let key = ring::hmac::Key::new(hkdf_algorithm.hmac_algorithm(), &salt_bytes);
    ring::hmac::sign(&key, secret).as_ref().to_vec()
}

struct Client {
    state: State,
    my_private_key: Option<EphemeralPrivateKey>,
    algorithm: ring::hkdf::Algorithm,
    to_send: Vec<u8>,
}

fn client_received_handshake(client: &mut Client, plaintext: TLSPlaintext, plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
    println!("Handshake record");
    let mut reader = BinaryReader::new(&plaintext.fragment);
    let count = 0;
    while reader.remaining() > 0 {
        let old_offset = reader.abs_offset();
        let server_handshake = reader.read_item::<Handshake>()?;
        let new_offset = reader.abs_offset();

        println!("{:#?}", server_handshake);

        match &mut client.state {
            State::ClientHelloSent(state_data) => {
                match server_handshake {
                    Handshake::ServerHello(server_hello) => {
                        let server_hello_bytes: Vec<u8> = Vec::from(&plaintext.fragment[old_offset..new_offset]);
                        state_data.transcript.extend_from_slice(&server_hello_bytes);
                        let my_private_key2 = client.my_private_key.take().unwrap();

                        let secret: &[u8] = &match get_x25519_shared_secret(my_private_key2, &server_hello) {
                            Some(r) => r,
                            None => return Err("Cannot get shared secret".into()),
                        };
                        println!("Shared secret = {}", BinaryData(&secret));

                        let new_prk = get_derived_prk(&state_data.prk, client.algorithm, secret);

                        println!("Got expected server hello");

                        let algorithm_len = hkdf::KeyType::len(&client.algorithm);
                        let thash = transcript_hash(&state_data.transcript);
                        let hs = TrafficSecrets {
                            client: derive_secret_prk_hash(client.algorithm, &new_prk, b"c hs traffic", &thash),
                            server: derive_secret_prk_hash(client.algorithm, &new_prk, b"s hs traffic", &thash),
                        };

                        println!("KEY CLIENT_HANDSHAKE_TRAFFIC_SECRET: {}", BinaryData(&hs.client));
                        println!("KEY SERVER_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&hs.server));

                        // handshake_traffic_secrets = Some(hs);

                        client.state = State::ServerHelloReceived(ServerHelloReceivedData {
                            prk: new_prk,
                            transcript: state_data.transcript.clone(), // TODO: Avoid clone
                            handshake_secrets: hs,
                            server_sequence_no: 0,
                        });
                    }
                    _ => {
                        println!("Received unexpected handshake type");
                    }
                }
            }
            _ => {
                println!("Received handhake record in invalid state; don't know what to do");
            }
        }
    }
    Ok(())
}

fn decrypt_traffic<'a>(algorithm: ring::hkdf::Algorithm,
                       traffic_secret: &[u8],
                       sequence_no: u64,
                       plaintext_raw: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut write_key: [u8; 32] = [0; 32];
    let mut write_iv: [u8; 12] = [0; 12];

    hkdf_expand_label(algorithm, traffic_secret, b"key", &[], &mut write_key);
    hkdf_expand_label(algorithm, traffic_secret, b"iv", &[], &mut write_iv);

    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= write_iv[i];
    }

    let (tls_ciphertext, bytes_consumed) = TLSCiphertext::from_raw_data(&plaintext_raw)?;
    if bytes_consumed != plaintext_raw.len() {
        return Err("bytes_consumed != plaintext_raw.len()".into());
    }

    let mut additional_data: Vec<u8> = Vec::new();
    additional_data.extend_from_slice(&plaintext_raw[0..5]); // TODO: verify we have at least 5 bytes

    use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

    let unbound_key = match UnboundKey::new(&AES_256_GCM, &write_key[0..32]) {
        Ok(v) => v,
        Err(e) => return Err(GeneralError::new(format!("UnboundKey::new() failed: {}", e))),
    };
    let key = LessSafeKey::new(unbound_key);

    let mut work: Vec<u8> = Vec::new();
    work.extend_from_slice(&tls_ciphertext.encrypted_record);

    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::from(additional_data);
    let open_result: Result<&mut [u8], ring::error::Unspecified> = key.open_in_place(nonce, aad, &mut work);
    Ok(open_result?.to_vec())
}

fn encrypt_traffic<'a>(algorithm: ring::hkdf::Algorithm,
                       traffic_secret: &[u8],
                       sequence_no: u64,
                       input_plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut write_key: [u8; 32] = [0; 32];
    let mut write_iv: [u8; 12] = [0; 12];

    hkdf_expand_label(algorithm, traffic_secret, b"key", &[], &mut write_key);
    hkdf_expand_label(algorithm, traffic_secret, b"iv", &[], &mut write_iv);

    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= write_iv[i];
    }

    // let mut tls_ciphertext_data: Vec<u8> = TLSCiphertext::to_raw_data(input_plaintext);
    let mut tls_ciphertext_data = input_plaintext.to_vec();
    // let (tls_ciphertext, bytes_consumed) = TLSCiphertext::from_raw_data(&plaintext_raw)?;
    // if bytes_consumed != plaintext_raw.len() {
    //     return Err("bytes_consumed != plaintext_raw.len()".into());
    // }

    // let mut additional_data: Vec<u8> = Vec::new();
    // additional_data.extend_from_slice(&tls_ciphertext_data[0..5]); // TODO: verify we have at least 5 bytes

    use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305};

    let unbound_key = match UnboundKey::new(&AES_256_GCM, &write_key[0..32]) {
        Ok(v) => v,
        Err(e) => return Err(GeneralError::new(format!("UnboundKey::new() failed: {}", e))),
    };
    let key = LessSafeKey::new(unbound_key);
    let additional_data = TLSCiphertext::to_additional_data(input_plaintext, key.algorithm().tag_len());
    println!("encrypt_traffic: tag_len = {}", key.algorithm().tag_len());

    // let mut work: Vec<u8> = Vec::new();
    // work.extend_from_slice(&tls_ciphertext.encrypted_record);

    println!("encrypt_traffic: nonce = {:?}", BinaryData(&nonce_bytes));
    println!("encrypt_traffic: aad = {:?}", BinaryData(&additional_data));
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::from(additional_data.clone());

    key.seal_in_place_append_tag(nonce, aad, &mut tls_ciphertext_data)?;
    Ok(tls_ciphertext_data)

    // let mut res: Vec<u8> = Vec::new();
    // res.extend_from_slice(&additional_data);
    // res.extend_from_slice(&tls_ciphertext_data);
    // Ok(res)


    // let open_result: Result<&mut [u8], ring::error::Unspecified> = key.open_in_place(nonce, aad, &mut work);
    // Ok(open_result?.to_vec())
}

fn client_received_application_data(client: &mut Client, plaintext: TLSPlaintext, plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
    match &mut client.state {
        State::ServerHelloReceived(state_data) => {
            // println!("Received ApplicationData (server_sequence_no = {})", state_data.server_sequence_no);
            let current_sequence_no = state_data.server_sequence_no;
            state_data.server_sequence_no += 1;
            println!("ApplicationData for server_sequence_no {}", current_sequence_no);

            let plaintext = match decrypt_traffic(client.algorithm,
                                                  &state_data.handshake_secrets.server,
                                                  current_sequence_no,
                                                  &plaintext_raw) {
                Err(e) => return Err(GeneralError::new(format!("key.open_in_place() failed: {}", e))),
                Ok(plaintext) => plaintext,
            };


            // TEMP: Add test zero padding
            // let mut plaintext: Vec<u8> = plaintext.to_vec();
            // for i in 0..5 {
            //     plaintext.push(0);
            // }

            let mut type_offset: usize = plaintext.len();
            while type_offset > 0 && plaintext[type_offset - 1] == 0 {
                type_offset -= 1;
            }
            if type_offset == 0 {
                return Err(GeneralError::new("Plaintext: Missing type field"));
            }
            let inner_content_type = ContentType::from_raw(plaintext[type_offset - 1]);
            let inner_body: &[u8] = &plaintext[0..type_offset - 1];
            let message = Message::from_raw(inner_body, inner_content_type)?;
            println!("======== Received {}", message.name());

            // let old_transcript = state_data.transcript.clone();
            let old_transcript_hash: Vec<u8> = transcript_hash(&state_data.transcript);
            state_data.transcript.extend_from_slice(&inner_body);
            let new_transcript_hash: Vec<u8> = transcript_hash(&state_data.transcript);
            // println!("transcript hash = {:?}", BinaryData(&transcript_hash(&state_data.transcript)));

            // println!("inner_content_type = {:?}", inner_content_type);
            // println!("inner_body.len() = {}", inner_body.len());


            // println!("plaintext =");
            // println!("{:#?}", Indent(&DebugHexDump(&plaintext)));
            // println!("inner_body =");
            // println!("{:#?}", Indent(&DebugHexDump(&inner_body)));


            match message {
                Message::Handshake(Handshake::Certificate(certificate)) => {

                    println!("    Received Handshake::Certificate");
                    println!("        certificate_request_context.len() = {}", certificate.certificate_request_context.len());
                    println!("        certificate_list.len() = {}", certificate.certificate_list.len());

                    println!("    This is a certificate handshake");
                    for entry in certificate.certificate_list.iter() {
                        println!("    - entry");
                        let filename = "certificate.crt";
                        std::fs::write(filename, &entry.data)?;
                        println!("    Wrote to {}", filename);
                    }
                    // println!("handshake = {:#?}", inner_handshake);

                }
                Message::Handshake(Handshake::CertificateVerify(certificate_verify)) => {

                    println!("    Received Handshake::CertificateVerify with algorithm {:?} and {} signature bytes",
                        certificate_verify.algorithm,
                        certificate_verify.signature.len());
                    // println!("handshake = {:#?}", inner_handshake);

                }
                Message::Handshake(Handshake::Finished(finished)) => {

                    println!("    Received Handshake::Finished with {} bytes", finished.data.len());
                    let algorithm_len = hkdf::KeyType::len(&client.algorithm);
                    let input_psk: &[u8] = &vec_with_len(algorithm_len);
                    let new_prk = get_derived_prk(&state_data.prk, client.algorithm, input_psk);

                    let thash = transcript_hash(&state_data.transcript);
                    let ap = TrafficSecrets {
                        client: derive_secret_prk_hash(client.algorithm, &new_prk, b"c ap traffic", &thash),
                        server: derive_secret_prk_hash(client.algorithm, &new_prk, b"s ap traffic", &thash),
                    };
                    println!("        KEY CLIENT_TRAFFIC_SECRET_0: {}", BinaryData(&ap.client));
                    println!("        KEY SERVER_TRAFFIC_SECRET_0 = {}", BinaryData(&ap.server));



                    {
                        let derived_bytes = derive_secret3(client.algorithm, &state_data.handshake_secrets.server, b"finished");

                        println!("server_finished_key_bytes = {:?}", BinaryData(&derived_bytes));
                        let hmac_algorithm: ring::hmac::Algorithm = client.algorithm.hmac_algorithm();
                        let finished_key: ring::hmac::Key = ring::hmac::Key::new(hmac_algorithm, &derived_bytes);
                        let finished_tag: &[u8] = &old_transcript_hash;
                        println!();
                        println!("server_finish: handshake_hash = {:?}", BinaryData(finished_tag));
                        let verify_tag = ring::hmac::sign(&finished_key, finished_tag);
                        let verify_data: &[u8] = &verify_tag.as_ref();
                        println!("server_finish: verify_data    = {:?}", BinaryData(verify_data));
                        println!("server_finish: finished.data  = {:?}", BinaryData(&finished.data));
                        println!();
                        match ring::hmac::verify(&finished_key, finished_tag, &finished.data) {
                            Ok(()) => println!("Finished: Verification succeeded"),
                            Err(_) => println!("Finished: Verification failed"),
                        };
                    }


                    let mut client_sequence_no: u64 = 0;

                    // Send Client Finished message
                    {
                        let derived_bytes = derive_secret3(client.algorithm, &state_data.handshake_secrets.client, b"finished");

                        println!("client_finished_key_bytes = {:?}", BinaryData(&derived_bytes));
                        let hmac_algorithm: ring::hmac::Algorithm = client.algorithm.hmac_algorithm();
                        let finished_key: ring::hmac::Key = ring::hmac::Key::new(hmac_algorithm, &derived_bytes);
                        let finished_tag_ref: &[u8] = &new_transcript_hash;
                        println!();
                        println!("client_finish: handshake_hash = {:?}", BinaryData(&finished_tag_ref));
                        let verify_tag = ring::hmac::sign(&finished_key, &finished_tag_ref);
                        let verify_data: &[u8] = &verify_tag.as_ref();
                        println!("client_finish: verify_data    = {:?}", BinaryData(verify_data));

                        let client_finished = Handshake::Finished(Finished {
                            data: verify_data.to_vec(),
                        });

                        let mut writer = BinaryWriter::new();
                        writer.write_item(&client_finished)?;
                        let client_finished_bytes: Vec<u8> = Vec::from(writer);
                        println!("client_finished_bytes = {:?}", BinaryData(&client_finished_bytes));

                        let mut to_encrypt: Vec<u8> = Vec::new();
                        to_encrypt.extend_from_slice(&client_finished_bytes);
                        to_encrypt.push(22); // Handshake



                        let client_finished_enc = encrypt_traffic(
                            client.algorithm,
                            &state_data.handshake_secrets.client,
                            client_sequence_no,
                            &to_encrypt)?;
                        client_sequence_no += 1;

                        let output_record = TLSPlaintext {
                            content_type: ContentType::ApplicationData,
                            legacy_record_version: 0x0303,
                            fragment: client_finished_enc,
                        };
                        client.to_send.extend_from_slice(&output_record.to_vec());
                        // Ok(output_record)

                    }


                    // HTTP request
                    {
                        let mut to_encrypt: Vec<u8> = Vec::new();
                        to_encrypt.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
                        to_encrypt.push(23); // ApplicationData

                        client_sequence_no = 0;
                        let client_finished_enc = encrypt_traffic(
                            client.algorithm,
                            &ap.client,
                            client_sequence_no,
                            &to_encrypt)?;
                        client_sequence_no += 1;

                        let output_record = TLSPlaintext {
                            content_type: ContentType::ApplicationData,
                            legacy_record_version: 0x0303,
                            fragment: client_finished_enc,
                        };
                        client.to_send.extend_from_slice(&output_record.to_vec());
                    }



                    // println!("handshake = {:#?}", inner_handshake);
                    client.state = State::Established(EstablishedData {
                        prk: new_prk,
                        application_secrets: ap,
                        client_sequence_no: 0,
                        // server_sequence_no: state_data.server_sequence_no,
                        server_sequence_no: 0,
                    });

                }
                _ => {
                    println!("Unexpected message type {}", message.name());
                }
            }
        }


        State::Established(state_data) => {
            // println!("Received ApplicationData (server_sequence_no = {})", state_data.server_sequence_no);
            let current_sequence_no = state_data.server_sequence_no;
            state_data.server_sequence_no += 1;
            println!("ApplicationData for server_sequence_no {}", current_sequence_no);

            let plaintext = match decrypt_traffic(client.algorithm,
                                                  &state_data.application_secrets.server,
                                                  current_sequence_no,
                                                  &plaintext_raw) {
                Err(e) => return Err(GeneralError::new(format!("established: key.open_in_place() failed: {}", e))),
                Ok(plaintext) => plaintext,
            };


            // TEMP: Add test zero padding
            // let mut plaintext: Vec<u8> = plaintext.to_vec();
            // for i in 0..5 {
            //     plaintext.push(0);
            // }

            let mut type_offset: usize = plaintext.len();
            while type_offset > 0 && plaintext[type_offset - 1] == 0 {
                type_offset -= 1;
            }
            if type_offset == 0 {
                return Err(GeneralError::new("Plaintext: Missing type field"));
            }
            let inner_content_type = ContentType::from_raw(plaintext[type_offset - 1]);
            let inner_body: &[u8] = &plaintext[0..type_offset - 1];
            let message = Message::from_raw(inner_body, inner_content_type)?;
            println!("======== Received {}", message.name());
            match message {
                Message::Handshake(Handshake::NewSessionTicket(ticket)) => {
                    println!("ticket = {:#?}", ticket);
                }
                Message::ApplicationData(data) => {
                    println!("data =");
                    println!("{:#?}", Indent(&DebugHexDump(&data)));
                }
                Message::Alert(alert) => {
                    // println!("inner_alert = {:?}", Indent(&alert));
                }
                _ => {
                    println!("Unexpected message type {}", message.name());
                }
            }
        }



        _ => {
            println!("Received ApplicationData but don't have secret");
        }
    }
    Ok(())
}


async fn test_client() -> Result<(), Box<dyn Error>> {
    let algorithm: ring::hkdf::Algorithm = ring::hkdf::HKDF_SHA384;
    let algorithm_len = hkdf::KeyType::len(&algorithm);
    println!("algorithm.len() = {}", algorithm_len);

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

    let serialized_filename = "record-constructed.bin";
    std::fs::write(serialized_filename, &client_hello_plaintext_record_bytes)?;
    println!("Wrote {}", serialized_filename);

    let mut socket = TcpStream::connect("localhost:443").await?;
    socket.write_all(&client_hello_plaintext_record_bytes).await?;

    let mut initial_transcript: Vec<u8> = Vec::new();
    initial_transcript.extend_from_slice(&client_hello_bytes);
    let mut client = Client {
        state: State::ClientHelloSent(ClientHelloSentData {
            prk: get_zero_prk(algorithm),
            transcript: initial_transcript,
        }),
        my_private_key: my_private_key,
        algorithm: algorithm,
        to_send: Vec::new(),
    };

    let mut receiver = Receiver::new();

    while let Some((plaintext, plaintext_raw)) = receiver.next(&mut socket).await? {
        match plaintext.content_type {
            ContentType::Invalid => {
                println!("Unsupported record type: Invalid");
            }
            ContentType::ChangeCipherSpec => {
                println!("ChangeCipherSpec record: Ignoring");
            }
            ContentType::Alert => {
                println!("Unsupported record type: Alert");
            }
            ContentType::Handshake => {
                client_received_handshake(&mut client, plaintext, plaintext_raw)?;
            }
            ContentType::ApplicationData => {
                client_received_application_data(&mut client, plaintext, plaintext_raw)?;
            }
            ContentType::Unknown(code) => {
                println!("Unsupported record type: {}", code);
            }
        }


        if client.to_send.len() > 0 {
            socket.write_all(&client.to_send).await?;
            println!("Sent {} bytes", client.to_send.len());
            client.to_send.clear();
        }
    }
    println!("Server closed connection");
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
