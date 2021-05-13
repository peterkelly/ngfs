use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use super::super::crypt::{HashAlgorithm, AeadAlgorithm, CryptError};
use super::super::util::{vec_with_len};
use super::types::handshake::{
    // ClientHello,
    ServerHello,
    Finished,
    CipherSuite,
};
use super::types::extension::{
    Extension,
    NamedGroup,
};
use super::types::record::{
    TLSCiphertext,
    ContentType,
    Message,
};
use super::error::{
    TLSError,
};

#[derive(Clone)] // TODO: Avoid need for clone
pub struct EncryptionKey {
    pub raw: Vec<u8>,
    pub aead_alg: AeadAlgorithm,
    pub write_key: Vec<u8>,
    pub write_iv: [u8; 12],
}

impl EncryptionKey {
    pub fn new(raw: Vec<u8>, hash_alg: HashAlgorithm, aead_alg: AeadAlgorithm) -> Result<Self, CryptError> {
        let mut write_key = vec_with_len(aead_alg.key_len());
        let mut write_iv: [u8; 12] = [0; 12];
        hkdf_expand_label(hash_alg, &raw, b"key", &[], &mut write_key)?;
        hkdf_expand_label(hash_alg, &raw, b"iv", &[], &mut write_iv)?;
        Ok(EncryptionKey {
            raw,
            aead_alg,
            write_key,
            write_iv,
        })
    }
}

pub struct Ciphers {
    pub hash_alg: HashAlgorithm,
    pub aead_alg: AeadAlgorithm,
}

impl Ciphers {
    pub fn from_server_hello(server_hello: &ServerHello) -> Result<Self, TLSError> {
        match server_hello.cipher_suite {
            CipherSuite::TLS_AES_128_GCM_SHA256 => {
                Ok(Ciphers {
                    hash_alg: HashAlgorithm::SHA256,
                    aead_alg: AeadAlgorithm::AES_128_GCM_SHA256,
                })
            }
            CipherSuite::TLS_AES_256_GCM_SHA384 => {
                Ok(Ciphers {
                    hash_alg: HashAlgorithm::SHA384,
                    aead_alg: AeadAlgorithm::AES_256_GCM_SHA384,
                })
            }
            _ => {
                Err(TLSError::UnsupportedCipherSuite)
            }
        }
    }
}

pub struct TrafficSecrets {
    pub client: EncryptionKey,
    pub server: EncryptionKey,
}

impl TrafficSecrets {
    pub fn derive_from(ciphers: &Ciphers, transcript: &[u8], prk: &[u8], label: &str) -> Result<Self, CryptError> {
        let client_label = format!("c {} traffic", label);
        let server_label = format!("s {} traffic", label);
        let thash = ciphers.hash_alg.hash(transcript);
        Ok(TrafficSecrets {
            client: EncryptionKey::new(
                derive_secret(ciphers.hash_alg, &prk, client_label.as_bytes(), &thash)?,
                ciphers.hash_alg,
                ciphers.aead_alg)?,
            server: EncryptionKey::new(
                derive_secret(ciphers.hash_alg, &prk, server_label.as_bytes(), &thash)?,
                ciphers.hash_alg,
                ciphers.aead_alg)?,
        })
    }
}

fn hkdf_expand_label(
    alg: HashAlgorithm,
    prk: &[u8],
    label_suffix: &[u8],
    context: &[u8],
    okm: &mut [u8],
) -> Result<(), CryptError> {
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

    alg.hkdf_expand(prk, &hkdf_label, okm)?;
    Ok(())
}

pub fn derive_secret(alg: HashAlgorithm, secret: &[u8], label: &[u8], thash: &[u8]) -> Result<Vec<u8>, CryptError> {
    let len = alg.byte_len();
    let mut result: Vec<u8> = vec_with_len(len);
    hkdf_expand_label(alg, &secret, label, &thash, &mut result)?;
    Ok(result)
}

// fn get_client_hello_x25519_key_share(client_hello: &ClientHello) -> Option<Vec<u8>> {
//     for extension in client_hello.extensions.iter() {
//         if let Extension::KeyShareClientHello(key_shares) = extension {
//             for ks in key_shares.iter() {
//                 if ks.group == NamedGroup::X25519 {
//                     return Some(ks.key_exchange.clone());
//                 }
//             }
//         }
//     }
//     return None;
// }

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

pub fn get_server_hello_x25519_shared_secret(
    my_private_key: EphemeralPrivateKey,
    server_hello: &ServerHello,
) -> Option<Vec<u8>> {
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

fn empty_transcript_hash(alg: HashAlgorithm) -> Vec<u8> {
    alg.hash(&[])
}

pub fn get_zero_prk(alg: HashAlgorithm) -> Vec<u8> {
    let input_zero: &[u8] = &vec_with_len(alg.byte_len());
    let input_psk: &[u8] = &vec_with_len(alg.byte_len());
    alg.hkdf_extract(&input_zero, input_psk)
}

pub fn get_derived_prk(alg: HashAlgorithm, prbytes: &[u8], secret: &[u8]) -> Result<Vec<u8>, CryptError> {
    let salt_bytes: Vec<u8> = derive_secret(alg, &prbytes, b"derived", &empty_transcript_hash(alg))?;
    Ok(alg.hkdf_extract(&salt_bytes, secret))
}

pub fn encrypt_traffic(
    traffic_secret: &EncryptionKey,
    sequence_no: u64,
    inout: &mut Vec<u8>,
) -> Result<(), TLSError> {
    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= traffic_secret.write_iv[i];
    }

    let len = inout.len() + traffic_secret.aead_alg.tag_len();

    let additional_data: [u8; 5] = [
        0x17, // opaque_type = application_data = 23
        0x03, // legacy_record_version = 0x0303
        0x03, // legacy_record_version
        (len >> 8) as u8,
        len as u8,
    ];

    traffic_secret.aead_alg.encrypt_in_place(
        &traffic_secret.write_key,
        &nonce_bytes,
        &additional_data,
        inout)
        .map_err(|_| TLSError::EncryptionFailed)?;
    Ok(())
}

fn decrypt_traffic(
    traffic_secret: &EncryptionKey,
    sequence_no: u64,
    plaintext_raw: &[u8],
) -> Result<Vec<u8>, TLSError> {
    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= traffic_secret.write_iv[i];
    }

    let (tls_ciphertext, bytes_consumed) = match TLSCiphertext::from_raw_data(&plaintext_raw) {
        Ok(v) => v,
        Err(_) => return Err(TLSError::DecryptionFailed),
    };
    if bytes_consumed != plaintext_raw.len() {
        return Err(TLSError::DecryptionFailed);
    }

    if plaintext_raw.len() < 5 {
        return Err(TLSError::DecryptionFailed);
    }

    // let mut associated_data: [u8; 5] = [0; 5];
    let associated_data: [u8; 5] = [
        plaintext_raw[0],
        plaintext_raw[1],
        plaintext_raw[2],
        plaintext_raw[3],
        plaintext_raw[4],
    ];

    let mut work: Vec<u8> = tls_ciphertext.encrypted_record;
    traffic_secret.aead_alg.decrypt_in_place(
        &traffic_secret.write_key,
        &nonce_bytes,
        &associated_data,
        &mut work)
        .map_err(|_| TLSError::DecryptionFailed)?;
    Ok(work)
}

pub fn decrypt_message(
    sequence_no: u64,
    decryption_key: &EncryptionKey,
    plaintext_raw: &[u8],
) -> Result<(Message, Vec<u8>), TLSError> {
    // println!("ApplicationData for server_sequence_no {}", sequence_no);

    let plaintext = decrypt_traffic(decryption_key, sequence_no, plaintext_raw)?;


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
        return Err(TLSError::InvalidPlaintextRecord);
    }
    let inner_content_type = ContentType::from_raw(plaintext[type_offset - 1]);
    let inner_body: &[u8] = &plaintext[0..type_offset - 1];

    let mut inner_body_vec: Vec<u8> = Vec::new();
    inner_body_vec.extend_from_slice(inner_body);
    let message = Message::from_raw(inner_body, inner_content_type)
        .map_err(|_| TLSError::InvalidMessageRecord)?;
    // println!("======== Received {}", message.name());

    Ok((message, inner_body_vec))
}

pub fn verify_finished(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    transcript_hash: &[u8],
    finished: &Finished,
) -> Result<(), TLSError> {
    let finished_key = derive_secret(hash_alg, &encryption_key.raw, b"finished", &[])?;

    // println!("finished_key = {:?}", BinaryData(&finished_key));
    // println!();
    // println!("finish: handshake_hash = {:?}", BinaryData(&transcript_hash));
    // let verify_data: Vec<u8> = hash_alg.hmac_sign(&finished_key, &transcript_hash)?;
    // println!("finish: verify_data    = {:?}", BinaryData(&verify_data));
    // println!("finish: finished.data  = {:?}", BinaryData(&finished.verify_data));
    // println!();

    if hash_alg.hmac_verify(&finished_key, &transcript_hash, &finished.verify_data)? {
        Ok(())
    }
    else {
        Err(TLSError::FinishedVerificationFailed)
    }
}
