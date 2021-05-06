use ring::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::aead::{LessSafeKey, UnboundKey, Nonce, Aad};
use ring::error::Unspecified;
use super::super::crypt::HashAlgorithm;
use super::super::util::{vec_with_len};
use super::types::handshake::{
    // ClientHello,
    ServerHello,
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

fn hkdf_expand_label(
    alg: HashAlgorithm,
    prk: &[u8],
    label_suffix: &[u8],
    context: &[u8],
    okm: &mut [u8],
) {
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

    alg.hkdf_expand(prk, &hkdf_label, okm);
}

pub fn derive_secret(alg: HashAlgorithm, secret: &[u8], label: &[u8], thash: &[u8]) -> Vec<u8> {
    let len = alg.byte_len();
    let mut result: Vec<u8> = vec_with_len(len);
    hkdf_expand_label(alg, &secret, label, &thash, &mut result);
    result
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
    let mut output: Vec<u8> = vec_with_len(alg.byte_len());
    alg.hkdf_extract(&input_zero, input_psk, &mut output);
    output
}

pub fn get_derived_prk(alg: HashAlgorithm, prbytes: &[u8], secret: &[u8]) -> Vec<u8> {
    let salt_bytes: Vec<u8> = derive_secret(alg, &prbytes, b"derived", &empty_transcript_hash(alg));
    let mut output: Vec<u8> = vec_with_len(alg.byte_len());
    alg.hkdf_extract(&salt_bytes, secret, &mut output);
    output
}

pub fn encrypt_traffic(
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    traffic_secret: &[u8],
    sequence_no: u64,
    inout: &mut Vec<u8>,
) -> Result<(), TLSError> {
    let mut write_key: [u8; 32] = [0; 32];
    let mut write_iv: [u8; 12] = [0; 12];

    hkdf_expand_label(hash_alg, traffic_secret, b"key", &[], &mut write_key);
    hkdf_expand_label(hash_alg, traffic_secret, b"iv", &[], &mut write_iv);

    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= write_iv[i];
    }

    let unbound_key = match UnboundKey::new(aead_alg, &write_key[0..32]) {
        Ok(v) => v,
        Err(Unspecified) => return Err(TLSError::EncryptionFailed),
    };
    let key = LessSafeKey::new(unbound_key);

    let len = inout.len() + key.algorithm().tag_len();

    let additional_data: [u8; 5] = [
        0x17, // opaque_type = application_data = 23
        0x03, // legacy_record_version = 0x0303
        0x03, // legacy_record_version
        (len >> 8) as u8,
        len as u8,
    ];


    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let aad = Aad::from(additional_data);

    match key.seal_in_place_append_tag(nonce, aad, inout) {
        Ok(()) => (),
        Err(Unspecified) => return Err(TLSError::EncryptionFailed),
    };
    Ok(())
}

fn decrypt_traffic(
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    traffic_secret: &[u8],
    sequence_no: u64,
    plaintext_raw: &[u8],
) -> Result<Vec<u8>, TLSError> {
    let mut write_key: [u8; 32] = [0; 32];
    let mut write_iv: [u8; 12] = [0; 12];

    hkdf_expand_label(hash_alg, traffic_secret, b"key", &[], &mut write_key);
    hkdf_expand_label(hash_alg, traffic_secret, b"iv", &[], &mut write_iv);

    let sequence_no_bytes: [u8; 8] = sequence_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = [0; 12];
    &nonce_bytes[4..12].copy_from_slice(&sequence_no_bytes);
    for i in 0..12 {
        nonce_bytes[i] ^= write_iv[i];
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

    let unbound_key = match ring::aead::UnboundKey::new(aead_alg, &write_key[0..32]) {
        Ok(v) => v,
        Err(Unspecified) => return Err(TLSError::DecryptionFailed),
    };
    let key = ring::aead::LessSafeKey::new(unbound_key);

    let mut work: Vec<u8> = tls_ciphertext.encrypted_record;

    let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
    let aad = ring::aead::Aad::from(&plaintext_raw[0..5]);

    let open_result = match key.open_in_place(nonce, aad, &mut work) {
        Ok(v) => v,
        Err(Unspecified) => return Err(TLSError::DecryptionFailed),
    };

    Ok(open_result.to_vec())
}

pub fn decrypt_message(
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    sequence_no: u64,
    decryption_key: &[u8],
    plaintext_raw: &[u8],
) -> Result<(Message, Vec<u8>), TLSError> {
    println!("ApplicationData for server_sequence_no {}", sequence_no);

    let plaintext = decrypt_traffic(hash_alg,
                                          aead_alg,
                                          decryption_key,
                                          sequence_no,
                                          plaintext_raw)?;


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
    println!("======== Received {}", message.name());

    Ok((message, inner_body_vec))
}
