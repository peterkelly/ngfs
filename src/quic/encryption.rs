use std::error::Error;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use crate::crypto::aead::AeadAlgorithm;
use super::wire::EndpointSecrets;

pub fn add_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    secrets: &EndpointSecrets,
) -> Result<(), Box<dyn Error>> {
    let key = GenericArray::from_slice(&secrets.hp);
    let cipher = Aes128::new(&key);
    let mut mask = get_sample(packet, pn_offset)?;
    cipher.encrypt_block(&mut mask);

    let pn_length = ((packet[0] & 0x03) + 1) as usize;
    if (packet[0] & 0x80) == 0x80 {
        packet[0] ^= mask[0] & 0x0f; // Long header: 4 bits masked
    }
    else {
        packet[0] ^= mask[0] & 0x1f; // Short header: 5 bits masked
    }

    if pn_offset + pn_length > packet.len() {
        return Err("Insufficient data for packet number".into());
    }
    for i in 0..pn_length {
        packet[pn_offset + i] ^= mask[i + 1];
    }

    Ok(())
}

pub fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    secrets: &EndpointSecrets,
) -> Result<(), Box<dyn Error>> {
    let key = GenericArray::from_slice(&secrets.hp);
    let cipher = Aes128::new(&key);
    let mut mask = get_sample(packet, pn_offset)?;
    cipher.encrypt_block(&mut mask);

    if (packet[0] & 0x80) == 0x80 {
        packet[0] ^= mask[0] & 0x0f; // Long header: 4 bits masked
    }
    else {
        packet[0] ^= mask[0] & 0x1f; // Short header: 5 bits masked
    }

    let pn_length = ((packet[0] & 0x03) + 1) as usize;

    if pn_offset + pn_length > packet.len() {
        return Err("Insufficient data for packet number".into());
    }
    for i in 0..pn_length {
        packet[pn_offset + i] ^= mask[i + 1];
    }

    Ok(())
}

pub fn encrypt_payload(
    packet_no: u64,
    header: &[u8],
    pn_offset: usize,
    mut payload: Vec<u8>,
    expected_length: usize,
    secrets: &EndpointSecrets,
    aead_alg: AeadAlgorithm,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let nonce = make_nonce(secrets, packet_no);
    assert!(payload.len() + aead_alg.tag_len() == expected_length);
    aead_alg.encrypt_in_place(&secrets.key, &nonce, header, &mut payload)?;
    assert!(payload.len() == expected_length);

    let mut packet: Vec<u8> = Vec::new();
    packet.extend_from_slice(header);
    packet.extend_from_slice(&payload);

    add_header_protection(&mut packet, pn_offset, secrets)?;

    Ok(packet)
}

pub fn decrypt_payload(
    packet: &mut [u8],
    pn_offset: usize,
    length: usize,
    secrets: &EndpointSecrets,
    aead_alg: AeadAlgorithm,
) -> Result<(u64, Vec<u8>), Box<dyn Error>> {
    assert!(secrets.hp.len() == 16);

    remove_header_protection(packet, pn_offset, secrets)?;
    let pn_length = ((packet[0] & 0x03) + 1) as usize;
    println!("decrypt_payload: pn_length = {}", pn_length);

    // TODO: check length is valid
    let payload_start = pn_offset + pn_length;
    let payload_end = pn_offset + length;
    let header = &packet[0..payload_start];
    let mut payload: Vec<u8> = Vec::from(&packet[payload_start..payload_end]);
    let packet_no = u64_from_slice(&packet[pn_offset..pn_offset + pn_length]);
    let nonce = make_nonce(secrets, packet_no);
    println!("decrypt_payload: before decrypt_in_place");
    aead_alg.decrypt_in_place(&secrets.key, &nonce, header, &mut payload)?;

    println!("decrypt_payload: payload.len() after decryption = {}", payload.len());

    Ok((packet_no, payload))
}

fn get_sample(
    packet: &[u8],
    pn_offset: usize,
) -> Result<GenericArray<u8, typenum::U16>, Box<dyn Error>> {
    let sample_offset = pn_offset + 4;
    // let sample_length = 16; // for AES_128_GCM_SHA256
    if sample_offset + 16 > packet.len() {
        return Err("Insufficient data for sample".into());
    }
    let mut sample: GenericArray<u8, typenum::U16> = GenericArray::from([0u8; 16]);
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);
    Ok(sample)
}

fn make_nonce(secrets: &EndpointSecrets, packet_no: u64) -> [u8; 12] {
    let pn_bytes = packet_no.to_be_bytes();
    let mut nonce_bytes: [u8; 12] = secrets.iv.clone();
    for i in 0..8 {
        nonce_bytes[4 + i] ^= pn_bytes[i];
    }
    nonce_bytes
}

fn u64_from_slice(pn_bytes: &[u8]) -> u64 {
    let mut packet_no: u64 = 0;
    for b in pn_bytes.iter() {
        packet_no = (packet_no << 8) | (*b as u64);
    }
    packet_no
}
