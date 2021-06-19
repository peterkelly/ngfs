#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use super::super::p2p::{PublicKey, KeyType};

pub fn encode_libp2p_public_key(dalek_public_key: &ed25519_dalek::PublicKey) -> Vec<u8> {
    let libp2p_public_key = PublicKey {
        key_type: KeyType::Ed25519,
        data: Vec::from(dalek_public_key.to_bytes()),
    };
    let libp2p_public_key_bytes: Vec<u8> = libp2p_public_key.to_pb();
    libp2p_public_key_bytes
}
