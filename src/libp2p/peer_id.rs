use crate::libp2p::secio::{PublicKey, KeyType};

pub fn encode_libp2p_public_key(dalek_public_key: &ed25519_dalek::PublicKey) -> Vec<u8> {
    let libp2p_public_key = PublicKey {
        key_type: KeyType::Ed25519,
        data: Vec::from(dalek_public_key.to_bytes()),
    };
    let libp2p_public_key_bytes: Vec<u8> = libp2p_public_key.to_pb();
    libp2p_public_key_bytes
}
