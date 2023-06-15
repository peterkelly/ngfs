#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::fmt;
use crate::crypto::crypt::HashAlgorithm;
use crate::crypto::error::CryptError;
use crate::tls::helpers::{hkdf_expand_label, hkdf_expand_label2};
use crate::util::util::BinaryData;
use super::spec::ConnectionId;

#[derive(Clone)]
pub struct EndpointSecrets {
    pub initial: Vec<u8>,
    pub key: [u8; 16],
    pub iv: [u8; 12],
    pub hp: [u8; 16],
}

impl EndpointSecrets {
    pub fn from_initial(hash_alg: HashAlgorithm, initial: &[u8]) -> Result<EndpointSecrets, CryptError> {
        let mut key: [u8; 16] = [0; 16];
        let mut iv: [u8; 12] = [0; 12];
        let mut hp: [u8; 16] = [0; 16];
        hkdf_expand_label(hash_alg, initial, b"quic key", b"", &mut key)?;
        hkdf_expand_label(hash_alg, initial, b"quic iv", b"", &mut iv)?;
        hkdf_expand_label(hash_alg, initial, b"quic hp", b"", &mut hp)?;
        Ok(EndpointSecrets { initial: Vec::from(initial), key, iv, hp })
    }
}

impl fmt::Debug for EndpointSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointSecrets")
            .field("key", &BinaryData(&self.key))
            .field("iv", &BinaryData(&self.iv))
            .field("hp", &BinaryData(&self.hp))
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionSecrets {
    pub client: EndpointSecrets,
    pub server: EndpointSecrets,
}

impl ConnectionSecrets {
    pub fn from_initial(
        hash_alg: HashAlgorithm,
        initial: &[u8],
    ) -> Result<ConnectionSecrets, CryptError> {
        let client_initial_secret = hkdf_expand_label2(
            hash_alg,
            initial,
            b"client in",
            &[],
            hash_alg.byte_len(),
        )?;
        let server_initial_secret = hkdf_expand_label2(
            hash_alg,
            initial,
            b"server in",
            &[],
            hash_alg.byte_len(),
        )?;


        Ok(ConnectionSecrets {
            client: EndpointSecrets::from_initial(hash_alg, &client_initial_secret)?,
            server: EndpointSecrets::from_initial(hash_alg, &server_initial_secret)?,
        })
    }

    pub fn from_connection_id(
        hash_alg: HashAlgorithm,
        dst_connection_id: &ConnectionId,
    ) -> Result<ConnectionSecrets, CryptError> {
        let initial_salt = &[0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                             0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a];
        let initial_secret = hash_alg.hkdf_extract(initial_salt, &dst_connection_id.0);
        Self::from_initial(hash_alg, &initial_secret)
    }
}
