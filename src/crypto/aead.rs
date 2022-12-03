use std::marker::PhantomData;
use crypto::aead::{AeadInPlace, AeadCore, Key, Nonce, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use generic_array::typenum::Unsigned;
use super::error::CryptError;

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AeadAlgorithm {
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
    // CHACHA20_POLY1305_SHA256,
    // AES_128_CCM_SHA256,
    // AES_128_CCM_8_SHA256,
}


fn try_key_from_slice<AEAD : KeyInit>(key: &[u8]) -> Result<&Key<AEAD>, CryptError> {
    if key.len() != AEAD::KeySize::USIZE {
        Err(CryptError::InvalidKeyLength)
    }
    else {
        Ok(Key::<AEAD>::from_slice(key))
    }
}

fn try_nonce_from_slice<AEAD: AeadCore>(nonce: &[u8]) -> Result<&Nonce<AEAD>, CryptError> {
    if nonce.len() != AEAD::NonceSize::USIZE {
        Err(CryptError::InvalidNonceLength)
    }
    else {
        Ok(Nonce::<AEAD>::from_slice(nonce))
    }
}

struct AEADCommon<AEAD> (PhantomData<AEAD>) where AEAD : AeadInPlace + KeyInit;

impl<AEAD> AEADCommon<AEAD> where AEAD : AeadInPlace + KeyInit {
    fn key_len() -> usize {
        AEAD::KeySize::USIZE
    }

    fn nonce_len() -> usize {
        AEAD::NonceSize::USIZE
    }

    fn tag_len() -> usize {
        AEAD::TagSize::USIZE
    }

    #[allow(clippy::ptr_arg)]
    fn encrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptError>
    {
        let key = try_key_from_slice::<AEAD>(key)?;
        let nonce = try_nonce_from_slice::<AEAD>(nonce)?;
        let aead = AEAD::new(key);
        aead.encrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| CryptError::DecryptionFailed)
    }

    #[allow(clippy::ptr_arg)]
    fn decrypt_in_place(
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>,
    ) -> Result<(), CryptError>
    {
        let key = try_key_from_slice::<AEAD>(key)?;
        let nonce = try_nonce_from_slice::<AEAD>(nonce)?;
        let aead = AEAD::new(key);
        aead.decrypt_in_place(nonce, associated_data, buffer)
            .map_err(|_| CryptError::DecryptionFailed)
    }
}

impl AeadAlgorithm {
    pub fn key_len(&self) -> usize {
        match self {
            AeadAlgorithm::AES_128_GCM_SHA256 => AEADCommon::<Aes128Gcm>::key_len(),
            AeadAlgorithm::AES_256_GCM_SHA384 => AEADCommon::<Aes256Gcm>::key_len(),
        }
    }

    pub fn nonce_len(&self) -> usize {
        match self {
            AeadAlgorithm::AES_128_GCM_SHA256 => AEADCommon::<Aes128Gcm>::nonce_len(),
            AeadAlgorithm::AES_256_GCM_SHA384 => AEADCommon::<Aes256Gcm>::nonce_len(),
        }
    }

    pub fn tag_len(&self) -> usize {
        match self {
            AeadAlgorithm::AES_128_GCM_SHA256 => AEADCommon::<Aes128Gcm>::tag_len(),
            AeadAlgorithm::AES_256_GCM_SHA384 => AEADCommon::<Aes256Gcm>::tag_len(),
        }
    }

    pub fn encrypt_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>
    ) -> Result<(), CryptError> {
        match self {
            AeadAlgorithm::AES_128_GCM_SHA256 => AEADCommon::<Aes128Gcm>::
                encrypt_in_place(key, nonce, associated_data, buffer),
            AeadAlgorithm::AES_256_GCM_SHA384 => AEADCommon::<Aes256Gcm>::
                encrypt_in_place(key, nonce, associated_data, buffer),
        }
    }

    pub fn decrypt_in_place(
        &self,
        key: &[u8],
        nonce: &[u8],
        associated_data: &[u8],
        buffer: &mut Vec<u8>
    ) -> Result<(), CryptError> {
        match self {
            AeadAlgorithm::AES_128_GCM_SHA256 => AEADCommon::<Aes128Gcm>::
                decrypt_in_place(key, nonce, associated_data, buffer),
            AeadAlgorithm::AES_256_GCM_SHA384 => AEADCommon::<Aes256Gcm>::
                decrypt_in_place(key, nonce, associated_data, buffer),
        }
    }
}
