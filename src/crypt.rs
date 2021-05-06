use std::fmt;
use std::error::Error;
use std::marker::PhantomData;
use crypto::digest::{Digest, Update, BlockInput, FixedOutput, Reset};
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};
use crypto::aead::{AeadInPlace, AeadCore, Key, Nonce, NewAead};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use generic_array::typenum::Unsigned;

#[derive(Debug)]
pub enum CryptError {
    InvalidPrkLength,
    InvalidLength,
    InvalidKeyLength,
    InvalidNonceLength,
    EncryptionFailed,
    DecryptionFailed,
}

impl fmt::Display for CryptError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for CryptError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
}

impl HashAlgorithm {
    pub fn byte_len(&self) -> usize {
        match self {
            HashAlgorithm::SHA256 => 32,
            HashAlgorithm::SHA384 => 48,
            HashAlgorithm::SHA512 => 64,
        }
    }

    pub fn hash(&self, input: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::SHA256 => hash::<Sha256>(input),
            HashAlgorithm::SHA384 => hash::<Sha384>(input),
            HashAlgorithm::SHA512 => hash::<Sha512>(input),
        }
    }

    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8],  okm: &mut [u8]) -> Result<(), CryptError> {
        match self {
            HashAlgorithm::SHA256 => hkdf_expand::<Sha256>(prk, info, okm),
            HashAlgorithm::SHA384 => hkdf_expand::<Sha384>(prk, info, okm),
            HashAlgorithm::SHA512 => hkdf_expand::<Sha512>(prk, info, okm),
        }
    }

    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::SHA256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.as_slice().to_vec(),
            HashAlgorithm::SHA384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.as_slice().to_vec(),
            HashAlgorithm::SHA512 => Hkdf::<Sha512>::extract(Some(salt), ikm).0.as_slice().to_vec(),
        }
    }

    pub fn hmac_sign(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptError> {
        match self {
            HashAlgorithm::SHA256 => hmac_sign::<Sha256>(key, data),
            HashAlgorithm::SHA384 => hmac_sign::<Sha384>(key, data),
            HashAlgorithm::SHA512 => hmac_sign::<Sha512>(key, data),
        }
    }

    pub fn hmac_verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptError> {
        match self {
            HashAlgorithm::SHA256 => hmac_verify::<Sha256>(key, data, expected),
            HashAlgorithm::SHA384 => hmac_verify::<Sha384>(key, data, expected),
            HashAlgorithm::SHA512 => hmac_verify::<Sha512>(key, data, expected),
        }
    }
}

fn hash<D : Digest>(input: &[u8]) -> Vec<u8> {
    let mut digest = D::new();
    digest.update(input);
    digest.finalize().to_vec()
}

fn hkdf_expand<D>(prk: &[u8], info: &[u8],  okm: &mut [u8]) -> Result<(), CryptError>
    where D: Update + BlockInput + FixedOutput + Reset + Default + Clone
{
    let hkdf = Hkdf::<D>::from_prk(prk).map_err(|_| CryptError::InvalidPrkLength)?;
    hkdf.expand(info, okm).map_err(|_| CryptError::InvalidLength)?;
    Ok(())
}

fn hmac_sign<D>(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptError>
    where D: Update + BlockInput + FixedOutput + Reset + Default + Clone
{
    let mut mac = Hmac::<D>::new_from_slice(key).map_err(|_| CryptError::InvalidKeyLength)?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn hmac_verify<D>(key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptError>
    where D: Update + BlockInput + FixedOutput + Reset + Default + Clone
{
    let mut mac = Hmac::<D>::new_from_slice(key).map_err(|_| CryptError::InvalidKeyLength)?;
    mac.update(data);
    match mac.verify(expected) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AeadAlgorithm {
    AES_128_GCM_SHA256,
    AES_256_GCM_SHA384,
    // CHACHA20_POLY1305_SHA256,
    // AES_128_CCM_SHA256,
    // AES_128_CCM_8_SHA256,
}


fn try_key_from_slice<AEAD : NewAead>(key: &[u8]) -> Result<&Key<AEAD>, CryptError> {
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

struct AEADCommon<AEAD> (PhantomData<AEAD>) where AEAD : AeadInPlace + NewAead;

impl<AEAD> AEADCommon<AEAD> where AEAD : AeadInPlace + NewAead {
    fn key_len() -> usize {
        AEAD::KeySize::USIZE
    }

    fn nonce_len() -> usize {
        AEAD::NonceSize::USIZE
    }

    fn tag_len() -> usize {
        AEAD::TagSize::USIZE
    }

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
        aead.encrypt_in_place(&nonce, associated_data, buffer)
            .map_err(|_| CryptError::DecryptionFailed)
    }

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
        aead.decrypt_in_place(&nonce, associated_data, buffer)
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
