use crypto::digest::Digest;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};
use hmac::{Hmac, Mac, NewMac};
use super::error::CryptError;

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

    pub fn make_hasher(&self) -> Hasher {
        match self {
            HashAlgorithm::SHA256 => Hasher::SHA256(Sha256::new()),
            HashAlgorithm::SHA384 => Hasher::SHA384(Sha384::new()),
            HashAlgorithm::SHA512 => Hasher::SHA512(Sha512::new()),
        }
    }

    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8],  okm: &mut [u8]) -> Result<(), CryptError> {
        match self {
            HashAlgorithm::SHA256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(prk)
                    .map_err(|_| CryptError::InvalidPrkLength)?;
                hkdf.expand(info, okm).map_err(|_| CryptError::InvalidLength)?;
                Ok(())
            }
            HashAlgorithm::SHA384 => {
                let hkdf = Hkdf::<Sha384>::from_prk(prk)
                    .map_err(|_| CryptError::InvalidPrkLength)?;
                hkdf.expand(info, okm).map_err(|_| CryptError::InvalidLength)?;
                Ok(())

            }
            HashAlgorithm::SHA512 => {
                let hkdf = Hkdf::<Sha512>::from_prk(prk)
                    .map_err(|_| CryptError::InvalidPrkLength)?;
                hkdf.expand(info, okm).map_err(|_| CryptError::InvalidLength)?;
                Ok(())
            }
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
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            HashAlgorithm::SHA384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            HashAlgorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    pub fn hmac_verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> Result<bool, CryptError> {
        match self {
            HashAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                match mac.verify(expected) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }

            }
            HashAlgorithm::SHA384 => {
                let mut mac = Hmac::<Sha384>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                match mac.verify(expected) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }

            }
            HashAlgorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(key)
                    .map_err(|_| CryptError::InvalidKeyLength)?;
                mac.update(data);
                match mac.verify(expected) {
                    Ok(_) => Ok(true),
                    Err(_) => Ok(false),
                }
            }
        }
    }
}

#[derive(Clone)]
pub enum Hasher {
    SHA256(Sha256),
    SHA384(Sha384),
    SHA512(Sha512),
}

impl Hasher {
    pub fn update(&mut self, input: &[u8]) {
        match self {
            Hasher::SHA256(h) => Digest::update(h, input),
            Hasher::SHA384(h) => Digest::update(h, input),
            Hasher::SHA512(h) => Digest::update(h, input),
        }
    }

    pub fn finalize(&self) -> Vec<u8> {
        match self.clone() {
            Hasher::SHA256(h) => Digest::finalize(h).to_vec(),
            Hasher::SHA384(h) => Digest::finalize(h).to_vec(),
            Hasher::SHA512(h) => Digest::finalize(h).to_vec(),
        }
    }
}
