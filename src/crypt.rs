use crypto::digest::Digest;
use super::util::vec_with_len;
use crypto::hkdf::{hkdf_extract, hkdf_expand};
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::sha2::{Sha256, Sha384, Sha512};

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
        let mut output = vec_with_len(self.byte_len());
        match self {
            HashAlgorithm::SHA256 => {
                let mut digest = Sha256::new();
                digest.input(input);
                digest.result(&mut output);
            }
            HashAlgorithm::SHA384 => {
                let mut digest = Sha384::new();
                digest.input(input);
                digest.result(&mut output);
            }
            HashAlgorithm::SHA512 => {
                let mut digest = Sha512::new();
                digest.input(input);
                digest.result(&mut output);
            }
        }
        output
    }

    pub fn hkdf_expand(&self, prk: &[u8], info: &[u8],  okm: &mut [u8]) {
        match self {
            HashAlgorithm::SHA256 => hkdf_expand(Sha256::new(), prk, info, okm),
            HashAlgorithm::SHA384 => hkdf_expand(Sha384::new(), prk, info, okm),
            HashAlgorithm::SHA512 => hkdf_expand(Sha512::new(), prk, info, okm),
        }
    }

    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8], prk: &mut [u8]) {
        match self {
            HashAlgorithm::SHA256 => hkdf_extract(Sha256::new(), salt, ikm, prk),
            HashAlgorithm::SHA384 => hkdf_extract(Sha384::new(), salt, ikm, prk),
            HashAlgorithm::SHA512 => hkdf_extract(Sha512::new(), salt, ikm, prk),
        }
    }

    pub fn hmac_sign(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::SHA256 => Self::hmac_sign_digest(Sha256::new(), key, data).code().to_vec(),
            HashAlgorithm::SHA384 => Self::hmac_sign_digest(Sha384::new(), key, data).code().to_vec(),
            HashAlgorithm::SHA512 => Self::hmac_sign_digest(Sha512::new(), key, data).code().to_vec(),
        }
    }

    pub fn hmac_verify(&self, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        match self {
            HashAlgorithm::SHA256 => Self::hmac_verify_digest(Sha256::new(), key, data, expected),
            HashAlgorithm::SHA384 => Self::hmac_verify_digest(Sha384::new(), key, data, expected),
            HashAlgorithm::SHA512 => Self::hmac_verify_digest(Sha512::new(), key, data, expected),
        }
    }

    fn hmac_sign_digest<D : Digest>(digest: D, key: &[u8], data: &[u8]) -> MacResult {
        let mut hmac = Hmac::new(digest, key);
        hmac.input(data);
        hmac.result()
    }

    fn hmac_verify_digest<D : Digest>(digest: D, key: &[u8], data: &[u8], expected: &[u8]) -> bool {
        let actual_result = Self::hmac_sign_digest(digest, key, data);
        let expected_result = MacResult::new_from_owned(expected.to_vec());
        actual_result.eq(&expected_result) // constant-time comparison
    }
}
