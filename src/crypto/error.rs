use std::fmt;
use std::error::Error;

#[derive(Debug, Eq, PartialEq, Clone)]
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
