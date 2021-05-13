use std::error::Error;
use std::fmt;
use super::super::crypt::CryptError;

#[derive(Debug)]
pub enum TLSError {
    EncryptionFailed,
    DecryptionFailed,
    InvalidPlaintextRecord,
    InvalidMessageRecord,
    Internal(CryptError),
    FinishedVerificationFailed,
    UnsupportedCipherSuite,
}

impl fmt::Display for TLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for TLSError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl From<CryptError> for TLSError {
    fn from(error: CryptError) -> Self {
        TLSError::Internal(error)
    }
}
