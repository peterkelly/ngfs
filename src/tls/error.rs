use std::error::Error;
use std::fmt;
use crate::crypto::error::CryptError;
use super::types::alert::Alert;
use ring::error::KeyRejected;

#[derive(Debug, Clone)]
pub enum TLSError {
    EncryptionFailed,
    DecryptionFailed,
    MessageEncodingFailed,
    UnexpectedMessage(&'static str),
    UnexpectedEOF,
    UnexpectedAlert(Alert),
    InvalidPlaintextRecord,
    InvalidMessageRecord,
    Internal(CryptError),
    FinishedVerificationFailed,
    UnsupportedCipherSuite,
    UnsupportedSignatureScheme,
    VerifyCertificateFailed,
    VerifyTranscriptFailed,
    RsaKeyRejected(KeyRejected),
    SignatureFailed,
    SignatureVerificationFailed,
    InvalidCertificate,
    UnsupportedCertificateSignatureAlgorithm,
    RandomFillFailed,
    EphemeralPrivateKeyGenerationFailed,
    ComputePublicKeyFailed,
    GetSharedSecretFailed,
    EmptyCertificatList,
    MissingCertificateMessage,
    MissingCertificateVerifyMessage,
    CACertificateUnavailable,
    IOError(std::io::ErrorKind),
}

impl From<TLSError> for std::io::Error {
    fn from(e: TLSError) -> std::io::Error {
        match e {
            TLSError::IOError(kind) => std::io::Error::from(kind),
            TLSError::UnexpectedEOF => std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            _ => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
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
