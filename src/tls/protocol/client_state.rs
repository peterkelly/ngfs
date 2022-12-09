use super::super::types::handshake::{
    Handshake,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::error::TLSError;

pub enum ClientState {
    ReceivedServerHello,
    ReceivedEncryptedExtensions {
        encrypted_extensions: EncryptedExtensions,
    },
    ReceivedCertificateRequest {
        encrypted_extensions: EncryptedExtensions,
        certificate_request: CertificateRequest,
    },
    ReceivedCertificate {
        encrypted_extensions: EncryptedExtensions,
        certificate_request: Option<CertificateRequest>,
        certificate: Certificate,
    },
    ReceivedCertificateVerify {
        encrypted_extensions: EncryptedExtensions,
        certificate_request: Option<CertificateRequest>,
        certificate: Option<Certificate>,
        certificate_verify: (CertificateVerify, Vec<u8>),
    },
    ReceivedFinished {
        encrypted_extensions: EncryptedExtensions,
        certificate_request: Option<CertificateRequest>,
        certificate: Option<Certificate>,
        certificate_verify: Option<(CertificateVerify, Vec<u8>)>,
        finished: (Finished, Vec<u8>),
    },
}

impl ClientState {
    pub fn on_hash_and_handshake(self, hash: Vec<u8>, handshake: Handshake) -> Result<Self, TLSError> {
        use ClientState::*;
        use Handshake::*;
        match self {
            ReceivedServerHello => {
                match handshake {
                    EncryptedExtensions(encrypted_extensions) => {
                        Ok(ReceivedEncryptedExtensions {
                            encrypted_extensions
                        })
                    }
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ReceivedEncryptedExtensions { encrypted_extensions } => {
                match handshake {
                    CertificateRequest(certificate_request) => Ok(ReceivedCertificateRequest {
                        encrypted_extensions,
                        certificate_request,
                    }),
                    Certificate(certificate) => Ok(ReceivedCertificate {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate,
                    }),
                    CertificateVerify(v) => Ok(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate: None,
                        certificate_verify: (v, hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ReceivedCertificateRequest {
                encrypted_extensions,
                certificate_request,
            } => {
                match handshake {
                    Certificate(certificate) => Ok(ReceivedCertificate {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate,
                    }),
                    CertificateVerify(v) => Ok(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: (v, hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ReceivedCertificate {
                encrypted_extensions,
                certificate_request,
                certificate,
            } => {
                match handshake {
                    CertificateVerify(v) => Ok(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: (v, hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: None,
                        finished: (v, hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ReceivedCertificateVerify {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
            } => {
                match handshake {
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate,
                        certificate_verify: Some(certificate_verify),
                        finished: (v, hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ReceivedFinished { .. } => {
                Err(TLSError::UnexpectedMessage(handshake.name()))
            }
        }
    }
}
