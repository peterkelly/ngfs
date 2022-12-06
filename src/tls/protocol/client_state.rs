use super::super::types::handshake::{
    Handshake,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::error::TLSError;
use super::client::{HashAndHandshake, ServerMessages};

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
    pub fn check_finished(self) -> Result<ServerMessages, ClientState> {
        match self {
            ClientState::ReceivedFinished {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
                finished,
            } => Ok(ServerMessages {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
                finished,
            }),
            _ => Err(self)
        }
    }

    pub fn on_hash_and_handshake(self, hh: HashAndHandshake) -> Result<Self, TLSError> {
        use ClientState::*;
        use Handshake::*;
        match self {
            ReceivedServerHello => {
                match hh.handshake {
                    EncryptedExtensions(encrypted_extensions) => {
                        Ok(ReceivedEncryptedExtensions {
                            encrypted_extensions
                        })
                    }
                    _ => Err(TLSError::UnexpectedMessage(hh.handshake.name())),
                }
            }
            ReceivedEncryptedExtensions { encrypted_extensions } => {
                match hh.handshake {
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
                        certificate_verify: (v, hh.hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hh.hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(hh.handshake.name())),
                }
            }
            ReceivedCertificateRequest {
                encrypted_extensions,
                certificate_request,
            } => {
                match hh.handshake {
                    Certificate(certificate) => Ok(ReceivedCertificate {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate,
                    }),
                    CertificateVerify(v) => Ok(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: (v, hh.hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hh.hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(hh.handshake.name())),
                }
            }
            ReceivedCertificate {
                encrypted_extensions,
                certificate_request,
                certificate,
            } => {
                match hh.handshake {
                    CertificateVerify(v) => Ok(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: (v, hh.hash),
                    }),
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: None,
                        finished: (v, hh.hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(hh.handshake.name())),
                }
            }
            ReceivedCertificateVerify {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
            } => {
                match hh.handshake {
                    Finished(v) => Ok(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate,
                        certificate_verify: Some(certificate_verify),
                        finished: (v, hh.hash),
                    }),
                    _ => Err(TLSError::UnexpectedMessage(hh.handshake.name())),
                }
            }
            ReceivedFinished { .. } => {
                Err(TLSError::UnexpectedMessage(hh.handshake.name()))
            }
        }
    }
}
