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
    ReceivedEncryptedExtensions(ReceivedEncryptedExtensions),
    ReceivedCertificateRequest(ReceivedCertificateRequest),
    ReceivedCertificate(ReceivedCertificate),
    ReceivedCertificateVerify(ReceivedCertificateVerify),
    ReceivedFinished(ReceivedFinished),
}

pub struct ReceivedEncryptedExtensions {
    pub encrypted_extensions: EncryptedExtensions,
}

pub struct ReceivedCertificateRequest {
    pub encrypted_extensions: EncryptedExtensions,
    pub certificate_request: CertificateRequest,
}

pub struct ReceivedCertificate {
    pub encrypted_extensions: EncryptedExtensions,
    pub certificate_request: Option<CertificateRequest>,
    pub certificate: Certificate,
}

pub struct ReceivedCertificateVerify {
    pub encrypted_extensions: EncryptedExtensions,
    pub certificate_request: Option<CertificateRequest>,
    pub certificate: Option<Certificate>,
    pub certificate_verify: (CertificateVerify, Vec<u8>),
}

pub struct ReceivedFinished {
    pub encrypted_extensions: EncryptedExtensions,
    pub certificate_request: Option<CertificateRequest>,
    pub certificate: Option<Certificate>,
    pub certificate_verify: Option<(CertificateVerify, Vec<u8>)>,
    pub finished: (Finished, Vec<u8>),
}

impl ClientState {
    pub fn on_hash_and_handshake(self, hash: Vec<u8>, handshake: Handshake) -> Result<Self, TLSError> {
        use Handshake::*;
        match self {
            ClientState::ReceivedServerHello => {
                match handshake {
                    EncryptedExtensions(encrypted_extensions) => {
                        Ok(ClientState::ReceivedEncryptedExtensions(ReceivedEncryptedExtensions {
                            encrypted_extensions
                        }))
                    }
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ClientState::ReceivedEncryptedExtensions(ReceivedEncryptedExtensions { encrypted_extensions }) => {
                match handshake {
                    CertificateRequest(certificate_request) =>
                        Ok(ClientState::ReceivedCertificateRequest(ReceivedCertificateRequest {
                        encrypted_extensions,
                        certificate_request,
                    })),
                    Certificate(certificate) => Ok(ClientState::ReceivedCertificate(ReceivedCertificate {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate,
                    })),
                    CertificateVerify(v) => Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate: None,
                        certificate_verify: (v, hash),
                    })),
                    Finished(v) => Ok(ClientState::ReceivedFinished(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: None,
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hash),
                    })),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ClientState::ReceivedCertificateRequest(ReceivedCertificateRequest {
                encrypted_extensions,
                certificate_request,
            }) => {
                match handshake {
                    Certificate(certificate) => Ok(ClientState::ReceivedCertificate(ReceivedCertificate {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate,
                    })),
                    CertificateVerify(v) => Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: (v, hash),
                    })),
                    Finished(v) => Ok(ClientState::ReceivedFinished(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request: Some(certificate_request),
                        certificate: None,
                        certificate_verify: None,
                        finished: (v, hash),
                    })),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ClientState::ReceivedCertificate(ReceivedCertificate {
                encrypted_extensions,
                certificate_request,
                certificate,
            }) => {
                match handshake {
                    CertificateVerify(v) => Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: (v, hash),
                    })),
                    Finished(v) => Ok(ClientState::ReceivedFinished(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate: Some(certificate),
                        certificate_verify: None,
                        finished: (v, hash),
                    })),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
            }) => {
                match handshake {
                    Finished(v) => Ok(ClientState::ReceivedFinished(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate,
                        certificate_verify: Some(certificate_verify),
                        finished: (v, hash),
                    })),
                    _ => Err(TLSError::UnexpectedMessage(handshake.name())),
                }
            }
            ClientState::ReceivedFinished { .. } => {
                Err(TLSError::UnexpectedMessage(handshake.name()))
            }
        }
    }
}
