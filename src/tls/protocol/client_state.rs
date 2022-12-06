// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]
// #![allow(non_upper_case_globals)]

use super::super::types::handshake::{
    Handshake,
    EncryptedExtensions,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::error::TLSError;
use super::client::HashAndHandshake;

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

pub enum ClientState {
    ReceivedServerHello,
    ReceivedEncryptedExtensions(ReceivedEncryptedExtensions),
    ReceivedCertificateRequest(ReceivedCertificateRequest),
    ReceivedCertificate(ReceivedCertificate),
    ReceivedCertificateVerify(ReceivedCertificateVerify),
    ReceivedFinished(ReceivedFinished),
}

impl ClientState {
    pub fn check_finished(self) -> Result<ReceivedFinished, ClientState> {
        match self {
            ClientState::ReceivedFinished(f) => Ok(f),
            _ => Err(self)
        }
    }

    pub fn on_hash_and_handshake(self, hh: HashAndHandshake) -> Result<Self, TLSError> {
        match self {
            ClientState::ReceivedServerHello => {
                match hh.handshake {
                    Handshake::EncryptedExtensions(encrypted_extensions) => {
                        Ok(ClientState::ReceivedEncryptedExtensions(ReceivedEncryptedExtensions {
                            encrypted_extensions
                        }))
                    }
                    _ => {
                        Err(TLSError::UnexpectedMessage(hh.handshake.name()))
                    }
                }
            }
            ClientState::ReceivedEncryptedExtensions(state) => {
                match hh.handshake {
                    Handshake::CertificateRequest(certificate_request) => {
                        Ok(ClientState::ReceivedCertificateRequest(ReceivedCertificateRequest {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request,
                        }))
                    }
                    Handshake::Certificate(certificate) => {
                        Ok(ClientState::ReceivedCertificate(ReceivedCertificate {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: None,
                            certificate,
                        }))
                    }
                    Handshake::CertificateVerify(v) => {
                        Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: None,
                            certificate: None,
                            certificate_verify: (v, hh.hash),
                        }))
                    }
                    Handshake::Finished(v) => {
                        Ok(ClientState::ReceivedFinished(ReceivedFinished {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: None,
                            certificate: None,
                            certificate_verify: None,
                            finished: (v, hh.hash),
                        }))
                    }
                    _ => {
                        Err(TLSError::UnexpectedMessage(hh.handshake.name()))
                    }
                }
            }
            ClientState::ReceivedCertificateRequest(state) => {
                match hh.handshake {
                    Handshake::Certificate(certificate) => {
                        Ok(ClientState::ReceivedCertificate(ReceivedCertificate {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: Some(state.certificate_request),
                            certificate,
                        }))
                    }
                    Handshake::CertificateVerify(v) => {
                        Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: Some(state.certificate_request),
                            certificate: None,
                            certificate_verify: (v, hh.hash),
                        }))
                    }
                    Handshake::Finished(v) => {
                        Ok(ClientState::ReceivedFinished(ReceivedFinished {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: Some(state.certificate_request),
                            certificate: None,
                            certificate_verify: None,
                            finished: (v, hh.hash),
                        }))
                    }
                    _ => {
                        Err(TLSError::UnexpectedMessage(hh.handshake.name()))
                    }
                }
            }
            ClientState::ReceivedCertificate(state) => {
                match hh.handshake {
                    Handshake::CertificateVerify(v) => {
                        Ok(ClientState::ReceivedCertificateVerify(ReceivedCertificateVerify {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: state.certificate_request,
                            certificate: Some(state.certificate),
                            certificate_verify: (v, hh.hash),
                        }))
                    }
                    Handshake::Finished(v) => {
                        Ok(ClientState::ReceivedFinished(ReceivedFinished {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: state.certificate_request,
                            certificate: Some(state.certificate),
                            certificate_verify: None,
                            finished: (v, hh.hash),
                        }))
                    }
                    _ => {
                        Err(TLSError::UnexpectedMessage(hh.handshake.name()))
                    }
                }
            }
            ClientState::ReceivedCertificateVerify(state) => {
                match hh.handshake {
                    Handshake::Finished(v) => {
                        Ok(ClientState::ReceivedFinished(ReceivedFinished {
                            encrypted_extensions: state.encrypted_extensions,
                            certificate_request: state.certificate_request,
                            certificate: state.certificate,
                            certificate_verify: Some(state.certificate_verify),
                            finished: (v, hh.hash),
                        }))
                    }
                    _ => {
                        Err(TLSError::UnexpectedMessage(hh.handshake.name()))
                    }
                }
            }
            ClientState::ReceivedFinished(_) => {
                Err(TLSError::UnexpectedMessage(hh.handshake.name()))
            }
        }
    }
}
