#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use ring::agreement::EphemeralPrivateKey;
use super::super::helpers::{
    EncryptionKey,
    Ciphers,
    TrafficSecrets,
    get_server_hello_x25519_shared_secret,
    get_derived_prk,
    get_zero_prk,
    encrypt_traffic,
    decrypt_message,
    verify_finished,
    derive_secret,
};
use super::super::types::handshake::{
    Handshake,
    Certificate,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::types::extension::{
    Extension,
};
use super::super::types::record::{
    Message,
    ContentType,
    TLSPlaintext,
    TLSOutputPlaintext,
};
use super::super::error::{
    TLSError,
};
use super::super::super::util::{from_hex, vec_with_len, BinaryData, DebugHexDump, Indent};
use super::super::super::result::GeneralError;
use super::super::super::crypt::{HashAlgorithm, AeadAlgorithm};
use super::super::super::binary::{BinaryReader, BinaryWriter};

////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct ClientConn {
    pub to_send: Vec<u8>,
}

impl ClientConn {
    pub fn new() -> Self {
        ClientConn {
            to_send: Vec::new(),
        }
    }

    pub fn append_encrypted(
        &mut self,
        mut data: Vec<u8>,
        content_type: ContentType,
        traffic_secret: &EncryptionKey,
        client_sequence_no: u64,
    ) -> Result<(), TLSError> {
        data.push(content_type.to_raw());
        encrypt_traffic(
            traffic_secret,
            client_sequence_no,
            &mut data)?;

        let output_record = TLSOutputPlaintext {
            content_type: ContentType::ApplicationData,
            legacy_record_version: 0x0303,
            fragment: data,
        };
        self.to_send.extend_from_slice(&output_record.to_vec());
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

fn send_finished(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    new_transcript_hash: &[u8],
    conn: &mut ClientConn,
    sequence_no: u64,
) -> Result<(), Box<dyn Error>> {
    let finished_key: Vec<u8> = derive_secret(hash_alg, &encryption_key.raw, b"finished", &[])?;

    // println!("send_finished(): key = {:?}", BinaryData(&finished_key));
    // println!();
    // println!("send_finished(): handshake_hash = {:?}", BinaryData(&new_transcript_hash));

    let verify_data: Vec<u8> = hash_alg.hmac_sign(&finished_key, &new_transcript_hash)?;
    // println!("send_finished(): verify_data    = {:?}", BinaryData(&verify_data));

    let client_finished = Handshake::Finished(Finished { verify_data });

    let mut writer = BinaryWriter::new();
    writer.write_item(&client_finished)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    conn.append_encrypted(
        finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &encryption_key,        // traffic_secret
        sequence_no,            // sequence_no
    )?;

    Ok(())
}

pub struct PhaseTransition {
    pub phase: Phase,
    pub error: Option<Box<dyn Error>>,
}

impl PhaseTransition {
    pub fn ok(phase: Phase) -> Self {
        PhaseTransition {
            phase: phase,
            error: None,
        }
    }

    pub fn err(phase: Phase, error: Box<dyn Error>) -> Self {
        PhaseTransition {
            phase: phase,
            error: Some(error),
        }
    }
}

// Unencrypted data at start of handshake (ClientHello and ServerHello)
pub struct PhaseOne {
    pub transcript: Vec<u8>,
    pub my_private_key: Option<EphemeralPrivateKey>,
}

// Handshake once encryption established
pub struct PhaseTwo {
    pub ciphers: Ciphers,
    pub prk: Vec<u8>,
    pub transcript: Vec<u8>,
    pub handshake_secrets: TrafficSecrets,
    pub server_sequence_no: u64,

    pub encrypted_extensions: Option<Vec<Extension>>,
    pub server_certificate: Option<Certificate>,
    pub certificate_request: Option<CertificateRequest>,
    pub certificate_verify: Option<CertificateVerify>,
}

// Established
pub struct PhaseThree {
    pub ciphers: Ciphers,
    pub prk: Vec<u8>,
    pub application_secrets: TrafficSecrets,
    pub client_sequence_no: u64,
    pub server_sequence_no: u64,
}

pub enum Phase {
    One(PhaseOne),
    Two(PhaseTwo),
    Three(PhaseThree),
}

impl PhaseOne {
    fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        self.transcript.extend_from_slice(handshake_bytes);

        match handshake {
            Handshake::ServerHello(server_hello) => {
                println!("PhaseOne: Received ServerHello");
                println!("{:#?}", &Indent(&server_hello));
                let ciphers = match Ciphers::from_server_hello(server_hello) {
                    Ok(v) => v,
                    Err(e) => return PhaseTransition::err(Phase::One(self), e.into()),
                };

                let my_private_key2 = self.my_private_key.take().unwrap();
                let secret: &[u8] = &match get_server_hello_x25519_shared_secret(my_private_key2, &server_hello) {
                    Some(r) => r,
                    None => {
                        return PhaseTransition::err(Phase::One(self), GeneralError::new("Cannot get shared secret"));
                    }
                };
                println!("Shared secret = {}", BinaryData(&secret));

                let prk = match get_derived_prk(ciphers.hash_alg, &get_zero_prk(ciphers.hash_alg), secret) {
                    Ok(v) => v,
                    Err(e) => return PhaseTransition::err(Phase::One(self), e.into()),
                };

                println!("Got expected server hello");

                let hs = match TrafficSecrets::derive_from(&ciphers, &self.transcript, &prk, "hs") {
                    Ok(v) => v,
                    Err(e) => return PhaseTransition::err(Phase::One(self), e.into()),
                };
                println!("KEY CLIENT_HANDSHAKE_TRAFFIC_SECRET: {}", BinaryData(&hs.client.raw));
                println!("KEY SERVER_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&hs.server.raw));

                PhaseTransition::ok(Phase::Two(PhaseTwo {
                    ciphers,
                    prk,
                    transcript: self.transcript,
                    handshake_secrets: hs,
                    server_sequence_no: 0,
                    encrypted_extensions: None,
                    server_certificate: None,
                    certificate_request: None,
                    certificate_verify: None,
                }))
            }
            _ => {
                let msg = format!("PhaseOne: Received unexpected {}", handshake.name());
                PhaseTransition::err(Phase::One(self), GeneralError::new(msg))
            }
        }


    }

    fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {
        PhaseTransition::err(Phase::One(self), GeneralError::new("Received ApplicationData in PhaseOne"))
   }
}

impl PhaseTwo {
    fn decrypt_next_message(&mut self, plaintext_raw: &[u8]) -> Result<Message, Box<dyn Error>> {
        // TODO: Cater for alerts
        let (message, inner_body_vec) = decrypt_message(
            self.server_sequence_no,
            &self.handshake_secrets.server,
            plaintext_raw)?;
        self.server_sequence_no += 1;
        self.transcript.extend_from_slice(&inner_body_vec);
        Ok(message)
    }

    fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        PhaseTransition::err(Phase::Two(self), GeneralError::new("Received Handshake in PhaseTwo"))
    }

    fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {

        let old_thash: Vec<u8> = self.ciphers.hash_alg.hash(&self.transcript);
        let message = match self.decrypt_next_message(plaintext.raw) {
            Ok(v) => v,
            Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
        };
        let new_thash: Vec<u8> = self.ciphers.hash_alg.hash(&self.transcript);
        match message {
            Message::Handshake(Handshake::EncryptedExtensions(eex)) => {
                self.encrypted_extensions = Some(eex.extensions);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::CertificateRequest(creq)) => {
                self.certificate_request = Some(creq);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::Certificate(certificate)) => {
                self.server_certificate = Some(certificate);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::CertificateVerify(certificate_verify)) => {
                self.certificate_verify = Some(certificate_verify);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::Finished(finished)) => {
                let ciphers = &self.ciphers;
                let secrets = &self.handshake_secrets;

                println!("PhaseTwo: Received Handshake::Finished with {} bytes", finished.verify_data.len());
                println!("    encrypted_extensions   {}", self.encrypted_extensions.is_some());
                println!("    server_certificate     {}", self.server_certificate.is_some());
                println!("    certificate_request    {}", self.certificate_request.is_some());
                println!("    certificate_verify     {}", self.certificate_verify.is_some());


                let input_psk: &[u8] = &vec_with_len(ciphers.hash_alg.byte_len());
                let new_prk = match get_derived_prk(ciphers.hash_alg, &self.prk, input_psk) {
                    Ok(v) => v,
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                };

                let ap = match TrafficSecrets::derive_from(&ciphers, &self.transcript, &new_prk, "ap") {
                    Ok(v) => v,
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                };
                println!("        KEY CLIENT_TRAFFIC_SECRET_0: {}", BinaryData(&ap.client.raw));
                println!("        KEY SERVER_TRAFFIC_SECRET_0 = {}", BinaryData(&ap.server.raw));


                // let mut bad_finished = Finished { verify_data: finished.verify_data.clone() };
                // bad_finished.verify_data.push(0);
                match verify_finished(ciphers.hash_alg, &secrets.server, &old_thash, &finished) {
                    Ok(()) => (),
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                };

                // let mut bad_new_thash = new_thash.clone();
                // bad_new_thash.push(0);
                let client_sequence_no: u64 = 0;
                match send_finished(ciphers.hash_alg, &secrets.client, &new_thash, conn, client_sequence_no) {
                    Ok(()) => (),
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                };


                PhaseTransition::ok(Phase::Three(PhaseThree {
                    ciphers: self.ciphers,
                    prk: new_prk,
                    application_secrets: ap,
                    client_sequence_no: 0,
                    server_sequence_no: 0,
                }))
            }
            _ => {
                println!("PhaseTwo:  Ignore {}", message.name());
                PhaseTransition::ok(Phase::Two(self))

                // let msg = format!("PhaseTwo: Received unexpected {}", message.name());
                // PhaseTransition::err(Phase::Two(self), GeneralError::new(msg))
            }
        }
    }
}

impl PhaseThree {
    fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        PhaseTransition::err(Phase::Three(self), GeneralError::new("Received Handshake in PhaseThree"))
    }

    fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {
        println!("Established.application_data: server_sequence_no = {}", self.server_sequence_no);
        let decryption_key = &self.application_secrets.server;

        let (message, _) = match decrypt_message(
            self.server_sequence_no,
            &decryption_key,
            plaintext.raw) {
            Ok(v) => v,
            Err(e) => return PhaseTransition::err(Phase::Three(self), e.into()),
        };
        println!("Received message in Established state: {}", message.name());
        self.server_sequence_no += 1;

        match message {
            Message::Handshake(Handshake::NewSessionTicket(ticket)) => {
                println!("ticket = {:#?}", ticket);
                PhaseTransition::ok(Phase::Three(self))
            }
            Message::ApplicationData(data) => {
                println!("data =");
                println!("{:#?}", Indent(&DebugHexDump(&data)));
                PhaseTransition::ok(Phase::Three(self))
            }
            Message::Alert(alert) => {
                let msg = format!("PhaseThree: Received alert {:?}", alert);
                PhaseTransition::err(Phase::Three(self), GeneralError::new(msg))
            }
            _ => {
                let msg = format!("PhaseThree: Received unexpected {}", message.name());
                PhaseTransition::err(Phase::Three(self), GeneralError::new(msg))
            }
        }
    }
}

impl Phase {
    pub fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        match self {
            Phase::One(p) => p.handshake(handshake, handshake_bytes),
            Phase::Two(p) => p.handshake(handshake, handshake_bytes),
            Phase::Three(p) => p.handshake(handshake, handshake_bytes),
        }
    }

    pub fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {
        match self {
            Phase::One(p) => p.application_data(conn, plaintext),
            Phase::Two(p) => p.application_data(conn, plaintext),
            Phase::Three(p) => p.application_data(conn, plaintext),
        }
    }
}
