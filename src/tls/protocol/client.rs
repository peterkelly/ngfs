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
    rsa_sign,
    rsa_verify,
};
use super::super::types::handshake::{
    Handshake,
    Certificate,
    CertificateEntry,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::types::extension::{
    Extension,
    SignatureScheme,
};
use super::super::types::record::{
    Message,
    ContentType,
    TLSPlaintext,
    TLSOutputPlaintext,
};
use super::super::types::alert::{
    Alert,
};
use super::super::error::{
    TLSError,
};
use super::super::super::util::{from_hex, vec_with_len, BinaryData, DebugHexDump, Indent};
use super::super::super::result::GeneralError;
use super::super::super::crypt::{HashAlgorithm, AeadAlgorithm};
use super::super::super::binary::{BinaryReader, BinaryWriter};
use super::super::super::asn1;
use super::super::super::x509;

pub enum ServerAuth {
    None,
    CertificateAuthority(Vec<u8>),
}

pub enum ClientAuth {
    None,
    Certificate { cert: Vec<u8>, key: Vec<u8> },
}

pub struct ClientConfig {
    pub client_auth: ClientAuth,
    pub server_auth: ServerAuth,
}

////////////////////////////////////////////////////////////////////////////////////////////////////

struct ClientConn {
    to_send: Vec<u8>,
}

impl ClientConn {
    fn new() -> Self {
        ClientConn {
            to_send: Vec::new(),
        }
    }

    fn append_encrypted(
        &mut self,
        mut data: Vec<u8>,
        content_type: ContentType,
        traffic_secret: &EncryptionKey,
        client_sequence_no: u64,
        transcript: Option<&mut Vec<u8>>,
    ) -> Result<(), TLSError> {
        match transcript {
            Some(transcript) => transcript.extend_from_slice(&data),
            None => (),
        }
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
        let output_record_bytes = output_record.to_vec();
        // match transcript {
        //     Some(transcript) => transcript.extend_from_slice(&output_record_bytes),
        //     None => (),
        // }
        self.to_send.extend_from_slice(&output_record_bytes);
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

enum Endpoint {
    Client,
    Server,
}

fn send_finished(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    new_transcript_hash: &[u8],
    conn: &mut ClientConn,
    sequence_no: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let finished_key = derive_secret(hash_alg, &encryption_key.raw, b"finished", &[])?;
    let verify_data = hash_alg.hmac_sign(&finished_key, &new_transcript_hash)?;
    let client_finished = Handshake::Finished(Finished { verify_data });
    send_handshake(encryption_key, conn, *sequence_no, &client_finished, None)?;
    *sequence_no += 1;
    Ok(())
}

fn send_client_certificate(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    conn: &mut ClientConn,
    sequence_no: &mut u64,
    transcript: &mut Vec<u8>,
    client_cert_data: &[u8],
    client_key_data: &[u8],
    signature_scheme: SignatureScheme,
    rng: &dyn ring::rand::SecureRandom,
) -> Result<(), Box<dyn Error>> {
    let client_cert = x509::Certificate::from_bytes(client_cert_data)?;
    let handshake = Handshake::Certificate(Certificate {
        certificate_request_context: Vec::new(),
        certificate_list: vec![
            CertificateEntry {
                data: Vec::from(client_cert_data),
                certificate: client_cert,
                extensions: vec![],
            }
        ],
    });


    println!("old transcript len = {}", transcript.len());
    send_handshake(encryption_key, conn, *sequence_no, &handshake, Some(transcript))?;
    println!("new transcript len = {}", transcript.len());
    *sequence_no += 1;

    let thash: Vec<u8> = hash_alg.hash(transcript);

    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);

    let signature = rsa_sign(client_key_data, &verify_input, signature_scheme, rng)?;


    let handshake = Handshake::CertificateVerify(CertificateVerify {
        algorithm: signature_scheme,
        signature: signature,
    });
    send_handshake(encryption_key, conn, *sequence_no, &handshake, Some(transcript))?;
    *sequence_no += 1;

    Ok(())
}

fn send_handshake(
    encryption_key: &EncryptionKey,
    conn: &mut ClientConn,
    sequence_no: u64,
    handshake: &Handshake,
    transcript: Option<&mut Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    conn.append_encrypted(
        finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &encryption_key,        // traffic_secret
        sequence_no,            // sequence_no
        transcript,
    )?;

    Ok(())
}

fn verify_certificate(ca_raw: &[u8], target_raw: &[u8]) -> Result<(), TLSError> {
    let ca_cert = x509::Certificate::from_bytes(&ca_raw).map_err(|_| TLSError::InvalidCertificate)?;

    let mut target_reader = BinaryReader::new(&target_raw);
    let target_item = asn1::reader::read_item(&mut target_reader).map_err(|_| TLSError::InvalidCertificate)?;
    let elements = target_item.as_exact_sequence(3).map_err(|_| TLSError::InvalidCertificate)?;

    let tbs_certificate = x509::TBSCertificate::from_asn1(&elements[0]).map_err(|_| TLSError::InvalidCertificate)?;
    let signature_algorithm = x509::AlgorithmIdentifier::from_asn1(&elements[1]).map_err(|_| TLSError::InvalidCertificate)?;
    let signature_value_bit_string = elements[2].as_bit_string().map_err(|_| TLSError::InvalidCertificate)?;
    let signature = &signature_value_bit_string.bytes;

    let rsa_parameters: &ring::signature::RsaParameters;
    if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_256_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_384_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA384;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_512_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA512;
    }
    else {
        return Err(TLSError::UnsupportedCertificateSignatureAlgorithm);
    }

    let ca_public_key_info = &ca_cert.tbs_certificate.subject_public_key_info;
    let ca_public_key = ring::signature::UnparsedPublicKey::new(
        rsa_parameters,
        &ca_public_key_info.subject_public_key.bytes);
    let tbs_data = &target_raw[elements[0].range.clone()];
    ca_public_key.verify(tbs_data, signature).map_err(|_| TLSError::VerifyCertificateFailed)?;

    Ok(())
}

fn verify_transcript_opt(
    certificate_verify: &Option<CertificateVerify>,
    certificate_verify_thash: &Option<Vec<u8>>,
    public_key: &x509::SubjectPublicKeyInfo,
    endpoint: Endpoint,
) -> Result<(), Box<dyn Error>> {
    let certificate_verify: &CertificateVerify = match certificate_verify {
        Some(v) => v,
        None => {
            return Err(GeneralError::new("Server did not send CertificateVerify"));
        }
    };
    let certificate_verify_thash: &[u8] = match certificate_verify_thash {
        Some(v) => v,
        None => {
            return Err(GeneralError::new("Server did not send CertificateVerify thash"));
        }
    };

    verify_transcript(certificate_verify, certificate_verify_thash, public_key, endpoint)?;
    Ok(())
}

fn make_verify_transcript_input(endpoint: Endpoint, thash: &[u8]) -> Vec<u8> {
    let mut verify_input: Vec<u8> = Vec::new();
    for _ in 0..64 {
        verify_input.push(0x20);
    }
    let context_string = match endpoint {
        Endpoint::Client => b"TLS 1.3, client CertificateVerify",
        Endpoint::Server => b"TLS 1.3, server CertificateVerify",
    };
    verify_input.extend_from_slice(context_string);
    verify_input.push(0);
    verify_input.extend_from_slice(thash);
    verify_input
}

fn verify_transcript(
    certificate_verify: &CertificateVerify,
    certificate_verify_thash: &[u8],
    public_key: &x509::SubjectPublicKeyInfo,
    endpoint: Endpoint,
) -> Result<(), TLSError> {
    let verify_input = make_verify_transcript_input(endpoint, certificate_verify_thash);
    rsa_verify(
        certificate_verify.algorithm,
        &public_key.subject_public_key.bytes,
        &verify_input,
        &certificate_verify.signature
    )
}

struct PhaseTransition {
    phase: Phase,
    error: Option<Box<dyn Error>>,
}

impl PhaseTransition {
    fn ok(phase: Phase) -> Self {
        PhaseTransition {
            phase: phase,
            error: None,
        }
    }

    fn err(phase: Phase, error: Box<dyn Error>) -> Self {
        PhaseTransition {
            phase: phase,
            error: Some(error),
        }
    }
}

// Unencrypted data at start of handshake (ClientHello and ServerHello)
struct PhaseOne {
    transcript: Vec<u8>,
    my_private_key: Option<EphemeralPrivateKey>,
    config: ClientConfig,
}

// Handshake once encryption established
struct PhaseTwo {
    ciphers: Ciphers,
    prk: Vec<u8>,
    transcript: Vec<u8>,
    handshake_secrets: TrafficSecrets,
    server_sequence_no: u64,
    config: ClientConfig,

    encrypted_extensions: Option<Vec<Extension>>,
    server_certificate: Option<Certificate>,
    certificate_request: Option<CertificateRequest>,
    certificate_verify: Option<CertificateVerify>,
    certificate_verify_thash: Option<Vec<u8>>,
}

// Established
struct PhaseThree {
    ciphers: Ciphers,
    prk: Vec<u8>,
    application_secrets: TrafficSecrets,
    client_sequence_no: u64,
    server_sequence_no: u64,
}

enum Phase {
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
                    config: self.config,
                    encrypted_extensions: None,
                    server_certificate: None,
                    certificate_request: None,
                    certificate_verify: None,
                    certificate_verify_thash: None,
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
    fn decrypt_next_message(&mut self, plaintext_raw: &[u8]) -> Result<(Message, Vec<u8>), Box<dyn Error>> {
        // TODO: Cater for alerts
        let (message, inner_body_vec) = decrypt_message(
            self.server_sequence_no,
            &self.handshake_secrets.server,
            plaintext_raw)?;
        self.server_sequence_no += 1;
        self.transcript.extend_from_slice(&inner_body_vec);
        Ok((message, inner_body_vec))
    }

    fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        PhaseTransition::err(Phase::Two(self), GeneralError::new("Received Handshake in PhaseTwo"))
    }

    fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {

        let old_thash: Vec<u8> = self.ciphers.hash_alg.hash(&self.transcript);
        let (message, message_raw) = match self.decrypt_next_message(plaintext.raw) {
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
                // println!("PhaseTwo: Received CertificateRequest");
                println!("{:#?}", &Indent(&creq));
                self.certificate_request = Some(creq);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::Certificate(certificate)) => {
                // println!("PhaseTwo: Received Certificate");
                println!("{:#?}", &Indent(&certificate));
                for entry in certificate.certificate_list.iter() {
                    let mut registry = asn1::printer::ObjectRegistry::new();
                    x509::populate_registry(&mut registry);
                    x509::print_certificate(&registry, &entry.certificate);
                }
                self.server_certificate = Some(certificate);
                PhaseTransition::ok(Phase::Two(self))
            }
            Message::Handshake(Handshake::CertificateVerify(certificate_verify)) => {
                // println!("PhaseTwo: Received CertificateVerify");
                // println!("    algorithm = {:?}", certificate_verify.algorithm);
                // println!("    signature = <{} bytes>", certificate_verify.signature.len());
                self.certificate_verify = Some(certificate_verify);
                self.certificate_verify_thash = Some(old_thash.clone());
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

                let first_cert_entry : &CertificateEntry =
                match &self.server_certificate {
                    Some(server_certificate) => {
                        match server_certificate.certificate_list.get(0) {
                            Some(v) => v,
                            None => {
                                let e = GeneralError::new("Server sent an empty certificate list");
                                return PhaseTransition::err(Phase::Two(self), e.into());
                            }
                        }
                    }
                    None => {
                        let e = GeneralError::new("Server did not send certificate");
                        return PhaseTransition::err(Phase::Two(self), e.into());
                    }
                };

                let server_cert_raw: &[u8] = &first_cert_entry.data;
                let server_cert: &x509::Certificate = &first_cert_entry.certificate;

                let ca_cert: &[u8] = match &self.config.server_auth {
                    ServerAuth::CertificateAuthority(v) => v,
                    ServerAuth::None => {
                        let e = GeneralError::new("No CA certificate available");
                        return PhaseTransition::err(Phase::Two(self), e.into());
                    }
                };

                match verify_certificate(ca_cert, &server_cert_raw) {
                    Ok(()) => (),
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                }


                match verify_transcript_opt(
                    &self.certificate_verify,
                    &self.certificate_verify_thash,
                    &server_cert.tbs_certificate.subject_public_key_info,
                    Endpoint::Server
                ) {
                    Ok(()) => (),
                    Err(e) => return PhaseTransition::err(Phase::Two(self), e.into()),
                };


                let mut client_sequence_no: u64 = 0;

                // FIXME: Don't hard-code SignatureScheme
                match &self.config.client_auth {
                    ClientAuth::Certificate { cert, key } => {
                        let client_cert = cert;
                        let client_key = key;

                        let rng = ring::rand::SystemRandom::new();
                        match send_client_certificate(
                            ciphers.hash_alg, // hash_alg: HashAlgorithm,
                            &secrets.client, // encryption_key: &EncryptionKey,
                            conn, // conn: &mut ClientConn,
                            &mut client_sequence_no, // sequence_no: &mut u64,
                            &mut self.transcript, // transcript: &mut Vec<u8>,
                            client_cert, // client_cert_data: &[u8],
                            client_key, // client_key_data: &[u8],
                            SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                            &rng,
                        ) {
                            Ok(()) => {
                                println!("Sending client certificate succeeded");
                            }
                            Err(e) => {
                                println!("Sending client certificate failed: {}", e);
                                return PhaseTransition::err(Phase::Two(self), e.into());
                            }
                        }

                    }
                    ClientAuth::None => {
                    }
                }

                let new_thash: Vec<u8> = self.ciphers.hash_alg.hash(&self.transcript);

                // let mut bad_new_thash = new_thash.clone();
                // bad_new_thash.push(0);
                match send_finished(ciphers.hash_alg, &secrets.client, &new_thash, conn, &mut client_sequence_no) {
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
    fn handshake(mut self, handshake: &Handshake, handshake_bytes: &[u8]) -> PhaseTransition {
        match self {
            Phase::One(p) => p.handshake(handshake, handshake_bytes),
            Phase::Two(p) => p.handshake(handshake, handshake_bytes),
            Phase::Three(p) => p.handshake(handshake, handshake_bytes),
        }
    }

    fn application_data(mut self, conn: &mut ClientConn, plaintext: TLSPlaintext) -> PhaseTransition {
        match self {
            Phase::One(p) => p.application_data(conn, plaintext),
            Phase::Two(p) => p.application_data(conn, plaintext),
            Phase::Three(p) => p.application_data(conn, plaintext),
        }
    }
}

pub struct Client {
    received_alert: Option<Alert>,
    phase: Option<Phase>,
}

impl Client {
    pub fn new(my_private_key: EphemeralPrivateKey, config: ClientConfig) -> Self {
        Client {
            received_alert: None,
            phase: Some(Phase::One(PhaseOne {
                transcript: Vec::new(),
                my_private_key: Some(my_private_key),
                config: config,
            })),
        }
    }

    fn handshake(&mut self,
                 conn: &mut ClientConn,
                 plaintext: TLSPlaintext) -> Result<(), Box<dyn Error>> {
        // println!("Handshake record");
        let mut reader = BinaryReader::new(plaintext.fragment);
        while reader.remaining() > 0 {
            let old_offset = reader.abs_offset();
            let server_handshake = reader.read_item::<Handshake>()?;
            let new_offset = reader.abs_offset();
            let handshake_bytes: &[u8] = &plaintext.fragment[old_offset..new_offset];
            self.handshake_one(conn, &server_handshake, handshake_bytes)?;
        }
        Ok(())
    }

    fn handshake_one(
        &mut self,
        conn: &mut ClientConn,
        handshake: &Handshake,
        handshake_bytes: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let phase = self.phase.take();
        match phase {
            Some(phase) => {
                let transition = phase.handshake(handshake, handshake_bytes);
                self.phase = Some(transition.phase);
                match transition.error {
                    Some(e) => Err(e),
                    None => Ok(())
                }
            }
            None => {
                Err(GeneralError::new("phase is None"))
            }
        }
    }

    fn application_data(
        &mut self,
        conn: &mut ClientConn,
        plaintext: TLSPlaintext,
    ) -> Result<(), Box<dyn Error>> {
        let phase = self.phase.take();
        match phase {
            Some(phase) => {
                let transition = phase.application_data(conn, plaintext);
                self.phase = Some(transition.phase);
                match transition.error {
                    Some(e) => Err(e),
                    None => Ok(())
                }
            }
            None => {
                Err(GeneralError::new("phase is None"))
            }
        }
    }

    pub fn process_record(
        &mut self,
        outgoing_data: &mut Vec<u8>,
        plaintext: TLSPlaintext,
    ) -> Result<(), Box<dyn Error>> {
        let mut conn = ClientConn::new();
        match plaintext.content_type {
            ContentType::Handshake => self.handshake(&mut conn, plaintext)?,
            ContentType::ApplicationData => self.application_data(&mut conn, plaintext)?,
            ContentType::Invalid => {
                println!("Unsupported record type: Invalid");
            }
            ContentType::ChangeCipherSpec => {
                println!("ChangeCipherSpec record: Ignoring");
            }
            ContentType::Alert => {
                // TODO: Have this function passed a *complete* plaintext data, even if the alert data
                // is spread over multiple plaintext records
                let mut reader = BinaryReader::new(plaintext.fragment);
                let alert = reader.read_item::<Alert>()?;
                println!("Received alert: {:?}", alert);
                self.received_alert = Some(alert);
            }
            ContentType::Unknown(code) => {
                println!("Unsupported record type: {}", code);
            }
        }
        outgoing_data.extend_from_slice(&conn.to_send);
        Ok(())
    }

    pub fn write_client_hello(&mut self, handshake: &Handshake, output: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match &mut self.phase {
            Some(Phase::One(phase)) => {
                let record = handshake_to_record(&handshake)?;
                phase.transcript.extend_from_slice(&record.fragment);
                self.write_plaintext_record(&record, output)?;
                Ok(())
            }
            _ => {
                Err(GeneralError::new("Attempt to write ClientHello when not in Phase::One"))
            }
        }
    }

    pub fn write_plaintext_record(&mut self, record: &TLSOutputPlaintext,
                                  output: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match &mut self.phase {
            Some(Phase::One(_)) => {
                output.extend_from_slice(&record.to_vec());
                Ok(())
            }
            None => {
                println!("write_plaintext: phase = None");
                Err(GeneralError::new("client.phase is None"))
            }
            _ => {
                println!("write_plaintext: phase = Other");
                Err(GeneralError::new("Session is not yet established"))
            }
        }
    }

    pub fn write_plaintext(&mut self, data: &[u8], outgoing_data: &mut Vec<u8>) -> Result<(), Box<dyn Error>> {
        match &mut self.phase {
            Some(Phase::Three(phase)) => {
                println!("write_plaintext: phase = Three (Established)");
                let mut conn = ClientConn::new();
                conn.append_encrypted(
                    data.to_vec(),
                    ContentType::ApplicationData,
                    &phase.application_secrets.client,
                    phase.client_sequence_no,
                    None,
                )?;
                phase.client_sequence_no += 1;
                println!("write_plaintext: conn.to_send.len() = {}", conn.to_send.len());
                outgoing_data.extend_from_slice(&conn.to_send);
                Ok(())
            }
            None => {
                println!("write_plaintext: phase = None");
                Err(GeneralError::new("client.phase is None"))
            }
            _ => {
                println!("write_plaintext: phase = Other");
                Err(GeneralError::new("Session is not yet established"))
            }
        }
    }

    pub fn is_established(&self) -> bool {
        match &self.phase {
            Some(Phase::Three(_)) => true,
            _ => false,
        }
    }
}

fn handshake_to_record(handshake: &Handshake) -> Result<TLSOutputPlaintext, Box<dyn Error>> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;

    let output_record = TLSOutputPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };
    Ok(output_record)
}
