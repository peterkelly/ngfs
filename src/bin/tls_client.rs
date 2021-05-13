#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::fmt;
use tokio::net::{TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::sleep;
use std::time::Duration;
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::SystemRandom;
use torrent::result::GeneralError;
use torrent::util::{from_hex, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, BinaryWriter};
use torrent::crypt::{HashAlgorithm, AeadAlgorithm};
use torrent::tls::error::TLSError;
use torrent::tls::types::handshake::{
    CipherSuite,
    Handshake,
    ClientHello,
    ServerHello,
    Finished,
    Certificate,
    CertificateRequest,
    CertificateVerify,
};
use torrent::tls::types::extension::{
    ECPointFormat,
    NamedCurve,
    Extension,
    SignatureScheme,
    PskKeyExchangeMode,
    NamedGroup,
    ServerName,
    ProtocolName,
    KeyShareEntry,
};
use torrent::tls::types::record::{
    ContentType,
    Message,
    TLSPlaintext,
    TLSOutputPlaintext,
    TLSPlaintextError,
};
use torrent::tls::types::alert::{
    Alert,
};
use torrent::tls::helpers::{
    EncryptionKey,
    Ciphers,
    TrafficSecrets,
    derive_secret,
    get_server_hello_x25519_shared_secret,
    get_zero_prk,
    get_derived_prk,
    encrypt_traffic,
    decrypt_message,
    verify_finished,
};

fn make_client_hello(my_public_key_bytes: &[u8]) -> ClientHello {
    let random = from_hex("1a87a2e2f77536fcfa071500af3c7dffa5830e6c61214e2dee7623c2b925aed8").unwrap();
    let session_id = from_hex("7d954b019486e0dffaa7769a4b9d27d796eaee44b710f18d630f3292b6dc7560").unwrap();
    println!("random.len() = {}", random.len());
    println!("session_id.len() = {}", session_id.len());
    assert!(random.len() == 32);
    assert!(session_id.len() == 32);

    let mut random_fixed: [u8; 32] = Default::default();
    random_fixed.copy_from_slice(&random);

    let mut cipher_suites = Vec::<CipherSuite>::new();
    cipher_suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
    cipher_suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
    // cipher_suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    cipher_suites.push(CipherSuite::Unknown(0x00ff));

    let extensions = vec![
        Extension::ServerName(vec![ServerName::HostName(String::from("localhost"))]),
        Extension::ECPointFormats(vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedPrime,
            ECPointFormat::ANSIX962CompressedChar2]),
        Extension::SupportedGroups(vec![
            NamedCurve::X25519,
            NamedCurve::Secp256r1,
            NamedCurve::X448,
            NamedCurve::Secp521r1,
            NamedCurve::Secp384r1]),
        Extension::NextProtocolNegotiation(vec![]),
        Extension::ApplicationLayerProtocolNegotiation(vec![
            ProtocolName { data: Vec::from("h2".as_bytes()) },
            ProtocolName { data: Vec::from("http/1.1".as_bytes()) },
            ]),
        Extension::EncryptThenMac,
        Extension::ExtendedMasterSecret,
        Extension::PostHandshakeAuth,
        Extension::SignatureAlgorithms(vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::Ed25519,
            SignatureScheme::Ed448,
            SignatureScheme::RsaPssPssSha256,
            SignatureScheme::RsaPssPssSha384,
            SignatureScheme::RsaPssPssSha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512]),
        Extension::SupportedVersions(vec![2, 3, 4]),
        Extension::PskKeyExchangeModes(vec![PskKeyExchangeMode::PskDheKe]),
        Extension::KeyShareClientHello(vec![
            KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: Vec::from(my_public_key_bytes),
            }])
    ];

    ClientHello {
        legacy_version: 0x0303,
        random: random_fixed,
        legacy_session_id: session_id,
        cipher_suites: cipher_suites,
        legacy_compression_methods: vec![0],
        extensions: extensions,
    }
}

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
}

// Handshake once encryption established
struct PhaseTwo {
    ciphers: Ciphers,
    prk: Vec<u8>,
    transcript: Vec<u8>,
    handshake_secrets: TrafficSecrets,
    server_sequence_no: u64,

    encrypted_extensions: Option<Vec<Extension>>,
    server_certificate: Option<Certificate>,
    certificate_request: Option<CertificateRequest>,
    certificate_verify: Option<CertificateVerify>,
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

    async fn send_pending_data(&mut self, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        if self.to_send.len() > 0 {
            socket.write_all(&self.to_send).await?;
            println!("Sent {} bytes", self.to_send.len());
            self.to_send.clear();
        }
        Ok(())
    }
}

struct Client {
    received_alert: Option<Alert>,
    phase: Option<Phase>,
}

impl Client {
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

    fn process_record(
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
}

struct Session {
    client: Client,
    incoming_data: Vec<u8>,
    outgoing_data: Vec<u8>,
    read_closed: bool,
    write_closed: bool,
    error: Option<String>,
}

impl Session {
    pub fn new(client: Client) -> Self {
        Session {
            client: client,
            incoming_data: Vec::new(),
            outgoing_data: Vec::new(),
            // wants_read: true,
            // wants_write: true,
            read_closed: false,
            write_closed: false,
            error: None,
        }
    }

    pub fn write_client_hello(&mut self, handshake: &Handshake) -> Result<(), Box<dyn Error>> {
        match &mut self.client.phase {
            Some(Phase::One(phase)) => {
                let client_hello_plaintext_record: TLSOutputPlaintext = handshake_to_record(&handshake)?;

                let my_private_key: EphemeralPrivateKey = match phase.my_private_key.take() {
                    Some(v) => v,
                    None => {
                        return Err(GeneralError::new("my_private_key is None"));
                    }
                };


                // let client_hello_plaintext_record_bytes: Vec<u8> = client_hello_plaintext_record.to_vec();
                // self.outgoing_data.extend_from_slice(&client_hello_plaintext_record_bytes);

                // let mut transcript: Vec<u8> = start.transcript.clone();
                // transcript.extend_from_slice(&client_hello_plaintext_record.fragment);

                let mut transcript: Vec<u8> = phase.transcript.clone();
                transcript.extend_from_slice(&client_hello_plaintext_record.fragment);

                self.write_plaintext_record(&client_hello_plaintext_record)?;



                self.client.phase = Some(Phase::One(PhaseOne {
                    my_private_key: Some(my_private_key),
                    transcript: transcript,
                }));

                // let mut initial_transcript: Vec<u8> = Vec::new();
                // initial_transcript.extend_from_slice(&client_hello_bytes);

                Ok(())
            }
            _ => {
                Err(GeneralError::new("Attempt to write ClientHello when not in Phase::One"))
            }
        }
    }

    pub fn write_plaintext_record(&mut self, client_hello_plaintext_record: &TLSOutputPlaintext) -> Result<(), Box<dyn Error>> {
        match &mut self.client.phase {
            Some(Phase::One(_)) => {
                let client_hello_plaintext_record_bytes: Vec<u8> = client_hello_plaintext_record.to_vec();
                self.outgoing_data.extend_from_slice(&client_hello_plaintext_record_bytes);
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

    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match &self.error {
            Some(_) => return Err(GeneralError::new("Session is dead")),
            None => (),
        };
        match &mut self.client.phase {
            Some(Phase::Three(phase)) => {
                println!("write_plaintext: phase = Three (Established)");
                let mut conn = ClientConn::new();
                conn.append_encrypted(
                    data.to_vec(),
                    ContentType::ApplicationData,
                    &phase.application_secrets.client,
                    phase.client_sequence_no,
                )?;
                phase.client_sequence_no += 1;
                println!("write_plaintext: conn.to_send.len() = {}", conn.to_send.len());
                self.outgoing_data.extend_from_slice(&conn.to_send);
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

    pub fn add_incoming_data(&mut self, data: &[u8]) {
        self.incoming_data.extend_from_slice(data);
    }

    pub fn remove_outgoing_data(&mut self) -> Vec<u8> {
        self.outgoing_data.split_off(0)
    }

    pub fn report_error(&mut self, error: &str) {
        println!("Session::report_error: {}", error);
        self.error = Some(String::from(error));
        self.read_closed = true;
        self.write_closed = true;
    }

    pub fn process(&mut self) {
        loop {
            match TLSPlaintext::from_raw_data(&self.incoming_data) {
                Err(TLSPlaintextError::InsufficientData) => {
                    return;
                }
                Err(TLSPlaintextError::InvalidLength) => {
                    self.report_error("Invalid record length");
                    return;
                }
                Ok(record) => {
                    let to_remove = record.raw.len();
                    match self.client.process_record(&mut self.outgoing_data, record) {
                        Ok(()) => (),
                        Err(e) => {
                            self.report_error(&format!("{}", e));
                            break;
                        }
                    }
                    self.incoming_data = self.incoming_data.split_off(to_remove);
                }
            }
        }
    }

    fn on_read_end(&mut self) {
        self.read_closed = true;
        self.process();
    }

    fn on_read_data(&mut self, data: &[u8]) {
        self.add_incoming_data(data);
        self.process();
    }

    fn on_read_error(&mut self, e: &std::io::Error) {
        self.report_error(&format!("read from underlying transport: {}", e));
        self.process();
    }

    fn on_write_error(&mut self, e: &std::io::Error) {
        self.report_error(&format!("read from underlying transport: {}", e));
        self.process();
    }
}

struct Connection {
    session: Mutex<Session>,
    read_not: Notify,
    write_not: Notify,
    debug: bool,
    established_not: Notify,
}

impl Connection {
    fn new(session: Session) -> Self {
        Connection {
            session: Mutex::new(session),
            read_not: Notify::new(),
            write_not: Notify::new(),
            debug: false,
            established_not: Notify::new(),
        }
    }

    async fn write_client_hello(&self, handshake: &Handshake) -> Result<(), Box<dyn Error>> {
        self.session.lock().unwrap().write_client_hello(handshake)?;
        self.read_not.notify_one();
        self.write_not.notify_one();
        Ok(())
    }

    async fn wait_till_established(&self) -> Result<(), Box<dyn Error>> {
        self.established_not.notified().await;
        match &self.session.lock().unwrap().error {
            Some(s) => Err(GeneralError::new(s)),
            None => Ok(())
        }
    }

    async fn write_plaintext(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.session.lock().unwrap().write_plaintext(data)?;
        println!("write_plaintext: now outgoing_data.len() = {}",
            self.session.lock().unwrap().outgoing_data.len());
        self.read_not.notify_one();
        self.write_not.notify_one();
        Ok(())
    }

    async fn write_plaintext_string(&self, data: &str) -> Result<(), Box<dyn Error>> {
        self.write_plaintext(data.as_bytes()).await
    }

    fn check_events(&self) {
        let established = match self.session.lock().unwrap().client.phase {
            Some(Phase::Three(_)) => true,
            _ => false,
        };
        if established || self.had_error() {
            // FIXME: Do this only once, not on every call
            // println!("Notifying that session has been established");
            self.established_not.notify_one();
        }
    }

    fn on_read_end(&self) {
        self.session.lock().unwrap().on_read_end();
        self.check_events();
    }

    fn on_read_data(&self, data: &[u8]) {
        self.session.lock().unwrap().on_read_data(data);
        self.check_events();
    }

    fn on_read_error(&self, e: &std::io::Error) {
        self.session.lock().unwrap().on_read_error(e);
        self.check_events();
    }

    fn on_write_error(&self, e: &std::io::Error) {
        self.session.lock().unwrap().on_write_error(e);
        self.check_events();
    }

    fn had_error(&self) -> bool {
        match self.session.lock().unwrap().error {
            Some(_) => true,
            None => false,
        }
    }

    pub fn remove_outgoing_data(&self) -> Vec<u8> {
        let res = self.session.lock().unwrap().remove_outgoing_data();
        self.check_events();
        res
    }
}

async fn read_loop(conn: Arc<Connection>, reader: &mut (dyn AsyncRead + Unpin + Send)) {
    const READ_SIZE: usize = 1024;
    loop {
        let wants_read = true;
        if wants_read {
            let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
            match reader.read(&mut buf).await {
                Ok(0) => {
                    if conn.debug { println!("read_loop: end") }
                    conn.on_read_end();
                    return;
                }
                Ok(r) => {
                    if conn.debug { println!("read_loop: read {} bytes", r) }
                    conn.on_read_data(&buf[0..r]);
                }
                Err(e) => {
                    if conn.debug { println!("read_loop: error {}", e) }
                    conn.on_read_error(&e);
                    break;
                }
            }
        }
        if conn.had_error() {
            break;
        }

        conn.write_not.notify_one();
        conn.read_not.notified().await;
    }
}

async fn write_loop(conn: Arc<Connection>, writer: &mut (dyn AsyncWrite + Unpin + Send)) {
    const WRITE_SIZE: usize = 1024;
    loop {
        let data = conn.remove_outgoing_data();
        if data.len() > 0 {
            match writer.write_all(&data).await {
                Ok(()) => {
                    if conn.debug { println!("write_loop: wrote {} bytes", data.len()) }
                }
                Err(e) => {
                    if conn.debug { println!("write_loop: error {}", e) }
                    conn.on_write_error(&e);
                    break;
                }
            }
        }
        if conn.had_error() {
            break;
        }

        conn.read_not.notify_one();
        conn.write_not.notified().await;
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

async fn test_client() -> Result<(), Box<dyn Error>> {
    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));
    let my_private_key: Option<EphemeralPrivateKey> = Some(my_private_key);

    let client_hello = make_client_hello(my_public_key_bytes);
    let handshake = Handshake::ClientHello(client_hello);


    let mut socket = TcpStream::connect("localhost:443").await?;

    let mut client = Client {
        received_alert: None,
        phase: Some(Phase::One(PhaseOne {
            transcript: Vec::new(),
            my_private_key: my_private_key,
        })),
    };

    let session = Session::new(client);
    let mut conn = Connection::new(session);
    conn.debug = true;
    let conn = Arc::new(conn);

    let read_conn = conn.clone();
    let write_conn = conn.clone();


    let (mut read_half, mut write_half) = socket.into_split();
    let read_handle = tokio::spawn(async move {
        read_loop(read_conn, &mut read_half).await
    });

    let write_handle = tokio::spawn(async move {
        write_loop(write_conn, &mut write_half).await
    });

    conn.write_client_hello(&handshake).await?;

    println!("**** before wait_till_established()");
    conn.wait_till_established().await?;
    println!("**** after wait_till_established()");


    sleep(Duration::from_millis(1000)).await;
    conn.write_plaintext_string(
        "The primary goal of TLS is to provide a secure channel between two \
         communicating peers; the only requirement from the underlying \
         transport is a reliable, in-order data stream.  Specifically, the \
         secure channel should provide the following properties:").await?;

    sleep(Duration::from_millis(1000)).await;
    conn.write_plaintext_string(
        "-  Authentication: The server side of the channel is always \
         authenticated; the client side is optionally authenticated. \
         Authentication can happen via asymmetric cryptography (e.g., RSA \
         [RSA], the Elliptic Curve Digital Signature Algorithm (ECDSA) \
         [ECDSA], or the Edwards-Curve Digital Signature Algorithm (EdDSA) \
         [RFC8032]) or a symmetric pre-shared key (PSK).").await?;

    sleep(Duration::from_millis(1000)).await;
    conn.write_plaintext_string(
        "-  Confidentiality: Data sent over the channel after establishment is \
         only visible to the endpoints.  TLS does not hide the length of \
         the data it transmits, though endpoints are able to pad TLS \
         records in order to obscure lengths and improve protection against \
         traffic analysis techniques.").await?;

    sleep(Duration::from_millis(1000)).await;
    conn.write_plaintext_string(
        "-  Integrity: Data sent over the channel after establishment cannot \
         be modified by attackers without detection.").await?;

    sleep(Duration::from_millis(1000)).await;
    conn.write_plaintext_string(
        "These properties should be true even in the face of an attacker who \
         has complete control of the network, as described in [RFC3552].  See \
         Appendix E for a more complete statement of the relevant security \
         properties.").await?;

    // println!();
    // for i in 1..=5 {
    //     sleep(Duration::from_millis(1000)).await;
    //     let message = format!("Message from client {}\n", i);
    //     conn.write_plaintext(&message.as_bytes()).await?;
    //     print!("Wrote: {}", message);
    // }


    read_handle.await.unwrap();
    write_handle.await.unwrap();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await?;
    Ok(())
}
