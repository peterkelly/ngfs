#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::fmt;
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::SystemRandom;
use torrent::result::GeneralError;
use torrent::util::{from_hex, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, BinaryWriter};
use torrent::crypt::HashAlgorithm;
use torrent::tls::types::handshake::{
    CipherSuite,
    Handshake,
    ClientHello,
    Finished,
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
    TLSPlaintextError,
};
use torrent::tls::helpers::{
    derive_secret,
    get_server_hello_x25519_shared_secret,
    get_zero_prk,
    get_derived_prk,
    encrypt_traffic,
    decrypt_message,
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
    cipher_suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
    cipher_suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    cipher_suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
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

fn transcript_hash(alg: HashAlgorithm, transcript: &[u8]) -> Vec<u8> {
    let mut digest = alg.new_digest();
    digest.input(transcript);
    let mut result: Vec<u8> = vec![0; digest.output_bits() / 8];
    digest.result(&mut result);
    result
}

struct ClientHelloSent {
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    prk: Vec<u8>,
    transcript: Vec<u8>,
    my_private_key: Option<EphemeralPrivateKey>,
}

impl ClientHelloSent {
    fn handshake(&mut self,
                          handshake: &Handshake,
                          handshake_bytes: &[u8]) -> Result<Option<State>, Box<dyn Error>> {
        self.transcript.extend_from_slice(handshake_bytes);

        match handshake {
            Handshake::ServerHello(server_hello) => {
                let my_private_key2 = self.my_private_key.take().unwrap();

                let secret: &[u8] = &match get_server_hello_x25519_shared_secret(my_private_key2, &server_hello) {
                    Some(r) => r,
                    None => return Err("Cannot get shared secret".into()),
                };
                println!("Shared secret = {}", BinaryData(&secret));

                let new_prk = get_derived_prk(self.hash_alg, &self.prk, secret);

                println!("Got expected server hello");

                let thash = transcript_hash(self.hash_alg, &self.transcript);
                let hs = TrafficSecrets {
                    client: derive_secret(self.hash_alg, &new_prk, b"c hs traffic", &thash),
                    server: derive_secret(self.hash_alg, &new_prk, b"s hs traffic", &thash),
                };

                println!("KEY CLIENT_HANDSHAKE_TRAFFIC_SECRET: {}", BinaryData(&hs.client));
                println!("KEY SERVER_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&hs.server));

                // handshake_traffic_secrets = Some(hs);

                Ok(Some(State::ServerHelloReceived(ServerHelloReceived {
                    hash_alg: self.hash_alg,
                    aead_alg: self.aead_alg,
                    prk: new_prk,
                    transcript: self.transcript.clone(), // TODO: Avoid clone
                    handshake_secrets: hs,
                    server_sequence_no: 0,
                })))
            }
            _ => {
                Err(GeneralError::new("Received unexpected handshake type"))
            }
        }
    }

    fn application_data(&mut self,
                        _conn: &mut ClientConn,
                        _plaintext: TLSPlaintext,
                        _plaintext_raw: Vec<u8>) -> Result<Option<State>, Box<dyn Error>> {
        Err(GeneralError::new("Received ApplicationData in ClientHelloSent state"))
    }
}

struct ServerHelloReceived {
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    prk: Vec<u8>,
    transcript: Vec<u8>,
    handshake_secrets: TrafficSecrets,
    server_sequence_no: u64,
}

impl ServerHelloReceived {
    fn handshake(&mut self,
                 _handshake: &Handshake,
                 _handshake_bytes: &[u8]) -> Result<Option<State>, Box<dyn Error>> {
        Err(GeneralError::new("Received Handshake in ServerHelloReceived state"))
    }

    fn application_data(&mut self,
                        conn: &mut ClientConn,
                        _plaintext: TLSPlaintext,
                        plaintext_raw: Vec<u8>) -> Result<Option<State>, Box<dyn Error>> {
        let decryption_key = &self.handshake_secrets.server;

        let old_transcript_hash: Vec<u8> = transcript_hash(self.hash_alg, &self.transcript);
        let (message, inner_body_vec) = decrypt_message(
            self.hash_alg,
            self.aead_alg,
            self.server_sequence_no,
            decryption_key,
            &plaintext_raw)?;
        self.server_sequence_no += 1;
        self.transcript.extend_from_slice(&inner_body_vec);

        let new_transcript_hash: Vec<u8> = transcript_hash(self.hash_alg, &self.transcript);
        // println!("transcript hash = {:?}", BinaryData(&transcript_hash(self.hash_alg, &self.transcript)));

        // println!("inner_content_type = {:?}", inner_content_type);
        // println!("inner_body.len() = {}", inner_body.len());


        // println!("plaintext =");
        // println!("{:#?}", Indent(&DebugHexDump(&plaintext)));
        // println!("inner_body =");
        // println!("{:#?}", Indent(&DebugHexDump(&inner_body)));


        match message {
            Message::Handshake(Handshake::Certificate(certificate)) => {

                println!("    Received Handshake::Certificate");
                println!("        certificate_request_context.len() = {}",
                    certificate.certificate_request_context.len());
                println!("        certificate_list.len() = {}",
                    certificate.certificate_list.len());

                println!("    This is a certificate handshake");
                for entry in certificate.certificate_list.iter() {
                    println!("    - entry");
                    let filename = "certificate.crt";
                    std::fs::write(filename, &entry.data)?;
                    println!("    Wrote to {}", filename);
                }
                // println!("handshake = {:#?}", inner_handshake);

            }
            Message::Handshake(Handshake::CertificateVerify(certificate_verify)) => {

                println!("    Received Handshake::CertificateVerify with algorithm {:?} and {} signature bytes",
                    certificate_verify.algorithm,
                    certificate_verify.signature.len());
                // println!("handshake = {:#?}", inner_handshake);

            }
            Message::Handshake(Handshake::Finished(finished)) => {

                println!("    Received Handshake::Finished with {} bytes", finished.data.len());
                let input_psk: &[u8] = &vec_with_len(self.hash_alg.byte_len());
                let new_prk = get_derived_prk(self.hash_alg, &self.prk, input_psk);

                let thash = transcript_hash(self.hash_alg, &self.transcript);
                let ap = TrafficSecrets {
                    client: derive_secret(self.hash_alg, &new_prk, b"c ap traffic", &thash),
                    server: derive_secret(self.hash_alg, &new_prk, b"s ap traffic", &thash),
                };
                println!("        KEY CLIENT_TRAFFIC_SECRET_0: {}", BinaryData(&ap.client));
                println!("        KEY SERVER_TRAFFIC_SECRET_0 = {}", BinaryData(&ap.server));

                {
                    let finished_key: Vec<u8> =
                        derive_secret(self.hash_alg, &self.handshake_secrets.server, b"finished", &[]);
                    {
                        println!("server_finished_key = {:?}", BinaryData(&finished_key));
                        println!();
                        println!("server_finish: handshake_hash = {:?}", BinaryData(&old_transcript_hash));
                        let verify_data: Vec<u8> = self.hash_alg.hmac_sign(&finished_key, &old_transcript_hash);
                        println!("server_finish: verify_data    = {:?}", BinaryData(&verify_data));
                        println!("server_finish: finished.data  = {:?}", BinaryData(&finished.data));
                        println!();
                    }

                    if self.hash_alg.hmac_verify(&finished_key, &old_transcript_hash, &finished.data) {
                        println!("Finished (self.hash_alg): Verification succeeded");
                    }
                    else {
                        println!("Finished (self.hash_alg): Verification failed");
                        return Err(GeneralError::new("Incorrect finished data"));
                    }
                }

                // Send Client Finished message
                {
                    let finished_key: Vec<u8> =
                        derive_secret(self.hash_alg, &self.handshake_secrets.client, b"finished", &[]);

                    println!("client_finished_key = {:?}", BinaryData(&finished_key));
                    println!();
                    println!("client_finish: handshake_hash = {:?}",
                             BinaryData(&new_transcript_hash));

                    let verify_data: Vec<u8> =
                        self.hash_alg.hmac_sign(&finished_key, &new_transcript_hash);
                    println!("client_finish: verify_data    = {:?}", BinaryData(&verify_data));

                    let client_finished = Handshake::Finished(Finished {
                        data: self.hash_alg.hmac_sign(&finished_key, &new_transcript_hash),
                    });

                    let mut writer = BinaryWriter::new();
                    writer.write_item(&client_finished)?;
                    let client_finished_bytes: Vec<u8> = Vec::from(writer);
                    conn.append_encrypted(
                        client_finished_bytes,          // to_encrypt
                        ContentType::Handshake,         // content_type
                        self.hash_alg,                  // hash_alg
                        self.aead_alg,                  // aead_alg
                        &self.handshake_secrets.client, // traffic_secret
                        0,                              // client_sequence_no
                    )?;
                }

                // Start of application traffic
                let mut client_sequence_no: u64 = 0;

                // HTTP request
                {
                    let request = b"GET / HTTP/1.1\r\n\r\n".to_vec();
                    conn.append_encrypted(
                        request,                      // to_encrypt
                        ContentType::ApplicationData, // content_type
                        self.hash_alg,                // hash_alg
                        self.aead_alg,                // aead_alg
                        &ap.client,                   // traffic_secret
                        client_sequence_no,           // client_sequence_no
                    )?;
                }
                client_sequence_no += 1;



                // println!("handshake = {:#?}", inner_handshake);
                return Ok(Some(State::Established(Established {
                    hash_alg: self.hash_alg,
                    aead_alg: self.aead_alg,
                    prk: new_prk,
                    application_secrets: ap,
                    client_sequence_no: 0,
                    // server_sequence_no: self.server_sequence_no,
                    server_sequence_no: 0,
                })));
            }
            _ => {
                println!("Unexpected message type {}", message.name());
            }
        }
        Ok(None)
    }
}

struct Established {
    hash_alg: HashAlgorithm,
    aead_alg: &'static ring::aead::Algorithm,
    prk: Vec<u8>,
    application_secrets: TrafficSecrets,
    client_sequence_no: u64,
    server_sequence_no: u64,
}

impl Established {
    fn handshake(&mut self,
                 _handshake: &Handshake,
                 _handshake_bytes: &[u8]) -> Result<Option<State>, Box<dyn Error>> {
        Err(GeneralError::new("Received Handshake in Established state"))
    }

    fn application_data(&mut self,
                        _conn: &mut ClientConn,
                        _plaintext: TLSPlaintext,
                        plaintext_raw: Vec<u8>) -> Result<Option<State>, Box<dyn Error>> {
        let decryption_key = &self.application_secrets.server;

        let (message, _) = decrypt_message(
            self.hash_alg,
            self.aead_alg,
            self.server_sequence_no,
            decryption_key,
            &plaintext_raw)?;
        self.server_sequence_no += 1;

        match message {
            Message::Handshake(Handshake::NewSessionTicket(ticket)) => {
                println!("ticket = {:#?}", ticket);
            }
            Message::ApplicationData(data) => {
                println!("data =");
                println!("{:#?}", Indent(&DebugHexDump(&data)));
            }
            Message::Alert(_) => {
                // println!("inner_alert = {:?}", Indent(&alert));
            }
            _ => {
                println!("Unexpected message type {}", message.name());
            }
        }
        Ok(None)
    }
}

struct TrafficSecrets {
    client: Vec<u8>,
    server: Vec<u8>,
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

    // TODO: Make this return (). The only reason it returns a Result, and the only reason why
    // encrypt_traffic() returns a Result, is that the latter calls UnboundKey::new() because it
    // does a hkdf_expand_label() each time. We should do the hkdf_expand_label() just once when
    // we get a new prk, so it doesn't have to be repeated (and potentially fail) on every
    // encryption call.
    fn append_encrypted(
        &mut self,
        mut to_encrypt: Vec<u8>,
        content_type: ContentType,
        hash_alg: HashAlgorithm,
        aead_alg: &'static ring::aead::Algorithm,
        traffic_secret: &[u8],
        client_sequence_no: u64,
    ) -> Result<(), Box<dyn Error>> {
        to_encrypt.push(content_type.to_raw());
        let client_finished_enc = encrypt_traffic(
            hash_alg,
            aead_alg,
            traffic_secret,
            client_sequence_no,
            &to_encrypt)?;

        let output_record = TLSPlaintext {
            content_type: ContentType::ApplicationData,
            legacy_record_version: 0x0303,
            fragment: client_finished_enc,
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

enum State {
    ClientHelloSent(ClientHelloSent),
    ServerHelloReceived(ServerHelloReceived),
    Established(Established),
}

struct Client {
    state: State,
}

impl Client {
    fn invalid(&mut self,
               _conn: &mut ClientConn,
               _plaintext: TLSPlaintext,
               _plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
        println!("Unsupported record type: Invalid");
        Ok(())
    }

    fn change_cipher_spec(&mut self,
                          _conn: &mut ClientConn,
                          _plaintext: TLSPlaintext,
                          _plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
        println!("ChangeCipherSpec record: Ignoring");
        Ok(())
    }

    fn alert(&mut self,
             _conn: &mut ClientConn,
             _plaintext: TLSPlaintext,
             _plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
        println!("Unsupported record type: Alert");
        Ok(())
    }

    fn handshake(&mut self,
                 _conn: &mut ClientConn,
                 plaintext: TLSPlaintext,
                 _plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
        println!("Handshake record");
        let mut reader = BinaryReader::new(&plaintext.fragment);
        while reader.remaining() > 0 {
            let old_offset = reader.abs_offset();
            let server_handshake = reader.read_item::<Handshake>()?;
            let new_offset = reader.abs_offset();
            let handshake_bytes: &[u8] = &plaintext.fragment[old_offset..new_offset];

            println!("{:#?}", server_handshake);

            let new_state_opt = match &mut self.state {
                State::ClientHelloSent(state) => state.handshake(&server_handshake, handshake_bytes)?,
                State::ServerHelloReceived(state) => state.handshake(&server_handshake, handshake_bytes)?,
                State::Established(state) => state.handshake(&server_handshake, handshake_bytes)?,
            };

            match new_state_opt {
                Some(state) => self.state = state,
                None => (),
            };
        }
        Ok(())
    }

    fn application_data(&mut self,
                        conn: &mut ClientConn,
                        plaintext: TLSPlaintext,
                        plaintext_raw: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let new_state_opt = match &mut self.state {
            State::ClientHelloSent(state) => state.application_data(conn, plaintext, plaintext_raw)?,
            State::ServerHelloReceived(state) => state.application_data(conn, plaintext, plaintext_raw)?,
            State::Established(state) => state.application_data(conn, plaintext, plaintext_raw)?,
        };

        match new_state_opt {
            Some(state) => self.state = state,
            None => (),
        };
        Ok(())
    }

    fn unknown(&mut self,
               _conn: &mut ClientConn,
               code: u8) -> Result<(), Box<dyn Error>> {
        println!("Unsupported record type: {}", code);
        Ok(())
    }
}


pub enum ReceiverError {
    ConnectionClosedByPeer,
    InvalidRecordLength,
    SocketRecv(String),
}

impl fmt::Display for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReceiverError::ConnectionClosedByPeer => write!(f, "Connection closed by peer"),
            ReceiverError::InvalidRecordLength => write!(f, "Invalid record length"),
            ReceiverError::SocketRecv(msg) => write!(f, "{}", msg),
        }
    }
}

impl fmt::Debug for ReceiverError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl std::error::Error for ReceiverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

struct Receiver {
    incoming_data: Vec<u8>,
    to_remove: usize,
}

impl Receiver {
    fn new() -> Self {
        Receiver {
            incoming_data: Vec::new(),
            to_remove: 0,
        }
    }
}

impl Receiver {
    async fn next(&mut self, socket: &mut TcpStream) ->
                  Result<Option<(TLSPlaintext, Vec<u8>)>, ReceiverError> {
        const READ_SIZE: usize = 1024;
        loop {
            if self.to_remove > 0 {
                self.incoming_data = self.incoming_data.split_off(self.to_remove);
                self.to_remove = 0;
            }

            match TLSPlaintext::from_raw_data(&self.incoming_data) {
                Err(TLSPlaintextError::InsufficientData) => {
                    // need to read some more data from the socket before we can decode the record
                    let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
                    let r = match socket.read(&mut buf).await {
                        Err(e) => return Err(ReceiverError::SocketRecv(format!("{}", e))),
                        Ok(0) => return Ok(None),
                        Ok(r) => r,
                    };
                    self.incoming_data.extend_from_slice(&buf[0..r]);
                }
                Err(TLSPlaintextError::InvalidLength) => {
                    return Err(ReceiverError::InvalidRecordLength);
                }
                Ok((record, bytes_consumed)) => {
                    self.to_remove = bytes_consumed;
                    let record_raw = Vec::from(&self.incoming_data[0..bytes_consumed]);
                    return Ok(Some((record, record_raw)));
                }
            }
        }
    }
}

fn handshake_to_record(handshake: &Handshake) -> Result<TLSPlaintext, Box<dyn Error>> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };
    Ok(output_record)
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let hash_alg = HashAlgorithm::SHA384;
    let aead_alg = &ring::aead::AES_256_GCM;

    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));
    let my_private_key: Option<EphemeralPrivateKey> = Some(my_private_key);

    let client_hello = make_client_hello(my_public_key_bytes);
    let handshake = Handshake::ClientHello(client_hello);
    let client_hello_plaintext_record: TLSPlaintext = handshake_to_record(&handshake)?;
    let client_hello_plaintext_record_bytes: Vec<u8> = client_hello_plaintext_record.to_vec();
    let client_hello_bytes: Vec<u8> = Vec::from(client_hello_plaintext_record.fragment);

    let serialized_filename = "record-constructed.bin";
    std::fs::write(serialized_filename, &client_hello_plaintext_record_bytes)?;
    println!("Wrote {}", serialized_filename);

    let mut socket = TcpStream::connect("localhost:443").await?;
    socket.write_all(&client_hello_plaintext_record_bytes).await?;

    let mut initial_transcript: Vec<u8> = Vec::new();
    initial_transcript.extend_from_slice(&client_hello_bytes);
    let mut client = Client {
        state: State::ClientHelloSent(ClientHelloSent {
            hash_alg: hash_alg,
            aead_alg: aead_alg,
            prk: get_zero_prk(hash_alg),
            transcript: initial_transcript,
            my_private_key: my_private_key,
        }),
    };
    let mut conn = ClientConn::new();

    let mut receiver = Receiver::new();

    while let Some((plaintext, raw)) = receiver.next(&mut socket).await? {
        match plaintext.content_type {
            ContentType::Invalid => client.invalid(&mut conn, plaintext, raw)?,
            ContentType::ChangeCipherSpec => client.change_cipher_spec(&mut conn, plaintext, raw)?,
            ContentType::Alert => client.alert(&mut conn, plaintext, raw)?,
            ContentType::Handshake => client.handshake(&mut conn, plaintext, raw)?,
            ContentType::ApplicationData => client.application_data(&mut conn, plaintext, raw)?,
            ContentType::Unknown(code) => client.unknown(&mut conn, code)?,
        }

        conn.send_pending_data(&mut socket).await?;
    }
    println!("Server closed connection");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await?;
    Ok(())
}
