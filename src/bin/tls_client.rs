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
use torrent::tls::protocol::client::{
    Client,
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
        self.client.write_client_hello(handshake, &mut self.outgoing_data)
    }

    pub fn write_plaintext(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        match &self.error {
            Some(_) => return Err(GeneralError::new("Session is dead")),
            None => (),
        };
        self.client.write_plaintext(data, &mut self.outgoing_data)
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
        let established = self.session.lock().unwrap().client.is_established();
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




async fn test_client() -> Result<(), Box<dyn Error>> {
    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));

    let client_hello = make_client_hello(my_public_key_bytes);
    let handshake = Handshake::ClientHello(client_hello);

    let mut socket = TcpStream::connect("localhost:443").await?;
    let mut client = Client::new(my_private_key);

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
