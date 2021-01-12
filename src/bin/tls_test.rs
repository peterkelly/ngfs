#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::net::SocketAddr;
use std::fmt;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use torrent::util::{escape_string, BinaryData, DebugHexDump};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::tls::types::handshake::*;
use torrent::tls::types::extension::*;
use torrent::tls::types::record::*;
use torrent::util::from_hex;

fn make_client_hello() -> ClientHello {
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

    let mut extensions = vec![
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
                key_exchange: from_hex("13676e955e3f1e389274ffb25c6adb258a549c56779fd593613a73ea85acc669").unwrap().to_vec()
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

fn handshake_to_record(handshake: &Handshake) -> Result<Vec<u8>, Box<dyn Error>> {

    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };
    Ok(output_record.to_vec())
}

fn test_dh() -> Result<(), Box<dyn Error>> {
    use ring::agreement::{PublicKey, EphemeralPrivateKey, UnparsedPublicKey, X25519};
    use ring::rand::SystemRandom;
    let rng = SystemRandom::new();
    let my_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let my_public_key = my_private_key.compute_public_key()?;
    let my_public_key_bytes: &[u8] = my_public_key.as_ref();
    println!("my_public_key_bytes    = {}", BinaryData(my_public_key_bytes));

    let their_private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let their_public_key = their_private_key.compute_public_key()?;
    let their_public_key_bytes: &[u8] = their_public_key.as_ref();
    println!("their_public_key_bytes = {}", BinaryData(their_public_key_bytes));

    let my_unparsed_public_key = UnparsedPublicKey::new(&X25519, my_public_key_bytes);
    let their_unparsed_public_key = UnparsedPublicKey::new(&X25519, their_public_key_bytes);

    let key_material1 = ring::agreement::agree_ephemeral(
        my_private_key,
        &their_unparsed_public_key,
        ring::error::Unspecified,
        |key_material| Ok(Vec::from(key_material)))?;

    let key_material2 = ring::agreement::agree_ephemeral(
        their_private_key,
        &my_unparsed_public_key,
        ring::error::Unspecified,
        |key_material| Ok(Vec::from(key_material)))?;

    println!("key_material1 = {}", BinaryData(&key_material1));
    println!("key_material2 = {}", BinaryData(&key_material2));

    Ok(())
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let client_hello = make_client_hello();
    let handshake = Handshake::ClientHello(client_hello);
    let client_hello_data = handshake_to_record(&handshake)?;

    let serialized_filename = "record-constructed.bin";
    std::fs::write(serialized_filename, &client_hello_data)?;
    println!("Wrote {}", serialized_filename);

    let mut socket = TcpStream::connect("localhost:443").await?;
    socket.write_all(&client_hello_data).await?;

    let mut receiver = Receiver::new();

    while let Some((plaintext, plaintext_raw)) = receiver.next(&mut socket).await? {
        // println!("Plaintext: content type {:?}, version 0x{:04x}, fragment length {}, bytes_consumed {}",
        //         plaintext.content_type, plaintext.legacy_record_version, plaintext.fragment.len(), plaintext_raw.len());
        match plaintext.content_type {
            ContentType::Invalid => {
                println!("Unsupported record type: Invalid");
            }
            ContentType::ChangeCipherSpec => {
                println!("ChangeCipherSpec record: Ignoring");
            }
            ContentType::Alert => {
                println!("Unsupported record type: Alert");
            }
            ContentType::Handshake => {
                println!("Handshake record");
                let mut reader = BinaryReader::new(&plaintext.fragment);
                while reader.remaining() > 0 {
                    let server_handshake = reader.read_item::<Handshake>()?;
                    println!("{:#?}", server_handshake);
                }
            }
            ContentType::ApplicationData => {
                println!("Unsupported record type: ApplicationData");
            }
            ContentType::Unknown(code) => {
                println!("Unsupported record type: {}", code);
            }

        }
    }
    Ok(())
}

fn process_record<'a>(record: &'a TLSPlaintext, record_raw: &'a [u8]) -> Result<(), Box<dyn Error>> {
    let received_filename = "record-received.bin";
    std::fs::write(received_filename, record_raw)?;
    println!("Wrote {}", received_filename);

    let mut reader = BinaryReader::new(&record.fragment);
    let handshake = reader.read_item::<Handshake>()?;

    println!("{:#?}", handshake);

    // println!("--------------------------");
    let mut writer = BinaryWriter::new();
    writer.write_item(&handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };

    let serialized_filename = "record-serialized.bin";
    std::fs::write(serialized_filename, &output_record.to_vec())?;
    println!("Wrote {}", serialized_filename);

    Ok(())
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
    async fn next(&mut self, socket: &mut TcpStream) -> Result<Option<(TLSPlaintext, Vec<u8>)>, ReceiverError> {
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

async fn process_connection_inner(receiver: &mut Receiver, socket: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    while let Some((record, record_raw)) = receiver.next(socket).await? {
        process_record(&record, &record_raw)?;
    }
    Ok(())
}

async fn process_connection(mut socket: TcpStream, addr: SocketAddr) {
    println!("Received connection from {}", addr);
    let mut receiver = Receiver::new();

    match process_connection_inner(&mut receiver, &mut socket).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error processing connection: {}", e);
        }
    };
}

async fn test_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.01:8080").await?;
    println!("Listening for connections");
    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(process_connection(socket, addr));
        // let x: TcpStream = socket;
        // let y: SocketAddr = addr;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = match std::env::args().nth(1) {
        Some(command) => command,
        None => {
            eprintln!("No command specified");
            std::process::exit(1);
        }
    };

    match command.as_str() {
        "client" => test_client().await,
        "server" => test_server().await,
        "dh" => test_dh(),
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
