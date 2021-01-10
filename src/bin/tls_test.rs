#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::net::SocketAddr;
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
        Extension::EllipticCurves(vec![
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

async fn test_client() -> Result<(), Box<dyn Error>> {
    let client_hello = make_client_hello();
    let handshake = Handshake::ClientHello(client_hello);

    let mut writer = BinaryWriter::new();
    writer.write_item(&handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: &Vec::<u8>::from(writer),
    };

    let serialized_filename = "record-constructed.bin";
    std::fs::write(serialized_filename, &output_record.to_vec())?;
    println!("Wrote {}", serialized_filename);

    Ok(())
}

fn process_record<'a>(record: &'a TLSPlaintext, record_raw: &'a [u8]) -> Result<(), Box<dyn Error>> {
    let received_filename = "record-received.bin";
    std::fs::write(received_filename, record_raw)?;
    println!("Wrote {}", received_filename);

    let mut reader = BinaryReader::new(record.fragment);
    let handshake = reader.read_item::<Handshake>()?;

    println!("{:#?}", handshake);

    // println!("--------------------------");
    let mut writer = BinaryWriter::new();
    writer.write_item(&handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: &Vec::<u8>::from(writer),
    };

    let serialized_filename = "record-serialized.bin";
    std::fs::write(serialized_filename, &output_record.to_vec())?;
    println!("Wrote {}", serialized_filename);

    Ok(())
}

async fn process_connection_inner(mut socket: TcpStream, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    println!("Received connection from {}", addr);
    println!("local_addr = {}", socket.local_addr()?);
    println!("peer_addr = {}", socket.peer_addr()?);
    const READ_SIZE: usize = 1024;

    let mut incoming_data: Vec<u8> = Vec::new();

    loop {


        let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
        let r = socket.read(&mut buf).await?;
        if r == 0 {
            println!("Connection closed by peer");
            return Ok(())
        }
        incoming_data.extend_from_slice(&buf[0..r]);

        match TLSPlaintext::from_raw_data(&incoming_data) {
            Err(TLSPlaintextError::InsufficientData) => {
                // need to read some more data from the socket before we can decode the record
                continue;
            }
            Err(TLSPlaintextError::InvalidLength) => {
                println!("Client sent record with invalid length");
                return Ok(())
            }
            Ok((record, bytes_consumed)) => {
                process_record(&record, &incoming_data[0..bytes_consumed])?;
                incoming_data = incoming_data.split_off(bytes_consumed);
            }
        }
    }
}

async fn process_connection(socket: TcpStream, addr: SocketAddr) {
    match process_connection_inner(socket, addr).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error processing connection: {}", e);
        }
    }
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
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
