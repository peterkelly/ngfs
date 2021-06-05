#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

use ring::rand::SystemRandom;

use core::pin::Pin;
use core::task::{Context, Poll};
use std::error::Error;
use std::net::SocketAddr;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, BufReader, BufWriter, ReadBuf};
use tokio::sync::{Notify};
use futures::future::join;
use ring::agreement::{EphemeralPrivateKey, X25519};
use torrent::util::{from_hex, escape_string, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::result::GeneralError;
use torrent::protobuf::VarInt;
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
    TLSPlaintextError,
};
use torrent::tls::protocol::client::{
    EstablishedConnection,
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
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

async fn read_multistream_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<usize, Box<dyn Error>> {
    let mut buf: [u8; 1] = [0; 1];
    let mut value: usize = 0;
    loop {
        let r = match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(GeneralError::new("Unexpected end of input")),
            Ok(r) => {
                let b = buf[0];
                value = (value << 7) | ((b & 0x7f) as usize);
                if b & 0x80 == 0 {
                    break;
                }
            }
        };
    }
    Ok(value)
}

async fn read_multistream_data(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Box<dyn Error>> {
    let expected_len = read_multistream_varint(reader).await?;
    // println!("expected_len = {}", expected_len);
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        let r = match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(GeneralError::new("Unexpected end of input")),
            Ok(r) => {
                incoming_data.push(buf[0]);
                got_len += 1;
            }
        };
    }
    Ok(incoming_data)
}

async fn write_multistream_data(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Box<dyn Error>> {
    let len_bytes = VarInt::encode_usize(data.len());
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut socket = TcpStream::connect("localhost:4001").await?;


    write_multistream_data(&mut socket, b"/multistream/1.0.0\n").await?;
    write_multistream_data(&mut socket, b"/tls/1.0.0\n").await?;

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    let config = ClientConfig {
        client_auth: ClientAuth::None,
        server_auth: ServerAuth::None,
    };

    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let public_key = private_key.compute_public_key()?;
    println!("public_key_bytes    = {}", BinaryData(public_key.as_ref()));

    let client_hello = make_client_hello(public_key.as_ref());
    let handshake = Handshake::ClientHello(client_hello);

    let mut conn = establish_connection(config, socket, &handshake, private_key).await?;

    // let data = read_multistream_data(&mut socket).await?;
    // println!("{:#?}", &DebugHexDump(&data));
    // println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    Ok(())
}
