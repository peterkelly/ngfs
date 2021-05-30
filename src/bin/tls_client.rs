#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::fmt;
use std::fs;
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
    EstablishedConnection,
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
};
use torrent::x509;

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

fn parse_args() -> Result<ClientConfig, Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    let mut argno = 1;

    let mut ca_cert: Option<Vec<u8>> = None;
    let mut client_cert: Option<Vec<u8>> = None;
    let mut client_key: Option<Vec<u8>> = None;

    while argno < args.len() {
        if args[argno] == "--ca-cert" && argno + 1 < args.len() {
            ca_cert = Some(fs::read(&args[argno + 1])?);
            argno += 2;
        }
        else if args[argno] == "--client-cert" && argno + 1 < args.len() {
            client_cert = Some(fs::read(&args[argno + 1])?);
            argno += 2;
        }
        else if args[argno] == "--client-key" && argno + 1 < args.len() {
            client_key = Some(fs::read(&args[argno + 1])?);
            argno += 2;
        }
        else {
            return Err(GeneralError::new(format!("Unexpected argument: {}", args[argno])));
        }
    }

    let server_auth: ServerAuth;
    match &ca_cert {
        Some(crt) => server_auth = ServerAuth::CertificateAuthority(crt.clone()),
        None => server_auth = ServerAuth::None,
    }

    let client_auth: ClientAuth;
    match (&client_cert, &client_key) {
        (Some(cert), Some(key)) => {
            client_auth = ClientAuth::Certificate {
                cert: cert.clone(),
                key: key.clone(),
            };
        }
        (Some(_), None) => {
            return Err(GeneralError::new("--client-cert option requires --client-key"));
        }
        (None, Some(_)) => {
            return Err(GeneralError::new("--client-key option requires --client-cert"));
        }
        _ => {
            client_auth = ClientAuth::None;
        }
    }

    Ok(ClientConfig {
        client_auth,
        server_auth,
    })
}

async fn test_echo<T>(
    aconn: &mut EstablishedConnection<T>,
) -> Result<(), Box<dyn Error>>
    where T : AsyncRead + AsyncWrite + Unpin
{
    let parts: &[&[u8]] = &[
        b"The primary goal of TLS is to provide a secure channel between two \
         communicating peers; the only requirement from the underlying \
         transport is a reliable, in-order data stream.  Specifically, the \
         secure channel should provide the following properties:",

        b"-  Authentication: The server side of the channel is always \
         authenticated; the client side is optionally authenticated. \
         Authentication can happen via asymmetric cryptography (e.g., RSA \
         [RSA], the Elliptic Curve Digital Signature Algorithm (ECDSA) \
         [ECDSA], or the Edwards-Curve Digital Signature Algorithm (EdDSA) \
         [RFC8032]) or a symmetric pre-shared key (PSK).",

        b"-  Confidentiality: Data sent over the channel after establishment is \
         only visible to the endpoints.  TLS does not hide the length of \
         the data it transmits, though endpoints are able to pad TLS \
         records in order to obscure lengths and improve protection against \
         traffic analysis techniques.",

        b"-  Integrity: Data sent over the channel after establishment cannot \
         be modified by attackers without detection.",

        b"These properties should be true even in the face of an attacker who \
         has complete control of the network, as described in [RFC3552].  See \
         Appendix E for a more complete statement of the relevant security \
         properties.",
    ];

    for part in parts.iter() {
        sleep(Duration::from_millis(1000)).await;
        aconn.write_normal(part).await?;
        let data = aconn.read_normal().await?;
        println!("receive application data =");
        println!("{:#?}", Indent(&DebugHexDump(&data)));
    }

    Ok(())
}

async fn test_http<T>(
    aconn: &mut EstablishedConnection<T>,
) -> Result<(), Box<dyn Error>>
    where T : AsyncRead + AsyncWrite + Unpin
{
    aconn.write_normal(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await?;
    loop {
        let data = aconn.read_normal().await?;
        println!("receive application data =");
        println!("{:#?}", Indent(&DebugHexDump(&data)));
    }
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let config = parse_args()?;

    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let public_key = private_key.compute_public_key()?;
    println!("public_key_bytes    = {}", BinaryData(public_key.as_ref()));

    let client_hello = make_client_hello(public_key.as_ref());
    let handshake = Handshake::ClientHello(client_hello);

    let mut socket = TcpStream::connect("localhost:443").await?;

    let mut conn = establish_connection(config, socket, &handshake, private_key).await?;

    test_http(&mut conn).await?;
    // test_echo(&mut conn).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await?;
    Ok(())
}
