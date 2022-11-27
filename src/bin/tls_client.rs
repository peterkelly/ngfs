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
use std::path::PathBuf;
use clap::{Clap, ValueHint};
use tokio::net::{TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::sleep;
use std::time::Duration;
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::SystemRandom;
use torrent::error;
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
    make_client_hello,
    EstablishedConnection,
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
};
use torrent::x509;

#[derive(Clap, Debug)]
#[clap(name="tls_client")]
struct Opt {
    #[clap(long, value_hint=ValueHint::FilePath)]
    ca_cert: Option<PathBuf>,

    #[clap(long, value_hint=ValueHint::FilePath)]
    client_cert: Option<PathBuf>,

    #[clap(long, value_hint=ValueHint::FilePath)]
    client_key: Option<PathBuf>,

    #[clap(long)]
    address: Option<String>,
}

fn parse_args(opt: &Opt) -> Result<ClientConfig, Box<dyn Error>> {
    let mut ca_cert: Option<Vec<u8>> = None;
    let mut client_cert: Option<Vec<u8>> = None;
    let mut client_key: Option<Vec<u8>> = None;

    if let Some(filename) = &opt.ca_cert {
        ca_cert = Some(fs::read(filename)?);
    }

    if let Some(filename) = &opt.client_cert {
        client_cert = Some(fs::read(filename)?);
    }

    if let Some(filename) = &opt.client_key {
        client_key = Some(fs::read(filename)?);
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
            return Err(error!("--client-cert option requires --client-key"));
        }
        (None, Some(_)) => {
            return Err(error!("--client-key option requires --client-cert"));
        }
        _ => {
            client_auth = ClientAuth::None;
        }
    }

    Ok(ClientConfig {
        client_auth,
        server_auth,
        server_name: None,
    })
}

async fn test_echo(
    aconn: &mut EstablishedConnection,
) -> Result<(), Box<dyn Error>>
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
        aconn.write_all(part).await?;
        aconn.flush().await?;
        let mut buf = vec_with_len(65536);
        let r = aconn.read(&mut buf).await?;
        println!("receive application data =");
        println!("{:#?}", Indent(&DebugHexDump(&buf[0..r])));
    }

    Ok(())
}

async fn test_http(
    aconn: &mut EstablishedConnection,
) -> Result<(), Box<dyn Error>>
{
    aconn.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").await?;
    aconn.flush().await?;
    loop {
        let mut buf = vec_with_len(65536);
        let r = aconn.read(&mut buf).await?;
        if r == 0 {
            println!("received EOF");
            break;
        }
        println!("r = {}", r);
        println!("receive application data =");
        println!("{:#?}", Indent(&DebugHexDump(&buf[0..r])));
    }
    Ok(())
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    let mut config = parse_args(&opt)?;
    config.server_name = Some(String::from("localhost"));

    let address = opt.address.unwrap_or(String::from("localhost:443"));

    let socket = TcpStream::connect(&address).await?;
    let protocol_names = ["h2", "http/1.1"];
    let mut conn = establish_connection(Box::pin(socket), config, &protocol_names).await?;

    test_http(&mut conn).await?;
    // test_echo(&mut conn).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await?;
    Ok(())
}
