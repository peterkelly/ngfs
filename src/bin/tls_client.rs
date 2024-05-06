// #![allow(unused_variables)]
#![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use clap::{Parser, ValueHint};
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use std::time::Duration;
use ngfs::crypto::pem::{decode_pem, decode_pem_with_label};
use ngfs::util::util::{vec_with_len, DebugHexDump, Indent};
use ngfs::tls::protocol::client::{
    EstablishedConnection,
    ServerAuth,
    ClientAuth,
    ClientKey,
    ClientConfig,
    establish_connection,
};

#[derive(Parser, Debug)]
#[command(name="tls_client")]
struct Opt {
    #[arg(long, value_hint=ValueHint::FilePath)]
    ca_cert: Option<PathBuf>,

    #[arg(long, value_hint=ValueHint::FilePath)]
    client_cert: Option<PathBuf>,

    #[arg(long, value_hint=ValueHint::FilePath)]
    client_key: Option<PathBuf>,

    #[arg(long)]
    address: Option<String>,
}

fn parse_args(opt: &Opt) -> Result<ClientConfig, Box<dyn Error>> {
    let mut ca_cert: Option<Vec<u8>> = None;
    let mut client_cert: Option<Vec<u8>> = None;
    let mut client_key: Option<ClientKey> = None;

    if let Some(filename) = &opt.ca_cert {
        let pem_data = fs::read(filename)?;
        let decoded = decode_pem_with_label(&pem_data, "CERTIFICATE")?;
        ca_cert = Some(decoded);
    }

    if let Some(filename) = &opt.client_cert {
        let pem_data = fs::read(filename)?;
        let decoded = decode_pem_with_label(&pem_data, "CERTIFICATE")?;
        client_cert = Some(decoded);
    }

    if let Some(filename) = &opt.client_key {
        let pem_data = fs::read(filename)?;
        let (label, decoded) = decode_pem(&pem_data)?;
        if label == "RSA PRIVATE KEY" {
            client_key = Some(ClientKey::RSA(decoded));
        }
        else if label == "PRIVATE KEY" {
            // TODO: I think this could also be an RSA key, need to check content
            client_key = Some(ClientKey::EC(decoded));
        }
        else {
            return Err(format!("Unknown key type: {}", label).into());
        }
    }

    let server_auth = match &ca_cert {
        Some(crt) => ServerAuth::CertificateAuthority(crt.clone()),
        None => ServerAuth::None,
    };

    let client_auth = match (&client_cert, &client_key) {
        (Some(cert), Some(key)) => {
            ClientAuth::Certificate {
                cert: cert.clone(),
                key: key.clone(),
            }
        }
        (Some(_), None) => {
            return Err("--client-cert option requires --client-key".into());
        }
        (None, Some(_)) => {
            return Err("--client-key option requires --client-cert".into());
        }
        _ => {
            ClientAuth::None
        }
    };

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

    let address = opt.address.unwrap_or_else(|| String::from("localhost:443"));

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
