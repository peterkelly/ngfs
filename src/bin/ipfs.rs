#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

use std::error::Error;
use tokio::net::{TcpStream};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use torrent::util::{escape_string, vec_with_len, DebugHexDump};
use torrent::libp2p::tls::generate_certificate;
use torrent::libp2p::io::{read_length_prefixed_data, write_length_prefixed_data};
use torrent::libp2p::multistream::{
    multistream_handshake,
    multistream_list,
    multistream_select,
    SelectResponse,
};
use torrent::tls::protocol::client::{
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
};
use torrent::error;


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let mut rng = rand::rngs::OsRng {};
    let dalek_keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut rng);

    let client_key = openssl::rsa::Rsa::generate(2048)?.private_key_to_der()?;
    let rsa_key_pair = ring::signature::RsaKeyPair::from_der(&client_key)?;
    let certificate = generate_certificate(&rsa_key_pair, &dalek_keypair)?;

    println!("Generated certificate");

    let config = ClientConfig {
        client_auth: ClientAuth::Certificate {
            cert: certificate,
            key: client_key,
        },
        server_auth: ServerAuth::SelfSigned,
        server_name: None,
    };

    let mut socket = TcpStream::connect("localhost:4001").await?;

    multistream_handshake(&mut socket).await?;
    println!("Completed multistream handshake on TCP connection");

    let protocol_list = multistream_list(&mut socket).await?;
    println!("Available protocols on TCP connection:");
    for protocol in protocol_list {
        println!("    {}", escape_string(&protocol));
    }

    match multistream_select(&mut socket, b"/tls/1.0.0\n").await? {
        SelectResponse::Accepted => (),
        SelectResponse::Unsupported => {
            return Err(error!("/tls/1.0.0 is unsupported").into());
        }
    }
    println!("Negotiated TLS");

    let mut conn = establish_connection(socket, config).await?;
    println!("Established TLS connection");
    println!();
    multistream_handshake(&mut conn).await?;
    println!("Completed multistream handshake on TLS connection");

    let protocol_list = multistream_list(&mut conn).await?;
    println!("Available protocols on TLS connection:");
    for protocol in protocol_list {
        println!("    {}", escape_string(&protocol));
    }

    match multistream_select(&mut conn, b"/mplex/6.7.0\n").await? {
        SelectResponse::Accepted => (),
        SelectResponse::Unsupported => {
            return Err(error!("/mplex/6.7.0 is unsupported").into());
        }
    }
    println!("Negotiated /mplex/6.7.0");

    Ok(())
}
