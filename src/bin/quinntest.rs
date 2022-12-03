#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::sync::Arc;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use rustls::{Certificate, PrivateKey};
use torrent::libp2p::multistream::{
    multistream_handshake,
    multistream_list,
    multistream_select,
    SelectResponse,
};
use torrent::libp2p::tls::generate_certificate;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use torrent::ipfs::node::{IPFSNode, ServiceRegistry};
use torrent::ipfs::bitswap::handler::{bitswap_handler, bitswap_handler_show};

const ID_PROTOCOL: &[u8] = b"/ipfs/id/1.0.0\n";
const ID_PROTOCOL_STR: &str = "/ipfs/id/1.0.0";
const BITSWAP_PROTOCOL_STR: &str = "/ipfs/bitswap/1.2.0";
const BITSWAP_PROTOCOL: &[u8] = b"/ipfs/bitswap/1.2.0\n";

fn make_server_config(
    cert_chain: Vec<Certificate>,
    key_der: PrivateKey,
) -> Result<rustls::ServerConfig, rustls::Error> {
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;
    Ok(server_crypto)
    // server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    // if options.keylog {
    //     server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    // }

    // let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        match std::fs::write("temp-server-certificate.der", _end_entity) {
            Ok(()) => println!("Wrote temp-server-certificate.der"),
            Err(e) => println!("Error writing temp-server-certificate.der: {}", e),
        }
        println!("Skipping verification for {:?}", _server_name);
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

struct CombinedStream {
    send_stream: quinn::SendStream,
    recv_stream: quinn::RecvStream,
}

impl CombinedStream {
    fn new(pair: (quinn::SendStream, quinn::RecvStream)) -> Self {
        CombinedStream {
            send_stream: pair.0,
            recv_stream: pair.1,
        }
    }
}

impl AsyncRead for CombinedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut Pin::into_inner(self).recv_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for CombinedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut Pin::into_inner(self).send_stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut Pin::into_inner(self).send_stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut Pin::into_inner(self).send_stream).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut Pin::into_inner(self).send_stream).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.send_stream.is_write_vectored()
    }
}

fn make_client_config(
    private_key_filename: &str,
    certificate_filename: &str,
) -> Result<rustls::ClientConfig, Box<dyn Error>> {

    let private_key_bytes = std::fs::read(private_key_filename)?;
    let certificate_bytes = std::fs::read(certificate_filename)?;
    let private_key = rustls::PrivateKey(private_key_bytes);
    let certificate = rustls::Certificate(certificate_bytes);


    let config: quinn::EndpointConfig = quinn::EndpointConfig::default();
    let server_config: quinn::ServerConfig;


    let mut roots = rustls::RootCertStore::empty();
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        // .with_root_certificates(roots)
        .with_custom_certificate_verifier(SkipServerVerification::new())
        // .with_no_client_auth();
        .with_single_cert(vec![certificate], private_key)?;
    Ok(client_crypto)
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes: ring::pkcs8::Document = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let host_keypair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;

    let client_key = openssl::rsa::Rsa::generate(2048)?.private_key_to_der()?;
    let rsa_key_pair = ring::signature::RsaKeyPair::from_der(&client_key)?;
    let certificate = generate_certificate(&rsa_key_pair, &host_keypair)?;

    let node = Arc::new(IPFSNode::new(host_keypair));



    // let private_key_filename = "../torrent/certificates/client.key.der";
    // let certificate_filename = "../torrent/generated3.der";

    // let client_crypto = make_client_config(private_key_filename, certificate_filename)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        // .with_root_certificates(roots)
        .with_custom_certificate_verifier(SkipServerVerification::new())
        // .with_no_client_auth();
        .with_single_cert(vec![rustls::Certificate(certificate)], rustls::PrivateKey(client_key))?;

    // client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    // if options.keylog {
    //     client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    // }

    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));
    // endpoint.set_default_client_config(client_crypto);

    let localhost = Ipv4Addr::new(127, 0, 0, 1);
    let addr = SocketAddr::V4(SocketAddrV4::new(localhost, 4001));
    println!("Before connect");
    let conn: quinn::Connection = endpoint.connect(addr, "xx")?.await?;
    println!("After connect");
    // let request = format!("GET {}\r\n", url.path());
    // let start = Instant::now();
    // let rebind = options.rebind;
    // let host = options
    //     .host
    //     .as_ref()
    //     .map_or_else(|| url.host_str(), |x| Some(x))
    //     .ok_or_else(|| anyhow!("no hostname specified"))?;

    // eprintln!("connecting to {} at {}", host, remote);
    // let conn = endpoint
    //     .connect(remote, host)?
    //     .await
    //     .map_err(|e| anyhow!("failed to connect: {}", e))?;
    // eprintln!("connected at {:?}", start.elapsed());

    let mut stream = CombinedStream::new(conn.open_bi().await?);
    println!("Before multistream_handshake");
    multistream_handshake(&mut stream).await?;
    println!("Completed multistream handshake on bidi connection");

    // let (mut send0, mut recv0) = conn
    //     .open_bi()
    //     .await?;
    // println!("Opened bidirectional stream");
    // let mut send: quinn::SendStream = send0;
    // let mut recv: quinn::RecvStream = recv0;

    // loop {
    //     let mut buf: [u8; 1024] = [0; 1024];
    //     match recv.read(&mut buf).await? {
    //         Some(sz) => {
    //             println!("Read {} bytes", sz);
    //         }
    //         None => {
    //             break;
    //         }
    //     }
    // }

    match multistream_select(&mut stream, BITSWAP_PROTOCOL).await {
        Ok(SelectResponse::Accepted) => {
            println!("bitswap protocol accepted");
        },
        Ok(SelectResponse::Unsupported) => {
            return Err("bitswap protocol unsupported".into());
        }
        Err(e) => {
            return Err(e.into());
        }
    }

    let cid = String::from("QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc");

    bitswap_handler_show(node.clone(), Box::pin(stream), cid);

    loop {
        // keep the process alive
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }

    // Ok(())
}
