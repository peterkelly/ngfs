// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

const ID_PROTOCOL: &[u8] = b"/ipfs/id/1.0.0\n";
const ID_PROTOCOL_STR: &str = "/ipfs/id/1.0.0";
const BITSWAP_PROTOCOL_STR: &str = "/ipfs/bitswap/1.2.0";
const BITSWAP_PROTOCOL: &[u8] = b"/ipfs/bitswap/1.2.0\n";

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;
use std::pin::Pin;
use clap::Parser;
use tokio::net::{TcpStream};
use tokio::io::AsyncWriteExt;
use torrent::util::util::escape_string;
use torrent::libp2p::tls::generate_certificate;
use torrent::libp2p::io::{
    read_opt_length_prefixed_data,
    write_length_prefixed_data,
};
use torrent::libp2p::multistream::{
    multistream_handshake,
    multistream_list,
    multistream_select,
    SelectResponse,
};
use torrent::libp2p::mplex::{Mplex, Acceptor};
use torrent::tls::protocol::client::{
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
};
use torrent::util::io::AsyncStream;
use torrent::error;
use torrent::ipfs::node::{IPFSNode, ServiceRegistry};
use torrent::ipfs::identify::identify_handler;
use torrent::ipfs::bitswap::handler::{bitswap_handler, bitswap_handler_show};


#[derive(Parser)]
#[command(name="ipfs")]
struct Opt {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    Test,
    Show(Show),
}

#[derive(Parser)]
struct Show {
    #[arg()]
    cid: String,
}






async fn connection_handler2(
    node: Arc<IPFSNode>,
    services: Arc<ServiceRegistry>,
    mut stream: Pin<Box<dyn AsyncStream>>,
    accept_count: usize,
) -> Result<(), Box<dyn Error>> {
    multistream_handshake(&mut stream).await?;

    // let mut count = 0;
    loop {
        let data = match read_opt_length_prefixed_data(&mut stream).await? {
            Some(data) => data,
            None => {
                println!("{}: peer terminated stream normally", accept_count);
                return Ok(());
            }
        };
        // if count == 0 {
            println!("{}: peer requested service: {}",
                accept_count, escape_string(&String::from_utf8_lossy(&data)));
        // }
        // count += 1;
        match services.lookup(&data) {
            Some(handler) => {
                write_length_prefixed_data(&mut stream, ID_PROTOCOL).await?;
                stream.flush().await?;
                handler(node, stream);
                return Ok(())
            }
            None => {
                write_length_prefixed_data(&mut stream, b"na\n").await?;
                stream.flush().await?;
            }
        }
    }
}

async fn connection_handler(
    node: Arc<IPFSNode>,
    services: Arc<ServiceRegistry>,
    stream: Pin<Box<dyn AsyncStream>>,
    accept_count: usize,
)
{
    match connection_handler2(node, services, stream, accept_count).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("{}: Handler error: {}", accept_count, e);
        }
    }
}

async fn accept_loop(
    node: Arc<IPFSNode>,
    services: Arc<ServiceRegistry>,
    mut acceptor: Acceptor,
) {
    let mut accept_count: usize = 0;
    loop {
        match acceptor.accept().await {
            Ok(Some(stream)) => {
                println!("{}: accept_loop(): new connection", accept_count);
                tokio::spawn(connection_handler(
                    node.clone(),
                    services.clone(),
                    Box::pin(stream),
                    accept_count));
                accept_count += 1;
            }
            Ok(None) => {
                println!("{}: accept_loop(): no more connections (underlying transport closed)",
                    accept_count);
                return;
            }
            Err(e) => {
                eprintln!("{}: accept_loop(): {}", accept_count, e);
                return;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let mut rng = rand::rngs::OsRng {};
    let dalek_keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut rng);
    let node = Arc::new(IPFSNode::new(dalek_keypair));
    let mut registry = ServiceRegistry::new();
    registry.add(ID_PROTOCOL_STR, Box::new(&identify_handler));
    registry.add(BITSWAP_PROTOCOL_STR, Box::new(&bitswap_handler));
    let registry = Arc::new(registry);

    let client_key = openssl::rsa::Rsa::generate(2048)?.private_key_to_der()?;
    let rsa_key_pair = ring::signature::RsaKeyPair::from_der(&client_key)?;
    let certificate = generate_certificate(&rsa_key_pair, &node.dalek_keypair)?;

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

    let protocol_names = ["libp2p"];
    let mut conn = establish_connection(Box::pin(socket), config, &protocol_names).await?;
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

    let mplex = Mplex::new(Box::pin(conn));
    // mplex.set_logging_enabled(true);

    let (acceptor, mut connector) = mplex.split();
    tokio::spawn(accept_loop(node.clone(), registry.clone(), acceptor));

    // println!("-------- Before sleep");
    // tokio::time::sleep(Duration::from_millis(3000)).await;
    // println!("-------- After sleep");
    // println!();
    // println!();
    // println!();

    // {
    //     let mut id_stream = connector.connect(Some("id-test")).await?;
    //     multistream_handshake(&mut id_stream).await?;
    //     match multistream_select(&mut id_stream, ID_PROTOCOL).await {
    //         Ok(SelectResponse::Accepted) => {
    //             println!("id protocol accepted");
    //         },
    //         Ok(SelectResponse::Unsupported) => {
    //             return Err(error!("id protocol accepted").into());
    //         }
    //         Err(e) => {
    //             return Err(e.into());
    //         }
    //     }

    //     let identify_data = read_length_prefixed_data(&mut id_stream).await?;
    //     match Identify::from_pb(&identify_data) {
    //         Ok(identify) => {
    //             println!("Parse identify:");
    //             println!("{:#?}", identify);
    //         }
    //         Err(e) => {
    //             println!("Parse identify failed");
    //             return Err(e);
    //         }
    //     }
    // }

    let opt = Opt::parse();
    match opt.subcmd {
        SubCommand::Test => {
            println!("Test: sitting passively, waiting for connections");
        }
        SubCommand::Show(args) => {
            let mut stream = connector.connect(None).await?;
            multistream_handshake(&mut stream).await?;
            match multistream_select(&mut stream, BITSWAP_PROTOCOL).await {
                Ok(SelectResponse::Accepted) => {
                    println!("bitswap protocol accepted");
                },
                Ok(SelectResponse::Unsupported) => {
                    return Err(error!("bitswap protocol accepted").into());
                }
                Err(e) => {
                    return Err(e.into());
                }
            }

            bitswap_handler_show(node.clone(), Box::pin(stream), args.cid.clone());
        }
    }

    loop {
        // keep the process alive
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    // Ok(())

}
