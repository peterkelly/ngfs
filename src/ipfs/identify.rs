use std::error::Error;
use std::sync::Arc;
use std::pin::Pin;
use tokio::io::AsyncWriteExt;
use ring::signature::KeyPair;
use crate::util::io::AsyncStream;
use crate::libp2p::identify::Identify;
use crate::ipfs::node::IPFSNode;
use crate::libp2p::peer_id::{PublicKey, KeyType};
use crate::libp2p::multiaddr::{MultiAddr, Addr};
use crate::libp2p::io::write_length_prefixed_data;
use crate::formats::protobuf::protobuf::ToPB;

async fn identify_handler_inner(
    node: Arc<IPFSNode>,
    mut stream: Pin<Box<dyn AsyncStream>>,
) -> Result<(), Box<dyn Error>> {
    let identify = Identify {
        protocol_version: String::from("ipfs/0.1.0"),
        agent_version: String::from("test/0.0.0"),
        public_key: PublicKey {
            key_type: KeyType::Ed25519,
            data: Vec::from(node.host_keypair.public_key().as_ref()),
        },
        listen_addrs: vec![
            MultiAddr(vec![
                Addr::IP4("127.0.0.1".parse().unwrap()),
                Addr::TCP(4001),
            ]),
        ],
        observed_addr: MultiAddr(vec![
            Addr::IP4("127.0.0.1".parse().unwrap()),
            Addr::TCP(4004),
        ]),
        protocols: vec![
            // String::from("/p2p/id/delta/1.0.0"),
            String::from("/ipfs/id/1.0.0"),
            // String::from("/ipfs/id/push/1.0.0"),
            // String::from("/ipfs/ping/1.0.0"),
            // String::from("/libp2p/circuit/relay/0.1.0"),
            // String::from("/ipfs/lan/kad/1.0.0"),
            // String::from("/libp2p/autonat/1.0.0"),
            String::from("/ipfs/bitswap/1.2.0"),
            // String::from("/ipfs/bitswap/1.1.0"),
            // String::from("/ipfs/bitswap/1.0.0"),
            // String::from("/ipfs/bitswap"),
            // String::from("/x/"),
        ],
        signed_peer_record: None,
    };


    write_length_prefixed_data(&mut stream, &identify.to_pb()).await?;
    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

pub fn identify_handler(node: Arc<IPFSNode>, stream: Pin<Box<dyn AsyncStream>>) {
    println!("[identify] starting");
    tokio::spawn(async move {
        match identify_handler_inner(node, stream).await {
            Ok(()) => {
                println!("[identify] finished");
            },
            Err(e) => {
                println!("[identify] error: {}", e);
            }
        }
    });
}
