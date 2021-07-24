#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::sync::Arc;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::io::AsyncStream;
use crate::util::{Indent, DebugHexDump};
use crate::libp2p::identify::Identify;
use crate::ipfs::node::IPFSNode;
use crate::p2p::{PublicKey, KeyType};
use crate::libp2p::multiaddr::{MultiAddr, Addr};
use crate::libp2p::io::{
    read_opt_length_prefixed_data,
    write_length_prefixed_data,
};
use super::message::Message;

async fn bitswap_handler_inner(
    node: Arc<IPFSNode>,
    mut stream: Box<dyn AsyncStream>,
) -> Result<(), Box<dyn Error>> {
    loop {
        let data = match read_opt_length_prefixed_data(&mut stream).await? {
            Some(data) => data,
            None => {
                println!("[bitswap] peer closed connection");
                break;
            }
        };

        println!("[bitswap] received data:");
        println!("{:#?}", Indent(&DebugHexDump(&data)));

        match Message::from_pb(&data) {
            Ok(message) => {
                println!("[bitswap] message = {:#?}", message);
            }
            Err(e) => {
                println!("[bitswap] decoding message failed: {}", e);
                break;
            }
        }
    }

    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

pub fn bitswap_handler(node: Arc<IPFSNode>, stream: Box<dyn AsyncStream>) {
    println!("[bitswap] starting");
    tokio::spawn(async move {
        match bitswap_handler_inner(node, stream).await {
            Ok(()) => {
                println!("[bitswap] finished");
            },
            Err(e) => {
                println!("[bitswap] error: {}", e);
            }
        }
    });
}
