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
use crate::cid::{CID, CIDPrefix, RawCID};
use crate::libp2p::multiaddr::{MultiAddr, Addr};
use crate::libp2p::io::{
    read_opt_length_prefixed_data,
    write_length_prefixed_data,
};
use super::message::{Message, WantList, Entry, WantType};
use super::block::get_block_cid;
use crate::ipfs::dagpb::{PBNode, PBLink};
use crate::ipfs::unixfs::{Data as UnixFsData};

async fn bitswap_handler_inner(
    node: Arc<IPFSNode>,
    mut stream: Box<dyn AsyncStream>,
) -> Result<(), Box<dyn Error>> {
    // let test_cid_str = "QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc"; // directory
    // let test_cid_str = "QmQy6xmJhrcC5QLboAcGFcAE1tC8CrwDVkrHdEYJkLscrQ"; // about.txt
    let test_cid_str = "bafykbzacedwpv7rrtq2rrdxyz6nsqqxzqvq3rqglnp2h426nbqisl3juwzezy"; // /etc/services
    let test_cid = CID::from_string(test_cid_str)?;
    let request_message = Message {
        wantlist: Some(WantList {
                entries: vec![
                    Entry {
                        block: RawCID(test_cid.to_bytes()),
                        priority: 1,
                        cancel: false,
                        want_type: WantType::Block,
                        send_dont_have: true,
                    }
                ],
                full: false,
            }),
        blocks: vec![],
        payload: vec![],
        block_presence: vec![],
        pending_bytes: None,
    };
    println!("Before sending request");
    write_length_prefixed_data(&mut stream, &request_message.to_pb()).await?;
    stream.flush().await?;
    println!("After sending request");

    let mut count = 0;

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

        let message = match Message::from_pb(&data) {
            Ok(message) => message,
            Err(e) => {
                println!("[bitswap] decoding message failed: {}", e);
                break;
            }
        };

        println!("[bitswap] message =\n{:#?}", Indent(&message));

        let encoded = message.to_pb();
        println!("**************** Encoded message matches? {}", encoded == data);
        if encoded != data {
            println!("original =\n{:#?}", Indent(&DebugHexDump(&data)));
            println!("encoded =\n{:#?}", Indent(&DebugHexDump(&encoded)));
        }

        for (block_index, block) in message.blocks.iter().enumerate() {
            println!("Block {}:", block_index);
            let cid_prefix = CIDPrefix::from_bytes(&block.prefix)?;
            println!("cid_prefix = {:?}", cid_prefix);
            let cid = get_block_cid(&cid_prefix, &block.data)?;
            println!("cid = {:?}", cid);
            println!("    = {}", cid.to_string());
            println!("data =\n{:#?}", Indent(&DebugHexDump(&block.data)));
            let node = PBNode::from_pb(&block.data)?;
            println!("node =\n{:#?}", node);
            match &node.bytes {
                None => println!("data = None"),
                Some(bytes) => {
                    let data = UnixFsData::from_pb(bytes)?;
                    println!("data =\n{:#?}", data);
                }
            }
        }

        count += 1;
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
