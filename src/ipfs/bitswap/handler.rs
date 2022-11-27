#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::sync::Arc;
use std::pin::Pin;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::util::io::AsyncStream;
use crate::util::util::{Indent, DebugHexDump};
use crate::libp2p::identify::Identify;
use crate::ipfs::node::IPFSNode;
use crate::libp2p::secio::{PublicKey, KeyType};
use crate::ipfs::types::cid::{CID, CIDPrefix, RawCID};
use crate::libp2p::multiaddr::{MultiAddr, Addr};
use crate::libp2p::io::{
    read_opt_length_prefixed_data,
    write_length_prefixed_data,
};
use super::message::{Message, WantList, Entry, WantType};
use super::block::get_block_cid;
use crate::ipfs::dagpb::{PBNode, PBLink};
use crate::ipfs::unixfs::{Data as UnixFsData};
use crate::ipfs::fs::{Node, Directory};

async fn bitswap_handler_inner(
    node: Arc<IPFSNode>,
    mut stream: Pin<Box<dyn AsyncStream>>,
    show_cid: Option<String>,
) -> Result<(), Box<dyn Error>> {

    if let Some(test_cid_str) = show_cid {
        // let test_cid_str = "QmQPeNsJPyVWPFDVHb77w8G42Fvo15z4bG2X8D2GhfbSXc"; // directory
        // let test_cid_str = "QmQy6xmJhrcC5QLboAcGFcAE1tC8CrwDVkrHdEYJkLscrQ"; // about.txt
        // let test_cid_str = "bafykbzacedwpv7rrtq2rrdxyz6nsqqxzqvq3rqglnp2h426nbqisl3juwzezy"; // /etc/services
        // let test_cid_str = "bafykbzaceaaqsv2wjwuhtzscq3ox2oryl3lqnui2plbutxlbhv4fcfol6i6ke"; // Python-3.8.1/

        let test_cid = CID::from_string(&test_cid_str)?;
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
    }

    let mut count = 0;

    loop {
        let data = match read_opt_length_prefixed_data(&mut stream).await? {
            Some(data) => data,
            None => {
                println!("[bitswap] peer closed connection");
                break;
            }
        };

        println!("[bitswap] received {} bytes:", data.len());
        // println!("{:#?}", Indent(&DebugHexDump(&data)));

        let message = match Message::from_pb(&data) {
            Ok(message) => message,
            Err(e) => {
                println!("[bitswap] decoding message failed: {}", e);
                break;
            }
        };

        // println!("[bitswap] message =\n{:#?}", Indent(&message));

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
            println!("data.len() = {}", data.len());
            // println!("data =\n{:#?}", Indent(&DebugHexDump(&block.data)));
            let node = PBNode::from_pb(&block.data)?;
            println!("node =\n{:#?}", node);
            match &node.bytes {
                None => println!("data = None"),
                Some(bytes) => {
                    let data = UnixFsData::from_pb(bytes)?;
                    println!("data =\n{:#?}", data);
                }
            }

            let fsnode = Node::from_dagpb_data(&block.data)?;
            match fsnode {
                Node::Directory(directory) => {
                    println!("directory fs node");
                    for entry in directory.entries {
                        println!("{:64} {:<12} {}", entry.cid.to_string(), entry.tsize, entry.name);
                    }
                }
                _ => {
                    println!("Other type of fs node");
                }
            }
        }

        count += 1;
    }

    stream.flush().await?;
    stream.shutdown().await?;
    Ok(())
}

pub fn bitswap_handler_show(node: Arc<IPFSNode>, stream: Pin<Box<dyn AsyncStream>>, show_cid: String) {
    println!("[bitswap] starting");
    tokio::spawn(async move {
        match bitswap_handler_inner(node, stream, Some(show_cid)).await {
            Ok(()) => {
                println!("[bitswap] finished");
            },
            Err(e) => {
                println!("[bitswap] error: {}", e);
            }
        }
    });
}

pub fn bitswap_handler(node: Arc<IPFSNode>, stream: Pin<Box<dyn AsyncStream>>) {
    println!("[bitswap] starting");
    tokio::spawn(async move {
        match bitswap_handler_inner(node, stream, None).await {
            Ok(()) => {
                println!("[bitswap] finished");
            },
            Err(e) => {
                println!("[bitswap] error: {}", e);
            }
        }
    });
}
