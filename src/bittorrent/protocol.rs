#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::error::Error;
use std::fmt;
use bytes::Bytes;
use super::data::BitField;

pub struct Node {
    port: u16,
}

impl Node {
    pub fn new(port: u16) -> Self {
        Node {
            port
        }
    }
}

struct ConnectRequest {
    transaction_id: u32,
}

struct ConnectResponse {
    transaction_id: u32,
    connection_id: u32,
}

impl ConnectRequest {
    fn encode(&self, out: &mut Vec<u8>) {
        let protocol_id: u64 = 0x41727101980;
        out.extend_from_slice(&protocol_id.to_be_bytes());
        let action: u32 = 0; // connect
        out.extend_from_slice(&action.to_be_bytes());
        out.extend_from_slice(&self.transaction_id.to_be_bytes());
    }
}

pub async fn run_client() -> Result<(), Box<dyn Error>> {
    Ok(())
}

#[derive(Debug)]
pub struct Handshake {
    pub reserved: [u8; 8],
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct Request {
    pub index: u32,
    pub begin: u32,
    pub length: u32,
}

#[derive(Debug)]
pub enum Message {
    Handshake(Handshake),
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    BitField(Bytes),
    Request(Request),
    Piece(u32, u32, Bytes),
    Cancel(Request),
    Port(u16),
}

#[derive(Debug, Clone)]
pub enum ProtocolError {
    IncorrectMessageLength(u8, usize),
    UnknownMessage(u8),
    InvalidHandshake,
}

impl Error for ProtocolError {
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProtocolError::IncorrectMessageLength(id, len) => {
                write!(f, "Incorrect length for message {}: {}", id, len)
            }
            ProtocolError::UnknownMessage(message_id) => {
                write!(f, "Unknown message {}", message_id)
            }
            ProtocolError::InvalidHandshake => {
                write!(f, "Invalid handshake")
            }
        }
    }
}
