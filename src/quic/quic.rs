// #![allow(unused_variables)]
#![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::collections::BTreeMap;
use super::protocol::frame::Frame;
use super::protocol::ids::{ConnectionId, StreamId};

pub struct FlowAccounting {
    pub max_bytes: u64,
    pub cur_bytes: u64,
}

pub struct Stream {
    recv_acct: FlowAccounting,
    send_acct: FlowAccounting,
}

pub struct Connection {
    dst_connection_id: ConnectionId,
    src_connection_id: ConnectionId,
    recv_acct: FlowAccounting,
    send_acct: FlowAccounting,
    streams: BTreeMap<StreamId, Stream>,
}

pub struct Packet {
    // pub dst_connection_id: ConnectionId,
    // pub src_connection_id: ConnectionId,
    pub packet_no: u64,
    pub frames: Vec<Frame>,
}
