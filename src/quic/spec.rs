#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::collections::BTreeMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::error::Error;
use std::fmt;
use crate::util::util::BinaryData;

pub struct Address {
}

pub enum ConnectionIdError {
    Invalid,
}

impl std::error::Error for ConnectionIdError {
}

impl fmt::Display for ConnectionIdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Invalid connection id")
    }
}

impl fmt::Debug for ConnectionIdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ConnectionId(pub Vec<u8>);

impl ConnectionId {
    pub fn from_raw(data: &[u8]) -> Result<ConnectionId, ConnectionIdError> {
        if data.len() <= 20 {
            Ok(ConnectionId(Vec::from(data)))
        }
        else {
            Err(ConnectionIdError::Invalid)
        }
    }
}

impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.len() == 0 {
            write!(f, ".")
        }
        else {
            write!(f, "{}", BinaryData(&self.0))
        }
    }
}

impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

pub struct StreamId(pub u64); // 62-bit integer

impl StreamId {
    pub fn initiator(&self) -> Initiator {

        // Section 2.1: "The least significant bit (0x01) of the stream ID identifies the
        // initiator of the stream. Client-initiated streams have even-numbered stream IDs (with
        // the bit set to 0), and server-initiated streams have odd-numbered stream IDs (with the
        // bit set to 1)."
        if self.0 & 0x01 == 0 {
            Initiator::Client
        }
        else {
            Initiator::Server
        }
    }

    pub fn directionality(&self) -> Directionality {
        // Section 2.1: "The second least significant bit (0x02) of the stream ID distinguishes
        // between bidirectional streams (with the bit set to 0) and unidirectional streams (with
        // the bit set to 1)."
        if self.0 & 0x02 == 0 {
            Directionality::Bidirectional
        }
        else {
            Directionality::Unidirectional
        }
    }

    pub fn stream_type(&self) -> StreamType {
        match self.0 & 0x03 {
            0x00 => StreamType::ClientInitiatedBidirectional,
            0x01 => StreamType::ServerInitiatedBidirectional,
            0x02 => StreamType::ClientInitiatedUnidirectional,
            _    => StreamType::ServerInitiatedUnidirectional,
        }
    }
}

pub struct StreamIdAllocator {
    next: u64,
}

impl StreamIdAllocator {
    pub fn new() -> Self {
        StreamIdAllocator {
            next: 0,
        }
    }

    pub fn allocate(stream_type: StreamType) -> StreamId {
        // Section 2.1: "The stream space for each type begins at the minimum value (0x00 through
        // 0x03, respectively); successive streams of each type are created with numerically
        // increasing stream IDs. A stream ID that is used out of order results in all streams of
        // that type with lower-numbered stream IDs also being opened."
        todo!()
    }
}

pub enum Initiator {
    Client,
    Server,
}

pub enum Directionality {
    Bidirectional,
    Unidirectional,
}

pub enum StreamType {
    ClientInitiatedBidirectional,  // 0x00
    ServerInitiatedBidirectional,  // 0x01
    ClientInitiatedUnidirectional, // 0x02
    ServerInitiatedUnidirectional, // 0x03
}


pub struct Datagram {
    packets: Vec<Packet>,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub frames: Vec<Frame>,
    pub src_connection_id: ConnectionId,
    pub dst_connection_id: ConnectionId,
    pub packet_no: u64,
    pub packet_type: PacketType,
}

impl Packet {
    pub fn is_ack_eliciting(&self) -> bool {
        todo!()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PacketType {
    Initial,
    ZeroRTT,
    Handshake,
    Retry,

    VersionNegotiation, // ?
    ShortHeader, // ?
}

#[derive(Clone, Debug)]
pub enum Frame {
    Padding,            // 0x00
    Ping,               // 0x01
    Ack,                // 0x02-0x03
    ResetStream,        // 0x04
    StopSending,        // 0x05
    Crypto(CryptoFrame),             // 0x06
    NewToken,           // 0x07
    Stream,             // 0x08-0x0f
    MaxData,            // 0x10
    MaxStreamData,      // 0x11
    MaxStreams,         // 0x12-0x13
    DataBlocked,        // 0x14
    StreamDataBlocked,  // 0x15
    StreamsBlocked,     // 0x16-0x17
    NewConnectionId,    // 0x18
    RetireConnectionId, // 0x19
    PathChallenge,      // 0x1a
    PathResponse,       // 0x1b
    ConnectionClose(ConnectionCloseFrame),    // 0x1c-0x1d
    HandshakeDone,      // 0x1e
}



pub struct StreamFrame {
    fin: bool, // type is in encoding only, we just need to represent fin
    stream_id: StreamId,
    offset: u64,
    length: u64,
    data: Vec<u8>,
}


pub struct Stream {
    recv_bytes: u64,
    recv_limit: u64,
    recv_final_size: Option<u64>,
}

pub struct Connection {
    recv_bytes: u64,
    recv_limit: u64,
    streams: BTreeMap<StreamId, Stream>,
    // ids: Vec<ConnectionId>,
    our_connection_id: ConnectionId, // they choose this, and use it to talk to us
    their_connection_id: ConnectionId, // we choose this, and use it to talk to them
}

impl Connection {
    pub fn new(our_connection_id: ConnectionId, their_connection_id: ConnectionId) -> Self {
        Connection {
            recv_bytes: 0,
            recv_limit: 0,
            streams: BTreeMap::new(),
            our_connection_id,
            their_connection_id,
        }
    }
}

pub enum EndpointType {
    Client,
    Server,
}

pub fn generate_connection_id() -> ConnectionId {
    todo!()
}

pub struct QUIC {
    connections: Vec<Rc<RefCell<Connection>>>,
    endpoint_type: EndpointType,
}

impl QUIC {
    fn on_receive_datagram(&mut self, datagram: &Datagram, env: &mut Environment) {
        for packet in datagram.packets.iter() {
            self.on_receive_packet(packet, env);
        }
    }

    fn on_receive_packet(&mut self, packet: &Packet, env: &mut Environment) {
        for conn in self.connections.iter() {
            let mut conn = conn.borrow_mut();
            if packet.dst_connection_id == conn.our_connection_id {
                // Found match for existing connection
                conn.on_receive_packet(packet, env);
                return;
            }
        }

        // Connection id does not match
        // TODO
        match self.endpoint_type {
            EndpointType::Client => {
                env.log("Packet received with unknown connection id");
            }
            EndpointType::Server => {

                if packet.packet_type != PacketType::Initial {
                    env.log("Non-initial packet received with unknown connection id");
                }
                else {
                    // Create a new connection
                    let mut conn = Connection::new(
                        packet.dst_connection_id.clone(),
                        generate_connection_id(),
                    );
                    conn.on_receive_packet(packet, env);
                    self.connections.push(Rc::new(RefCell::new(conn)));
                }
            }
        }
    }
}

impl Connection {
    fn on_receive_packet(&mut self, packet: &Packet, env: &mut Environment) {
        for frame in packet.frames.iter() {
            self.on_receive_frame(frame, env);
        }
    }

    fn on_receive_frame(&mut self, frame: &Frame, env: &mut Environment) {
    }
}

struct Environment {
}

impl Environment {
    fn log(&mut self, msg: impl Into<String>) {
    }

    fn signal_error(&mut self, name: &str) {
    }

    fn add_outgoing_packet(&mut self, packet: Packet) {
    }
}

#[derive(Clone, Debug)]
pub struct CryptoFrame {
    pub start_offset: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConnectionCloseFrame {
    pub error_code: u64,
    pub frame_type: Option<u64>,
    pub reason: String,
}

struct Buffer(Vec<u8>);

impl Buffer {
    fn new() -> Self {
        Buffer(Vec::new())
    }

    fn append(&mut self, data: impl AsRef<[u8]>) {
        self.0.extend_from_slice(data.as_ref());
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Display for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "<")?;
        for (i, byte) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "{:02x}", byte)?;
        }
        write!(f, ">")
    }
}

struct CryptoStream {
    pending: Vec<CryptoFrame>,
    data: Buffer,
    data_start_offset: u64,
    // data_end_offset: u64,
}

impl CryptoStream {
    fn new() -> Self {
        CryptoStream {
            pending: Vec::new(),
            data: Buffer::new(),
            data_start_offset: 0,
        }
    }

    fn add_frame(&mut self, frame: CryptoFrame) {
        self.pending.push(frame);
        self.check_pending();
    }

    fn check_pending(&mut self) {
        loop {
            let mut index: Option<usize> = None;
            let data_end_offset = self.data_start_offset + (self.data.len() as u64);
            for (i, frame) in self.pending.iter().enumerate() {
                if frame.start_offset <= data_end_offset {
                    index = Some(i);
                    break;
                }
            }
            if let Some(index) = index {
                let frame = self.pending.remove(index);
                if let Some(start_offset_in_frame) = data_end_offset.checked_sub(frame.start_offset) {
                    self.data.append(&frame.data[start_offset_in_frame as usize..]);
                }
            }
            else {
                break;
            }
        }
        println!("check_pending: offset = {}, data = {}", self.data_start_offset, self.data);
    }

    fn send(&mut self, start_offset: u64, data: impl AsRef<[u8]>) {
        self.add_frame(CryptoFrame { start_offset, data: Vec::from(data.as_ref()) });
    }
}

pub fn test() -> Result<(), Box<dyn Error>> {
    println!("quic test");
    let mut stream = CryptoStream::new();
    stream.send(0, vec![0x20, 0x21, 0x22]);

    Ok(())
}
