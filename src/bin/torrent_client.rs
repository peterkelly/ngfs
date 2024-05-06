// cargo run --bin torrent_client -- download samples/wallpapers.torrent 127.0.0.1:56276

#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::error::Error;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::sync::Arc;
use std::task::Poll;
use std::convert::TryInto;
use std::fmt;
use tokio::net::{UdpSocket, TcpSocket, TcpStream, lookup_host};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use clap::Parser;
use url::Url;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use ring::rand::{SystemRandom, SecureRandom};
use ngfs::util::util::{BinaryData, DebugHexDump, Indent};
use ngfs::bittorrent::torrent::{Torrent};
use ngfs::bittorrent::data::{BitField};
use ngfs::bittorrent::protocol::{Message, Handshake, Request, ProtocolError};

const LISTEN_PORT: u16 = 6681;

#[derive(Parser)]
#[command(name="torrent_client")]
struct Options {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    /// Show the list of trackers contained in the torrent file
    Trackers(Trackers),
    /// Send an announce request to a single specified tracker
    Announce(Announce),
    /// Parse a file containing an announce response
    ///
    /// This file can be obtained using the `announce` command
    ParseAnnounceResponse(ParseAnnounceResponse),
    /// Download a torrent from a specific peer
    ///
    /// First make announce request to a tracker to get the list of peers. Then
    /// use the `download` command with one of the ip:port socket addresses. The
    /// program will attempt to download the torrent from that single peer only.
    Download(Download),
}

#[derive(Parser)]
struct Trackers {
    filename: String,
}

#[derive(Parser)]
struct Announce {
    filename: String,
    #[arg(long)]
    tracker_no: usize,
}

#[derive(Parser)]
struct ParseAnnounceResponse {
    filename: String,
}

#[derive(Parser)]
struct Download {
    /// Torrent filename
    filename: String,
    /// ip:port of peer
    peer: String,
}



fn generate_peer_id() -> Result<[u8; 20], Box<dyn Error>> {
    let mut random: [u8; 20] = Default::default();
    SystemRandom::new().fill(&mut random)?;
    for i in 0..8 {
        random[i] = b'-';
    }
    Ok(random)
}

fn generate_transaction_id() -> Result<u32, Box<dyn Error>> {
    let mut random: [u8; 4] = Default::default();
    SystemRandom::new().fill(&mut random)?;
    let transaction_id = u32::from_be_bytes(random);
    Ok(transaction_id)
}

async fn open_tracker_connection(
    sock: &UdpSocket,
    tracker_addr: &SocketAddr,
) -> Result<u64, Box<dyn Error>> {
    let transaction_id = generate_transaction_id()?;

    println!("transaction_id = {:08x}", transaction_id);

    let mut to_send: Vec<u8> = Vec::new();
    to_send.put_u64(0x41727101980); // magic constant
    to_send.put_u32(0); // action: connect
    to_send.put_u32(transaction_id);
    println!("to_send (len {}) =", to_send.len());
    println!("{:#?}", Indent(&DebugHexDump(&to_send)));
    // sock.connect(tracker_addr).await?;
    sock.send_to(&to_send, tracker_addr).await?;

    // sock.send_to(&initial, remote_addr).await?;

    let mut buf = [0; 4096];
    let (len, addr) = sock.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, addr);
    println!("{:#?}", Indent(&DebugHexDump(&buf[0..len])));

    if len != 16 {
        return Err(format!("Expected {} bytes, got {}", 16, len).into());
    }

    let mut resp_action_bytes: [u8; 4] = [0; 4];
    resp_action_bytes.copy_from_slice(&buf[0..4]);
    let resp_action = u32::from_be_bytes(resp_action_bytes);

    if resp_action != 0 {
        return Err(format!("Expected action to be 0, got {}", resp_action).into());
    }

    let mut resp_transaction_id_bytes: [u8; 4] = [0; 4];
    resp_transaction_id_bytes.copy_from_slice(&buf[4..8]);
    let resp_transaction_id = u32::from_be_bytes(resp_transaction_id_bytes);

    let mut resp_connection_id_bytes: [u8; 8] = [0; 8];
    resp_connection_id_bytes.copy_from_slice(&buf[8..16]);
    let resp_connection_id = u64::from_be_bytes(resp_connection_id_bytes);

    println!("resp_action = 0x{:08x}", resp_action);
    println!("resp_transaction_id = 0x{:08x}", resp_transaction_id);
    println!("resp_connection_id = 0x{:08x}", resp_connection_id);

    if resp_transaction_id != transaction_id {
        return Err(format!("Expected transaction_id to be 0x{:08x}, got 0x{:08x}",
            transaction_id, resp_transaction_id).into());
    }
    Ok(resp_connection_id)
}

struct AnnounceRequest {
    connection_id: u64,  // 0       64-bit integer  connection_id
                         // 8       32-bit integer  action          1 // announce
                         // 12      32-bit integer  transaction_id
    info_hash: [u8; 20], // 16      20-byte string  info_hash
    peer_id: [u8; 20],   // 36      20-byte string  peer_id
    downloaded: u64,     // 56      64-bit integer  downloaded
    left: u64,           // 64      64-bit integer  left
    uploaded: u64,       // 72      64-bit integer  uploaded
    event: u32,          // 80      32-bit integer  event
    ip_address: u32,     // 84      32-bit integer  IP address
    key: u32,            // 88      32-bit integer  key
    num_want: i32,       // 92      32-bit integer  num_want        -1 // default
    port: i32,           // 96      16-bit integer  port
}

async fn send_tracker_request(
    sock: &UdpSocket,
    tracker_addr: &SocketAddr,
    connection_id: u64,
    info_hash: &[u8; 20],
    my_port: u16,
) -> Result<(), Box<dyn Error>> {

    let peer_id: [u8; 20] = [0; 20]; // TODO

    let transaction_id = generate_transaction_id()?;
    let mut to_send: Vec<u8> = Vec::new();

    // Offset  Size    Name    Value
    // 0       64-bit integer  connection_id
    to_send.put_u64(connection_id);
    // 8       32-bit integer  action          1 // announce
    to_send.put_u32(1);
    // 12      32-bit integer  transaction_id
    to_send.put_u32(transaction_id);
    // 16      20-byte string  info_hash
    to_send.extend_from_slice(info_hash);
    // 36      20-byte string  peer_id
    to_send.extend_from_slice(&peer_id);
    // 56      64-bit integer  downloaded
    to_send.put_u64(0);
    // 64      64-bit integer  left
    to_send.put_u64(0);
    // 72      64-bit integer  uploaded
    to_send.put_u64(0);
    // 80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
    to_send.put_u32(0);
    // 84      32-bit integer  IP address      0 // default
    to_send.put_u32(0);
    // 88      32-bit integer  key
    to_send.put_u32(0);
    // 92      32-bit integer  num_want        -1 // default
    to_send.put_i32(-1);
    // 96      16-bit integer  port
    to_send.put_u16(my_port);
    println!("to_send.len() = {}", to_send.len());

    sock.send_to(&to_send, tracker_addr).await?;
    Ok(())
}

async fn receive_tracker_response(
    sock: &UdpSocket,
) -> Result<AnnounceResponse, Box<dyn Error>> {
    let mut buf = [0; 4096];
    let (len, addr) = sock.recv_from(&mut buf).await?;
    println!("Received {} bytes from {}", len, addr);
    println!("{:#?}", Indent(&DebugHexDump(&buf[0..len])));

    println!("send_tracker_request done");
    std::fs::write("response.bin", &buf[0..len])?;

    let response = AnnounceResponse::parse(&buf[0..len])?;


    Ok(response)
}


async fn run_with_tracker(tracker_url: &Url, info_hash: &[u8; 20]) -> Result<(), Box<dyn Error>> {
    println!("Using tracker {}", tracker_url);
    // let sock = UdpSocket::bind("0.0.0.0:8080").await?;
    let (Some(host), Some(port)) = (tracker_url.host_str(), tracker_url.port()) else {
        return Err(format!("Missing host or port: {}", tracker_url).into());
    };
    let listen_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, LISTEN_PORT));
    let sock = UdpSocket::bind(listen_addr).await?;



    let socket_str = format!("{}:{}", host, port);
    println!("socket_str = {:?}", socket_str);

    let resolved_addrs: Vec<SocketAddr> = lookup_host(&socket_str).await?.collect();
    for addr in resolved_addrs.iter() {
        println!("Resolved: {}", addr);
    }

    let Some(tracker_addr) = resolved_addrs.get(0) else {
        return Err(format!("Cannot find any IP addresses for {}", socket_str).into());
    };
    println!("Connecting to {} ({})", tracker_url, tracker_addr);

    // let tracker_address: SocketAddrV4 = socket_str.parse()?;
    // println!("tracker_address = {}", tracker_address);

    let connection_id = open_tracker_connection(&sock, &tracker_addr).await?;

    println!("Connected to tracker with connection_id 0x{:08x}", connection_id);
    send_tracker_request(&sock, &tracker_addr, connection_id, info_hash, LISTEN_PORT).await?;

    let response = receive_tracker_response(&sock).await?;
    println!("{:#?}", response);


    // let mut buf = [0; 4096];
    // loop {
    //     let (len, addr) = sock.recv_from(&mut buf).await?;
    //     println!("{:?} bytes received from {:?}", len, addr);
    //     // println!("{:#?}", Indent(&DebugHexDump(&buf[0..len])));
    //     handler.on_recv_packet(&mut buf[0..len], addr);
    //     return Ok(());

    //     // let len = sock.send_to(&buf[..len], addr).await?;
    //     // println!("{:?} bytes sent", len);
    // }

    Ok(())
}

#[derive(Debug)]
struct AnnounceResponse {
    transaction_id: u32,
    interval: u32,
    leechers: u32,
    seeders: u32,
    peers: Vec<SocketAddr>,
}

impl AnnounceResponse {
    fn parse(data: &[u8]) -> Result<AnnounceResponse, Box<dyn Error>> {
        if data.len() < 4 {
            return Err(format!("Expected at least 4 bytes, got {}", data.len()).into());
        }

        let mut action_bytes: [u8; 4] = [0; 4];
        action_bytes.copy_from_slice(&data[0..4]);
        let action = u32::from_be_bytes(action_bytes);

        if action != 1 {
            return Err(format!("Expected action to be 1, got {}", action).into());
        }

        if data.len() < 20 {
            return Err(format!("Expected at least 20 bytes, got {}", data.len()).into());
        }

        let mut temp: [u8; 4] = [0; 4];
        temp.copy_from_slice(&data[4..8]);
        let resp_transaction_id = u32::from_be_bytes(temp);

        let mut temp: [u8; 4] = [0; 4];
        temp.copy_from_slice(&data[8..12]);
        let resp_interval = u32::from_be_bytes(temp);

        let mut temp: [u8; 4] = [0; 4];
        temp.copy_from_slice(&data[12..16]);
        let resp_leechers = u32::from_be_bytes(temp);

        let mut temp: [u8; 4] = [0; 4];
        temp.copy_from_slice(&data[16..20]);
        let resp_seeders = u32::from_be_bytes(temp);

        let mut response = AnnounceResponse {
            transaction_id: resp_transaction_id,
            interval: resp_interval,
            leechers: resp_leechers,
            seeders: resp_seeders,
            peers: Vec::new(),
        };

        let mut offset = 20;
        while offset + 6 <= data.len() {

            let mut temp: [u8; 4] = [0; 4];
            temp.copy_from_slice(&data[offset..offset + 4]);
            let peer_ip = Ipv4Addr::from(u32::from_be_bytes(temp));

            let mut temp: [u8; 2] = [0; 2];
            temp.copy_from_slice(&data[offset + 4..offset + 6]);
            let peer_port = u16::from_be_bytes(temp);

            let peer_addr = SocketAddrV4::new(peer_ip, peer_port);

            // println!("Peer {}:{}", peer_ip, peer_port);

            response.peers.push(SocketAddr::V4(peer_addr));

            offset += 6;
        }


        Ok(response)
    }
}

fn read_torrent_file(filename: &str) -> Result<Torrent, Box<dyn Error>> {
    let data: Vec<u8> = match std::fs::read(filename) {
        Ok(data) => data,
        Err(err) => {
            return Err(format!("Cannot read {}: {}", filename, err).into());
        }
    };
    let torrent = Torrent::from_bytes(&data).map_err(|e| format!("{}", e))?;
    Ok(torrent)
}

fn get_tracker_urls(torrent: &Torrent) -> Vec<Url> {
    let mut tracker_urls: Vec<Url> = Vec::new();

    for group in torrent.tracker_groups.iter() {
        for tracker in group.members.iter() {
            // println!("Tracker {}", tracker.url);
            match Url::parse(&tracker.url) {
                Ok(url) => {
                    tracker_urls.push(url);
                }
                Err(e) => {
                    println!("WARNING: Invalid tracker URL {:?}", tracker.url);
                }
            }
            // let url: () = Url::parse(&tracker.url);
        }
    }
    tracker_urls
}

struct ReceivedBlock {
    index: u32,
    begin: u32,
    data: Bytes,
}

struct Transfer {
    torrent: Torrent,
    we_have: BitField,

    pending_requests: Vec<Request>,
    active_requests: Vec<Request>,
    completed_requests: Vec<ReceivedBlock>,

    // received_blocks: Vec<ReceivedBlock>,
}

impl Transfer {
    fn new(torrent: Torrent) -> Self {
        let piece_count = torrent.pieces.len();
        let mut transfer = Transfer {
            torrent,
            we_have: BitField::new(piece_count),

            pending_requests: Vec::new(),
            active_requests: Vec::new(),
            completed_requests: Vec::new(),
        };

        // let request_length = 320;
        let default_request_length = 16384;

        for i in 0..piece_count {
            let mut this_piece_length: usize = transfer.torrent.piece_length;
            // let mut length: usize = 16384;
            if i + 1 == piece_count && this_piece_length > transfer.torrent.last_piece_length() {
                this_piece_length = transfer.torrent.last_piece_length();
            }

            let mut begin: usize = 0;
            while begin < this_piece_length {
                let remaining = this_piece_length - begin;
                let mut request_length: usize = std::cmp::min(default_request_length, remaining);
                // println!("adding pending request with index {}, begin {}, request_length {}",
                //     i, begin, request_length);
                transfer.pending_requests.push(Request {
                    index: i as u32,
                    begin: begin as u32,
                    length: request_length as u32,
                });
                begin += request_length;
            }
        }

        // transfer.pending_requests.reverse();

        transfer
    }

    // fn is_piece_complete(&self, index: usize) -> bool {
    //     unimplemented!()
    // }

    // fn have_byte_for_piece(&self, index: usize, offset: usize) -> bool {
    //     unimplemented!()
    // }

    fn start_request(&mut self) -> Option<Request> {
        if self.pending_requests.len() == 0 {
            return None;
        }
        else {
            let req = self.pending_requests.remove(0);
            self.active_requests.push(req.clone());
            return Some(req);
        }
    }

    fn complete_request(&mut self, index: u32, begin: u32, data: Bytes) {
        let mut active_request_index: Option<usize> = None;
        for (i, req) in self.active_requests.iter().enumerate() {
            if req.index == index && req.begin == begin && (req.length as usize) == data.len() {
                active_request_index = Some(i);
                break;
            }
        }
        match active_request_index {
            None => {
                println!("Recieved PIECE but no active request: index {}, begin {}, length {}",
                    index, begin, data.len());
            }
            Some(active_request_index) => {
                self.active_requests.remove(active_request_index);
                self.completed_requests.push(ReceivedBlock {
                    index,
                    begin,
                    data,
                })
            }
        }
    }
}

struct PeerConnection {
    // torrent: Arc<Torrent>,
    // we_are_interested: bool,
    // we_are_choked: bool,
    // they_are_interested: bool,
    // they_are_choked: bool,
    they_have: BitField,


    am_choking: bool, // this client is choking the peer
    am_interested: bool, // client is interested in the peer
    peer_choking: bool, // peer is choking this client
    peer_interested: bool, // peer is interested in this client

    incoming_data: BytesMut,
    peer_finished_sending: bool,
    done: bool,
    received_handshake: bool,
    received_first_message: bool,
    error_message: Option<String>,
}

impl PeerConnection {
    fn new(piece_count: usize) -> Self {
        // let mut they_have = BitField::new(torrent.pieces.len());
        PeerConnection {
            // torrent,
            am_choking: true,
            am_interested: false,
            peer_choking: true,
            peer_interested: false,
            they_have: BitField::new(piece_count),
            incoming_data: BytesMut::new(),
            peer_finished_sending: false,
            done: false,
            received_handshake: false,
            received_first_message: false,
            error_message: None,
            // they_have,
        }
    }

    fn report_protocol_violation<T>(&mut self, msg: T) where T: Into<String> {
        self.error_message = Some(msg.into());
        self.done = true;
    }
}

struct PeerOutput {
    outgoing_data: Vec<u8>,
}

impl PeerOutput {
    fn new() -> PeerOutput {
        PeerOutput {
            outgoing_data: Vec::new(),
        }
    }

    // async fn send_have(&mut self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
    //     unimplemented!()
    // }

    async fn send_outgoing_data(&mut self, stream: &mut TcpStream) -> Result<(), Box<dyn Error>> {
        if self.outgoing_data.len() == 0 {
            return Ok(());
        }
        stream.write_all(&self.outgoing_data).await?;
        self.outgoing_data = Vec::new();
        return Ok(());
    }

    fn queue_unchoke(&mut self) {
        // let msg_raw: [u8; 5] = [0x00, 0x00, 0x00, 0x01, 0x01];
        // stream.write_all(&msg_raw).await?;
        self.queue_msg(&[1]);
    }

    fn queue_interested(&mut self) {
        self.queue_msg(&[2]);
    }

    fn queue_not_interested(&mut self) {
        self.queue_msg(&[3]);
    }

    fn queue_msg(&mut self, body: &[u8]) {
        let msg_len_bytes = (body.len() as u32).to_be_bytes();
        self.outgoing_data.extend_from_slice(&msg_len_bytes);
        self.outgoing_data.extend_from_slice(&body);
    }

    fn queue_request(
        &mut self,
        index: u32,
        begin: u32,
        length: u32,
    ) {
        let mut msg_raw: Vec<u8> = Vec::new();
        msg_raw.push(6);
        msg_raw.extend_from_slice(&index.to_be_bytes());
        msg_raw.extend_from_slice(&begin.to_be_bytes());
        msg_raw.extend_from_slice(&length.to_be_bytes());

        self.queue_msg(&msg_raw);
    }
}

async fn recv_more_data(stream: &mut TcpStream, conn: &mut PeerConnection) -> Result<(), Box<dyn Error>> {
    // println!("recv_more_data");
    let mut buf: [u8; 10240] = [0; 10240];
    let nbytes = stream.read(&mut buf).await?;
    // println!("Read {} bytes", nbytes);
    if nbytes == 0 {
        conn.peer_finished_sending = true;
    }
    else {
        conn.incoming_data.extend_from_slice(&buf[0..nbytes]);
    }
    Ok(())
}




fn handle_message(
    transfer: &mut Transfer,
    conn: &mut PeerConnection,
    output: &mut PeerOutput,
    msg: Message,
) -> Result<(), Box<dyn Error>> {
    let mut want_more_requests = false;

    match msg {
        Message::Handshake(handshake) => {
            // println!(
            //     "<=== HANDSHAKE reserved = {:?}, info_hash = {:?}, peer_id = {:?}",
            //     BinaryData(&handshake.reserved),
            //     BinaryData(&handshake.info_hash),
            //     BinaryData(&handshake.peer_id),
            // );
            println!("<=== HANDSHAKE");
            println!("    reserved  = {:?}", BinaryData(&handshake.reserved));
            println!("    info_hash = {:?}", BinaryData(&handshake.info_hash));
            println!("    peer_id   = {:?}", BinaryData(&handshake.peer_id));
        }
        Message::KeepAlive => {
            println!("<=== KEEPALIVE");
        }
        Message::Choke => {
            println!("<=== CHOKE");
        }
        Message::Unchoke => {
            println!("<=== UNCHOKE");
            want_more_requests = true;
            // println!("    Before sending request");
            // // output.queue_request(0, 0, 1024);
            // output.queue_request(6, 500, 1024);
            // println!("    After sending request");
        }
        Message::Interested => {
            println!("<=== INTERESTED");
        }
        Message::NotInterested => {
            println!("<=== NOTINTERESTED");
        }
        Message::Have(piece_index) => {
            println!("<=== HAVE piece_index = {}", piece_index);
        }
        Message::BitField(data) => {
            println!("<=== BITFIELD");
            if conn.received_first_message {
                return Err("Received bitfield after first message".into());
            }
            println!("    Received bitfield ({} bytes)", data.len());
            let piece_count = transfer.torrent.pieces.len();
            let expected_bitfield_size = (piece_count + 7) / 8;
            // assert!(data.len() == message_len - 1);
            let actual_bitfield_size = data.len();

            check_message_len(5, &data, expected_bitfield_size)?;
            // if actual_bitfield_size != expected_bitfield_size {
            //     return Err(
            //         ProtocolError::IncorrectMessageLength(message_id,message_len).into()
            //     );
            // }
            conn.they_have.update_from_bytes(&data);
            println!(
                "    Of {} pieces, they have {} and need {}",
                transfer.torrent.pieces.len(),
                conn.they_have.num_set(),
                conn.they_have.num_clear()
            );


            // FIXME: Find a better place to send this from
            output.queue_unchoke();
            output.queue_interested();
        }
        Message::Request(request) => {
            println!(
                "<=== REQUEST index = {}, begin = {}, length = {}",
                request.index,
                request.begin,
                request.length,
            );
        }
        Message::Piece(index, begin, block) => {
            println!("<=== PIECE index = {}, begin = {}, block = <{} bytes>",
                index, begin, block.len());
            transfer.complete_request(index, begin, block);
            want_more_requests = true;
        }
        Message::Cancel(request) => {
            println!(
                "<=== CANCEL index = {}, begin = {}, length = {}",
                request.index,
                request.begin,
                request.length,
            );
        }
        Message::Port(port) => {
            println!("<=== PORT {}", port);
        }
    }

    if want_more_requests {
        println!("want_more_requests: #pending = {}, #active = {}, #completed = {}",
            transfer.pending_requests.len(),
            transfer.active_requests.len(),
            transfer.completed_requests.len());

        // for req in transfer.active_requests.iter() {
        //     println!("    active: index {}, begin {}, length {}",
        //         req.index, req.begin, req.length);
        // }

        let max_active_requests = 100;

        while transfer.active_requests.len() <= max_active_requests {

            let next_request = transfer.start_request();
            // let mut next_request: Option<Request> = None;
            // next_request = Some(Request {
            //     index: 6,
            //     begin: 500,
            //     length: 1024,
            // });
            if let Some(request) = next_request {
                output.queue_request(request.index, request.begin, request.length);
            }
            else {
                output.queue_not_interested();
                break;
            }
        }
    }

    Ok(())
}

fn get_next_message(
    transfer: &mut Transfer,
    conn: &mut PeerConnection,
    output: &mut PeerOutput,
) -> Poll<Result<Option<Message>, Box<dyn Error>>> {
    if !conn.received_handshake {
        if conn.incoming_data.len() < 68 {
            return Poll::Pending;
        }
        if &conn.incoming_data[0..20] != b"\x13BitTorrent protocol" {
            return Poll::Ready(Err(ProtocolError::InvalidHandshake.into()));
        }

        let handshake = Handshake {
            reserved: conn.incoming_data[20..28].try_into().unwrap(),
            info_hash: conn.incoming_data[28..48].try_into().unwrap(),
            peer_id: conn.incoming_data[48..68].try_into().unwrap(),
        };

        conn.incoming_data.advance(68);
        conn.received_handshake = true;
        return Poll::Ready(Ok(Some(Message::Handshake(handshake))));
    }

    if conn.incoming_data.len() < 4 {
        return Poll::Pending;
    }

    let mut message_len_bytes: [u8; 4] = [0; 4];
    message_len_bytes.copy_from_slice(&conn.incoming_data[0..4]);
    let message_len = u32::from_be_bytes(message_len_bytes) as usize;

    if message_len == 0 {
        conn.incoming_data.advance(4);
        return Poll::Ready(Ok(Some(Message::KeepAlive)));
    }

    if conn.incoming_data.len() < 5 {
        return Poll::Pending;
    }

    let message_id = conn.incoming_data[4];
    if conn.incoming_data.len() < 4 + (message_len as usize) {
        return Poll::Pending;
    }

    conn.incoming_data.advance(5);

    let message_body = conn.incoming_data.copy_to_bytes(message_len - 1);
    match parse_message(message_id, message_len, message_body) {
        Ok(message) => {
            Poll::Ready(Ok(Some(message)))
        }
        Err(e) => {
            Poll::Ready(Err(e.into()))
        }
    }
}

fn check_message_len(message_id: u8, message_body: &[u8], expected: usize) -> Result<(), ProtocolError> {
    if message_body.len() != expected {
        return Err(ProtocolError::IncorrectMessageLength(message_id, message_body.len()).into())
    }
    else {
        return Ok(())
    }
}

fn check_message_len_atleast(message_id: u8, message_body: &[u8], expected: usize) -> Result<(), ProtocolError> {
    if message_body.len() < expected {
        return Err(ProtocolError::IncorrectMessageLength(message_id, message_body.len()).into())
    }
    else {
        return Ok(())
    }
}

fn parse_message(
    message_id: u8,
    message_len: usize,
    mut message_body: Bytes,
) -> Result<Message, ProtocolError> {
    // println!("Received message id {}", message_id);
    match message_id {
        0 => {
            check_message_len(message_id, &message_body, 0)?;
            Ok(Message::Choke)
        }
        1 => {
            check_message_len(message_id, &message_body, 0)?;
            Ok(Message::Unchoke)
        }
        2 => {
            check_message_len(message_id, &message_body, 0)?;
            Ok(Message::Interested)
        }
        3 => {
            check_message_len(message_id, &message_body, 0)?;
            Ok(Message::NotInterested)
        }
        4 => {
            check_message_len(message_id, &message_body, 4)?;
            let mut piece_index_bytes: [u8; 4] = [0; 4];
            piece_index_bytes.copy_from_slice(&message_body);
            let piece_index = u32::from_be_bytes(piece_index_bytes);
            Ok(Message::Have(piece_index))
        }
        5 => {
            Ok(Message::BitField(message_body.clone()))
        }
        6 => {
            unimplemented!()
        }
        7 => {
            check_message_len_atleast(message_id, &message_body, 0)?;
            let index = message_body.get_u32();
            let begin = message_body.get_u32();
            Ok(Message::Piece(index, begin, message_body))
        }
        8 => {
            println!("Received cancel; message_len = {}", message_len);
            // Poll::Ready(Ok(()))
            unimplemented!()
        }
        9 => {
            println!("Received port; message_len = {}", message_len);
            // Poll::Ready(Ok(()))
            unimplemented!()
        }
        _ => {
            println!("Received message with unknown id {}", message_id);
            Err(ProtocolError::UnknownMessage(message_id))
        }
    }
    // conn.received_first_message = true;

    // Poll::Ready(Ok(()))
}

fn encode_handshake(info_hash: &[u8; 20], peer_id: &[u8; 20]) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();
    res.push(19); // pstrlen
    res.extend_from_slice(b"BitTorrent protocol"); // pstr
    res.extend_from_slice(&[0; 8]); // reserved
    res.extend_from_slice(info_hash);
    res.extend_from_slice(peer_id);
    res
}

async fn do_peer(transfer: &mut Transfer, addr_str: &str) -> Result<(), Box<dyn Error>> {
    let mut conn = PeerConnection::new(transfer.torrent.pieces.len());

    // Open a TCP connection to the peer
    let addr: SocketAddr = addr_str.parse()?;
    let socket = TcpSocket::new_v4()?;
    let mut stream: TcpStream = socket.connect(addr).await?;
    println!("Connected to peer");

    // Send the handshake
    let out_handshake = encode_handshake(&transfer.torrent.info_hash.data, &generate_peer_id()?);
    println!("out_handshake.len() = {}", out_handshake.len());
    println!("out_handshake =\n{:#?}", DebugHexDump(&out_handshake));
    stream.write_all(&out_handshake).await?;

    // Enter the receive loop
    while !conn.done && !conn.peer_finished_sending {
        let mut output = PeerOutput::new();
        match get_next_message(transfer, &mut conn, &mut output) {
            Poll::Pending => {
                recv_more_data(&mut stream, &mut conn).await?;
            }
            Poll::Ready(Ok(Some(message))) => {
                handle_message(transfer, &mut conn, &mut output, message)?;
            }
            Poll::Ready(Ok(None)) => {
                // TODO: set conn.done here, not in message parsing function
                break;
            }
            Poll::Ready(Err(e)) => {
                conn.report_protocol_violation(format!("{}", e));
            }
        }
        output.send_outgoing_data(&mut stream).await?;
    }

    if let Some(error_message) = &conn.error_message {
        println!("Client finished with error: {}", error_message);
    }
    else {
        println!("Client finished without error");
    }

    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Options::parse();
    // println!("filename = {:?}", opt.filename);

    match opt.subcmd {
        SubCommand::Trackers(sub) => {
            let torrent = read_torrent_file(&sub.filename)?;
            for group in torrent.tracker_groups.iter() {
                for tracker in group.members.iter() {
                    println!("{}", tracker.url);
                }
            }
        }
        SubCommand::Announce(sub) => {
            let torrent = read_torrent_file(&sub.filename)?;
            let tracker_urls = get_tracker_urls(&torrent);
            let Some(tracker_url) = tracker_urls.get(sub.tracker_no) else {
                return Err(format!("Unknown tracker {}", sub.tracker_no).into());
            };
            run_with_tracker(&tracker_url, &torrent.info_hash.data).await?;
        }
        SubCommand::ParseAnnounceResponse(sub) => {
            let data = std::fs::read(sub.filename)?;
            println!("Response: {} bytes", data.len());
            println!("{:#?}", DebugHexDump(&data));
            let response = AnnounceResponse::parse(&data)?;
            println!("{:#?}", response);
            return Ok(());
        }
        SubCommand::Download(sub) => {
            // test_bitfield_size();
            // test_bitfield_update_from_bytes();



            let torrent = read_torrent_file(&sub.filename)?;

            // TODO: Check unerflow
            // let last_piece_length = torrent.piece_length - (torrent.piece_length * torrent.pieces.len() - torrent.total_length);
            // let last_piece_length: usize;
            // if torrent.pieces.len() == 0 {
            //     last_piece_length = torrent.total_length;
            // }
            // else {
            //     last_piece_length = torrent.total_length - torrent.piece_length * (torrent.pieces.len() - 1);
            // }


            println!("Torrent file {}", sub.filename);
            println!("    info hash    = {}", torrent.info_hash);
            println!("    piece count  = {}", torrent.pieces.len());
            println!("    piece length = {}", torrent.piece_length);
            println!("    total length = {}", torrent.total_length);
            println!("    total psize  = {}", torrent.piece_length * torrent.pieces.len());
            println!("    last length  = {}", torrent.last_piece_length());
            println!("Downloading from peer {}", sub.peer);
            let mut transfer = Transfer::new(torrent);
            do_peer(&mut transfer, &sub.peer).await?;
        }
    }

    Ok(())
}

// use std::collections::BTreeMap;
// use ngfs::Id;

// fn main() -> Result<(), Box<dyn Error>> {
//     let mut ids: Vec<Id> = Vec::new();
//     let count = 12;
//     let mut map: BTreeMap<Id, String> = BTreeMap::new();
//     for i in 0..count {
//         let id = Id::default();
//         ids.push(id);
//     }
//     for (i, id) in ids.iter().enumerate() {
//         let value = format!("Item {}", i);
//         // let x: () = id.clone();
//         map.insert(id.clone(), value);
//     }

//     for (key, value) in map.iter() {
//         println!("{} = {}", key, value);
//     }


//     let a = Id::default();
//     let b = Id::default();
//     let c = Id::default();

//     println!("");
//     println!("a = {} -- {:?}", a, a);
//     println!("b = {} -- {:?}", b, b);
//     println!("c = {} -- {:?}", c, c);
//     println!("a == b ? {}", a == b);
//     println!("a < b ? {}", a < b);
//     println!("a <= b ? {}", a <= b);
//     println!("a > b ? {}", a > b);
//     println!("a >= b ? {}", a >= b);

//     // map.insert(a, String::from("One"));

//     Ok(())
// }
