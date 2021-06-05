#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use futures::future::{join};
use rand::prelude::Rng;
use std::collections::BTreeSet;
use std::convert::Into;
use std::convert::TryInto;
// use std::error::Error;
// use std::io::Error;
use std::net::SocketAddr;
use std::pin::Pin;
use std::result::Result;
use std::sync::Arc;
use std::task::{Poll, Context};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::net::{UdpSocket, lookup_host};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use tokio::sync::mpsc;
use tokio::sync::Mutex;


use torrent::util::BinaryData;
use torrent::torrent::{Torrent};
use torrent::error;

#[derive(Debug)]
// enum WriterCommand {
//     Write(Vec<u8>),
//     Close,
// }
struct WriterCommand {}

enum Workitem {
    Interested,
    Piece,
}

struct PeerConnection {
    torrent: Torrent,
    disconnect: bool,
    choked: bool,
    interested: bool,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,
    they_have: BTreeSet<u32>,
    we_have: BTreeSet<u32>,
    tx: UnboundedSender<WriterCommand>,

    sent_bitfield: bool,
    active_request: bool,
}

fn bitfield_bytes_required(pieces_len: usize) -> usize {
    (pieces_len + 8 - 1) / 8
}

impl PeerConnection {
    pub fn new(torrent: Torrent, tx: UnboundedSender<WriterCommand>) -> PeerConnection {
        let they_have: BTreeSet<u32> = BTreeSet::new();
        let we_have: BTreeSet<u32> = BTreeSet::new();
        PeerConnection {
            torrent: torrent,
            disconnect: false,
            choked: true,
            interested: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
            they_have,
            we_have,
            // want,
            tx,
            sent_bitfield: false,
            active_request: false,
        }
    }

    // pub fn on_received(&mut self, data: &[u8]) {
    // }

    pub fn on_received_message(&mut self, message: &Message) {
        // println!("Received message: {:?}", message);
        match message {
            Message::Choke => {
                println!("Choke");
                self.choked = true;
            }
            Message::Unchoke => {
                println!("Unchoke");
                self.choked = false;
            }
            Message::BitField(b) => {
                println!("BitField: {}", BinaryData(&b));
                // let expected_bitfield_len = (self.torrent.pieces.len() + 8 - 1) / 8;
                let expected_bitfield_len = bitfield_bytes_required(self.torrent.pieces.len());
                if b.len() != expected_bitfield_len {
                    println!("Invalid bitfield length: expected {}, got {}", expected_bitfield_len, b.len());
                    self.disconnect = true;
                    return;
                }
            }
            Message::Piece(index, begin, block) => {
                println!("Piece index= {}, begin= {}, block= {}",
                    index, begin, BinaryData(block));
            }
            _ => {
                println!("Don't know how to handle message: {:?}", message);
            }
        }
        self.print_status();
        self.tx.send(WriterCommand {}).unwrap();
    }

    pub fn on_receive_error(&mut self, err_str: &str) {
        println!("Error while receiving message: {}", err_str);
        self.disconnect = true;
    }

    pub fn on_send_error(&mut self, err_str: &str) {
        println!("Error while sending message: {}", err_str);
        self.disconnect = true;
    }

    pub fn print_status(&self) {
        print!("Peer status: ");
        if self.choked {
            print!("C");
        }
        else {
            print!("U");
        }
        if self.interested {
            print!(" I");
        }
        else {
            print!(" N");
        }
        print!(" them {}/{} us {}/{}",
            self.they_have.len(), self.torrent.pieces.len(),
            self.we_have.len(), self.torrent.pieces.len());
        println!("");
    }

    // pub fn on_sent(&mut self, len: usize) {
    // }

    // pub fn on_send_error(&mut self, err: &std::io::Error) {
    // }

    // pub fn on_recv_error(&mut self, err: &std::io::Error) {
    // }
}

struct HandshakeMessage {
    info_hash: [u8; 20],
    peer_id: [u8; 20],
}

async fn send_handshake(stream: &mut WriteHalf<'_>, msg: &HandshakeMessage) -> Result<(), std::io::Error> {
    let mut request: Vec<u8> = Vec::new();
    request.push(19);
    request.extend_from_slice("BitTorrent protocol".as_bytes());
    request.extend_from_slice(&[0; 8]);
    request.extend_from_slice(&msg.info_hash);
    request.extend_from_slice(&msg.peer_id);
    println!("request.len() = {}", request.len());
    stream.write(&request).await?;
    Ok(())
}

async fn recv_handshake(stream: &mut ReadHalf<'_>) -> Result<HandshakeMessage, Box<dyn std::error::Error>> {
    let mut buf: [u8; 68] = [0; 68];
    stream.read_exact(&mut buf).await?;
    if buf[0] != 19 {
        return Err(error!("Expected {} as string length, expected 19", buf[0]));
    }
    if &buf[1..20] != b"BitTorrent protocol" {
        return Err(error!("Incorrect protocol; got {}", String::from_utf8_lossy(&buf[1..20])));
    }

    let mut info_hash: [u8; 20] = [0; 20];
    let mut peer_id: [u8; 20] = [0; 20];
    info_hash.copy_from_slice(&buf[28..48]);
    peer_id.copy_from_slice(&buf[48..68]);

    Ok(HandshakeMessage {
        info_hash,
        peer_id,
    })
}

#[derive(Debug)]
enum Message {
    KeepAlive,
    Choke,
    Unchoke,
    Interested,
    NotInterested,
    Have(u32),
    BitField(Vec<u8>),
    Piece(u32, u32, Vec<u8>),
    Unknown(u8, Vec<u8>),
}

const BUFSIZE: usize = 4;

async fn read_message_raw<'a>(reader: &mut ReadHalf<'a>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut len_buf: [u8; 4] = [0; 4];
    reader.read_exact(&mut len_buf).await?;
    let len: usize = u32::from_be_bytes(len_buf) as usize;
    // println!("Message length = {}", len);



    // if len == 0 {
    //     return Ok(Message::KeepAlive);
    // }

    let mut body: Vec<u8> = Vec::new();
    while body.len() < len {
        let remaining = len - body.len();
        let mut temp: [u8; BUFSIZE] = [0; BUFSIZE];
        let toread = if remaining > BUFSIZE { BUFSIZE } else { remaining };
        assert!(remaining > 0);
        assert!(toread <= BUFSIZE);
        let r = reader.read(&mut temp[0..toread]).await?;
        body.append(&mut Vec::from(&temp[0..r]));
        // println!("r = {}, body.len() = {}", r, body.len());
    }

    Ok(body)
}



async fn read_message<'a>(reader: &mut ReadHalf<'a>) -> Result<Message, Box<dyn std::error::Error>> {
    let mut body = read_message_raw(reader).await?;
    println!("read_message: body.len() = {}", body.len());


    if body.len() == 0 {
        return Ok(Message::KeepAlive);
    }
    else {
        let id = body.remove(0);
        // println!("read_message: id = {}", id);
        match id {
            0 => { // choke
                if body.len() != 0 {
                    return Err(error!("Choke body: {} bytes, expected 0", body.len()));
                }
                return Ok(Message::Choke);
            }
            1 => { // unchoke
                if body.len() != 0 {
                    return Err(error!("Unchoke body: {} bytes, expected 0", body.len()));
                }
                return Ok(Message::Unchoke);
            }
            2 => { // interested
                if body.len() != 0 {
                    return Err(error!("Interested body: {} bytes, expected 0", body.len()));
                }
                return Ok(Message::Interested);
            }
            3 => { // not interested
                if body.len() != 0 {
                    return Err(error!("NotInterested body: {} bytes, expected 0", body.len()));
                }
                return Ok(Message::NotInterested);
            }
            4 => { // have
                if body.len() != 4 {
                    return Err(error!("Have body: {} bytes, expected 4", body.len()));
                }
                let mut data: [u8; 4] = [0; 4];
                data.copy_from_slice(&body[0..4]);
                let piece_index = u32::from_be_bytes(data);
                return Ok(Message::Have(piece_index));
            }
            5 => { // bitfield
                return Ok(Message::BitField(body));
            }
            // 6 => { // request
            // }
            7 => { // piece
                if body.len() < 8 {
                    return Err(error!("Have body: {} bytes, expected >= 8", body.len()));
                }
                let mut index_raw: [u8; 4] = [0; 4];
                index_raw.copy_from_slice(&body[0..4]);
                let index = u32::from_be_bytes(index_raw);

                let mut begin_raw: [u8; 4] = [0; 4];
                begin_raw.copy_from_slice(&body[4..8]);
                let begin = u32::from_be_bytes(begin_raw);

                return Ok(Message::Piece(index, begin, Vec::from(&body[8..])));
            }
            // 8 => { // cancel
            // }
            // 9 => { // port
            // }
            _ => {
                return Ok(Message::Unknown(id, body))
            }
        }
    }
}

async fn connection_reader<'a>(peer: Arc<Mutex<PeerConnection>>, mut reader: ReadHalf<'a>) {
    loop {
        if peer.lock().await.disconnect {
            break;
        }
        let res: Result<Message, String> = read_message(&mut reader).await.map_err(|e| format!("{}", e));
        match res {
            Ok(msg) => {
                peer.lock().await.on_received_message(&msg);
            },
            Err(err_str) => {
                // let x: () = e;
                // println!("Error reading from connection: {}", e);
                peer.lock().await.on_receive_error(&err_str);
            }
        }
    }
}

enum WriterAction {
    Interested,
    BitField,
    Request,
}

async fn write_raw_message(writer: &mut WriteHalf<'_>, body: &[u8])
    -> Result<(), Box<dyn std::error::Error>> {
    writer.write_all(&(body.len() as u32).to_be_bytes()).await?;
    writer.write_all(&body).await?;
    Ok(())
}

async fn writer_iteration(peer: &Arc<Mutex<PeerConnection>>, writer: &mut WriteHalf<'_>)
    -> Result<(), Box<dyn std::error::Error>> {

    loop {
        let mut pieces_len: usize = 0;
        let mut action: Option<WriterAction> = None;
        {
            let p = peer.lock().await;
            pieces_len = p.torrent.pieces.len();
            if !p.sent_bitfield {
                action = Some(WriterAction::BitField);
            }
            else if !p.interested {
                action = Some(WriterAction::Interested);
            }
            else if !p.choked && !p.active_request {
                action = Some(WriterAction::Request);
            }
        }

        match action {
            Some(WriterAction::Interested) => {
                let mut body: Vec<u8> = vec![2];
                write_raw_message(writer, &body).await?;
                println!("connection_writer: sent interested");
                {
                    let mut p = peer.lock().await;
                    p.interested = true;
                    p.print_status();
                }
            }
            Some(WriterAction::BitField) => {
                let nbytes = bitfield_bytes_required(pieces_len);
                let mut body: Vec<u8> = vec![5];
                for i in 0..nbytes {
                    body.push(0);
                }
                write_raw_message(writer, &body).await?;
                println!("connection_writer: sent bitfield");
                {
                    let mut p = peer.lock().await;
                    p.sent_bitfield = true;
                    p.print_status();
                }

            }
            Some(WriterAction::Request) => {
                let mut body: Vec<u8> = Vec::new();
                body.push(6);
                let index: u32 = 0;
                let begin: u32 = 0;
                let length: u32 = 16 * 1024;
                body.extend_from_slice(&index.to_be_bytes());
                body.extend_from_slice(&begin.to_be_bytes());
                body.extend_from_slice(&length.to_be_bytes());
                write_raw_message(writer, &body).await?;
                println!("connection_writer: sent request");
                {
                    let mut p = peer.lock().await;
                    p.active_request = true;
                    p.print_status();
                }
            }
            None => {
                break;
            }
        }
    }

    Ok(())
}

async fn connection_writer<'a>(peer: Arc<Mutex<PeerConnection>>, mut writer: WriteHalf<'a>,
                               mut rx: UnboundedReceiver<WriterCommand>) {
    loop {
        if peer.lock().await.disconnect {
            break;
        }

        let res = writer_iteration(&peer, &mut writer).await.map_err(|e| format!("{}", e));
        match res {
            Ok(_) => (),
            Err(err_str) => {
                peer.lock().await.on_send_error(&err_str);
                return;
            }
        }


        if let None = rx.recv().await {
            break;
        }
    }



    // while let Some(msg) = rx.recv().await {
    //     match msg {
    //         WriterCommand::Write(data) => {
    //             match writer.write_all(&data).await {
    //                 Ok(_) => (),
    //                 Err(e) => {
    //                     peer.lock().await.on_send_error(&format!("{}", e));
    //                     return;
    //                 }
    //             };
    //             // let mut pos: usize = 0;
    //             // while pos < data.len() {
    //             //     match writer.write(&data[pos..]).await {
    //             //         Ok(bytes_written) => {
    //             //             println!("{}: Wrote {} bytes", conn.connection_id, bytes_written);
    //             //             pos += bytes_written;
    //             //         }
    //             //         Err(e) => {
    //             //             println!("{}: Error writing to connection: {}", conn.connection_id, e);
    //             //             println!("connection_writer {} finished", conn.connection_id);
    //             //             return;
    //             //         }
    //             //     }
    //             // }
    //         }
    //         WriterCommand::Close => {
    //             // println!("connection_writer {} finished", conn.connection_id);
    //             return;
    //         }
    //     }
    // }
}

// async fn connection_writer<'a>(state: Arc<State>, conn: Arc<Connection>, mut writer: WriteHalf<'a>,
//                 mut rx: UnboundedReceiver<WriterCommand>) {
//     while let Some(msg) = rx.recv().await {
//         match msg {
//             WriterCommand::Write(data) => {
//                 let mut pos: usize = 0;
//                 while pos < data.len() {
//                     match writer.write(&data[pos..]).await {
//                         Ok(bytes_written) => {
//                             println!("{}: Wrote {} bytes", conn.connection_id, bytes_written);
//                             pos += bytes_written;
//                         }
//                         Err(e) => {
//                             println!("{}: Error writing to connection: {}", conn.connection_id, e);
//                             println!("connection_writer {} finished", conn.connection_id);
//                             return;
//                         }
//                     }
//                 }
//             }
//             WriterCommand::Close => {
//                 println!("connection_writer {} finished", conn.connection_id);
//                 return;
//             }
//         }
//     }
// }


async fn do_peer_connection(peer: String, torrent: Torrent) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let peer_addr: SocketAddr = match lookup_host(&peer).await?.next() {
        None => return Err(error!("Lookup failed: {}", peer)),
        Some(r) => r,
    };
    println!("Got peer: {}", peer_addr);
    let info_hash = &torrent.info_hash.data;
    println!("info_hash = {}", BinaryData(info_hash));

    let peer_id: [u8; 20] = [0xf2, 0x25, 0x27, 0x6a, 0xee, 0x14, 0x16, 0xa5, 0xe2, 0x45,
                             0x60, 0x6d, 0xd4, 0x8a, 0xf3, 0x4f, 0x88, 0xc0, 0x1d, 0x15];
    println!("peer_id = {}", BinaryData(&peer_id));

    let out_handshake = HandshakeMessage {
        info_hash: torrent.info_hash.data,
        peer_id: peer_id,
    };

    let mut stream: TcpStream = TcpStream::connect(peer_addr).await?;
    println!("Connected");

    let (mut reader, mut writer): (ReadHalf, WriteHalf) = stream.split();

    send_handshake(&mut writer, &out_handshake).await?;
    println!("Sent handshake");

    let in_handshake = recv_handshake(&mut reader).await?;
    println!("Received handshake");
    println!("Remote info hash = {}", BinaryData(&in_handshake.info_hash));
    println!("Remote peer id = {}", BinaryData(&in_handshake.peer_id));


    let (writer_tx, writer_rx) = mpsc::unbounded_channel::<WriterCommand>();
    writer_tx.send(WriterCommand {})?;
    let peer = Arc::new(Mutex::new(PeerConnection::new(torrent, writer_tx)));
    let reader_future = connection_reader(peer.clone(), reader);
    let writer_future = connection_writer(peer.clone(), writer, writer_rx);
    join(reader_future, writer_future).await;
    println!("Finished");

    Ok(())
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let args: Vec<String> = std::env::args().collect();

    let peer = match args.get(1) {
        Some(peer) => peer,
        None => {
            eprintln!("No peer specified");
            std::process::exit(1);
        }
    };

    let filename = match args.get(2) {
        Some(filename) => filename,
        None => {
            eprintln!("No filename specified");
            std::process::exit(1);
        }
    };


    let torrent_data = std::fs::read(filename)?;
    let torrent = Torrent::from_bytes(&torrent_data)?;



    let peer: String = peer.clone();
    let handle = tokio::spawn(async move {
        // do_peer_connection(peer, torrent).await
        match do_peer_connection(peer, torrent).await {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        }
    });

    match handle.await {
        _ => ()
    }

    Ok(())
}
