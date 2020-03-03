#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::pin::Pin;
use std::result::Result;
use std::io::Error;
use std::task::{Poll, Context};
use futures::future::{Future, select, Either};
use tokio::net::TcpStream;
use tokio::prelude::*;
use std::convert::TryInto;
use std::convert::Into;
use tokio::net::{UdpSocket, lookup_host};
// use std::error::Error;
use std::net::SocketAddr;
use rand::prelude::Rng;

use torrent::util::BinaryData;
use torrent::torrent::{Torrent};

struct PeerConnection {
    choked: bool,
    interested: bool,
    outgoing: Vec<u8>,
    incoming: Vec<u8>,
}

impl PeerConnection {
    pub fn new() -> PeerConnection {
        PeerConnection {
            choked: true,
            interested: false,
            incoming: Vec::new(),
            outgoing: Vec::new(),
        }
    }

    pub fn on_received(&mut self, data: &[u8]) {
    }

    pub fn on_sent(&mut self, len: usize) {
    }

    pub fn on_send_error(&mut self, err: &std::io::Error) {
    }

    pub fn on_recv_error(&mut self, err: &std::io::Error) {
    }
}

// async fn connection_loop(conn: PeerConnection, stream: &mut TcpStream) {
//     loop {
//         if conn.outgoing.len() > 0 {
//             let mut inbuf: [u8; 1] = [0; 1];
//             let read_future = stream.read(&mut inbuf);
//             let write_future = stream.write(&conn.outgoing);
//             let selection = futures::future::select(read_future, write_future);
//         }
//     }
// }

async fn test<T>(f: impl Future<Output=T>) -> T {
    unimplemented!()
}

// type PinnedRead = Pin<Box<dyn Future<Output=Result<usize, Error>>>>;
// type PinnedWrite = Pin<Box<dyn Future<Output=Result<usize, Error>>>>;

// type PinnedRead = Box<dyn Future<Output=Result<usize, Error>> + std::marker::Unpin>;
// type PinnedWrite = Box<dyn Future<Output=Result<usize, Error>> + std::marker::Unpin>;

// struct ReadWriteFutures {
//     read_future: Option<PinnedRead>,
//     write_future: Option<PinnedWrite>,
// }

// enum ReadWriteOutput {
//     Read(usize, Option<PinnedRead>),
//     Written(usize, Option<PinnedWrite>),
//     Empty,
// }

// impl Future for ReadWriteFutures {
//     type Output = ReadWriteOutput;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
//         if let Some(read_future) = &mut self.read_future {
//             let read_poll = Future::poll(Pin::new(read_future), cx);
//         }
//         // if let Some(write_future) = &self.write_future {
//         // }
//         return Poll::Ready(ReadWriteOutput::Empty);
//     }
// }

type BoxedRWFuture = Box<dyn Future<Output=Result<usize, Error>>>;

async fn do_peer_connection(peer: String, torrent: Torrent) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let peer_addr: SocketAddr = lookup_host(peer).await?.next().unwrap();
    println!("Got peer: {}", peer_addr);
    let info_hash = &torrent.info_hash.data;
    println!("info_hash = {}", BinaryData(info_hash));

    let peer_id: [u8; 20] = [0xf2, 0x25, 0x27, 0x6a, 0xee, 0x14, 0x16, 0xa5, 0xe2, 0x45,
                             0x60, 0x6d, 0xd4, 0x8a, 0xf3, 0x4f, 0x88, 0xc0, 0x1d, 0x15];
    println!("peer_id = {}", BinaryData(&peer_id));

    let mut request: Vec<u8> = Vec::new();
    request.push(19);
    request.extend_from_slice("BitTorrent protocol".as_bytes());
    request.extend_from_slice(&[0; 8]);
    request.extend_from_slice(info_hash);
    request.extend_from_slice(&peer_id);
    println!("request.len() = {}", request.len());

    let mut stream = TcpStream::connect(peer_addr).await.unwrap();
    // let x: () = stream;
    println!("created stream");

    let writer = stream.write(&request);
    // let x: () = writer;
    let result = writer.await;
    println!("wrote to stream; success={:?}", result.is_ok());
    // let x: () = result;

    let mut buf: [u8; 65536] = [0; 65536];
    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));

    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    // std::fs::write("peer_response", &buf[..r])?;

    // let conn = PeerConnection::new();
    // use std::sync::{Mutex, Arc};
    // let (mut reader, mut writer) = stream.split();
    // let mut reader = Arc::new(Mutex::new(reader));
    // let mut writer = Arc::new(Mutex::new(writer));

    // let handle1 = tokio::spawn(async move {
    //     for i in 1..20 {
    //         let wr = writer.lock().unwrap();
    //         match wr.write(b"x").await {
    //             Ok(w) => {},
    //             Err(e) => {},
    //         }
    //     }
    // });

    // let handle2 = tokio::spawn(async move {
    //     for i in 1..20 {
    //         let mut inbuf: [u8; 1] = [0; 1];
    //         let rd = reader.lock().unwrap();
    //         match rd.read(&mut buf).await {
    //             Ok(w) => {},
    //             Err(e) => {},
    //         }
    //     }
    // });

    // match handle1.await {
    //     _ => ()
    // }
    // match handle2.await {
    //     _ => ()
    // }



    // loop {
    //     if conn.outgoing.len() > 0 {
    //         let mut inbuf: [u8; 1] = [0; 1];
    //         // let x = test(reader.read(&mut inbuf));
    //         // let y: () = x;

    //         // let read_future: Pin<Box<dyn Future<Output=Result<usize, Error>>>> = Box::pin(reader.read(&mut inbuf));
    //         // let write_future: Pin<Box<dyn Future<Output=Result<usize, Error>>>> = Box::pin(writer.write(&conn.outgoing));


    //         // let read_future: Box<dyn Future<Output=Result<usize, Error>>> = Box::new(reader.read(&mut inbuf));
    //         // let write_future: Box<dyn Future<Output=Result<usize, Error>>> = Box::new(writer.write(&conn.outgoing));


    //         let read_future: BoxedRWFuture = Box::new(reader.read(&mut inbuf));
    //         let write_future: BoxedRWFuture = Box::new(writer.write(&conn.outgoing));

    //         // let selection = select(read_future, write_future).await;
    //         // match selection {
    //         //     Either::Left(value) => {
    //         //         let (read_result, write_future) = value;
    //         //         // let a: std::result::Result<usize, std::io::Error> = read_result;
    //         //         // let b: () = write_future;
    //         //     }
    //         //     Either::Right(value) => {
    //         //         let (write_result, read_future) = value;
    //         //         // let c: std::result::Result<usize, std::io::Error> = write_result;
    //         //         // let d: () = read_future;
    //         //     }
    //         // }
    //     }
    //     else {
    //         break;
    //     }
    // }


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
