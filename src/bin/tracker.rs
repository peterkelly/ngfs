// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::identity_op)]

use std::convert::TryInto;
use std::error::Error;
use tokio::net::{UdpSocket, lookup_host};
use std::net::SocketAddr;
use rand::prelude::Rng;

use ngfs::util::util::BinaryData;
use ngfs::bittorrent::torrent::{Torrent};

// struct ConnectRequest {
// }

struct ConnectResponse {
    action: u32,
    transaction_id: u32,
    connection_id: u64,
}

impl ConnectResponse {
    fn from(buf: &[u8]) -> Result<ConnectResponse, Box<dyn Error>> {
        if buf.len() != 16 {
            return Err("Invalid connect response".into());
        }

        Ok(ConnectResponse {
            action: u32::from_be_bytes(buf[0..4].try_into().unwrap()),
            transaction_id: u32::from_be_bytes(buf[4..8].try_into().unwrap()),
            connection_id: u64::from_be_bytes(buf[8..16].try_into().unwrap()),
        })
    }
}

struct AnnounceRequest {
    connection_id: u64,  // 0       64-bit integer  connection_id
    action: u32,         // 8       32-bit integer  action          1 // announce
    transaction_id: u32, // 12      32-bit integer  transaction_id
    info_hash: [u8; 20], // 16      20-byte string  info_hash
    peer_id: [u8; 20],   // 36      20-byte string  peer_id
    downloaded: u64,     // 56      64-bit integer  downloaded
    left: u64,           // 64      64-bit integer  left
    uploaded: u64,       // 72      64-bit integer  uploaded
    event: u32,          // 80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
    ip_address: u32,     // 84      32-bit integer  IP address      0 // default
    key: u32,            // 88      32-bit integer  key
    num_want: i32,       // 92      32-bit integer  num_want        -1 // default
    port: u16,           // 96      16-bit integer  port
}

impl AnnounceRequest {
    fn to_bytes(&self) -> [u8; 98] {
        let mut request: [u8; 98] = [0; 98];
        // 0       64-bit integer  connection_id
        request[0..8].copy_from_slice(&self.connection_id.to_be_bytes());
        // 8       32-bit integer  action          1 // announce
        request[8..12].copy_from_slice(&self.action.to_be_bytes());
        // 12      32-bit integer  transaction_id
        request[12..16].copy_from_slice(&self.transaction_id.to_be_bytes());
        // 16      20-byte string  info_hash
        request[16..36].copy_from_slice(&self.info_hash);
        // 36      20-byte string  peer_id
        request[36..56].copy_from_slice(&self.peer_id);
        // 56      64-bit integer  downloaded
        request[56..64].copy_from_slice(&self.downloaded.to_be_bytes());
        // 64      64-bit integer  left
        request[64..72].copy_from_slice(&self.left.to_be_bytes());
        // 72      64-bit integer  uploaded
        request[72..80].copy_from_slice(&self.uploaded.to_be_bytes());
        // 80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
        request[80..84].copy_from_slice(&self.event.to_be_bytes());
        // 84      32-bit integer  IP address      0 // default
        request[84..88].copy_from_slice(&self.ip_address.to_be_bytes());
        // 88      32-bit integer  key
        request[88..92].copy_from_slice(&self.key.to_be_bytes());
        // 92      32-bit integer  num_want        -1 // default
        request[92..96].copy_from_slice(&self.num_want.to_be_bytes());
        // 96      16-bit integer  port
        request[96..98].copy_from_slice(&self.port.to_be_bytes());
        request
    }
}

struct PeerEndpoint {
    ip: u32,
    port: u16,
}

struct AnnonuceResponse {      // Offset      Size            Name            Value
    action: u32,               // 0           32-bit integer  action          1 // announce
    transaction_id: u32,       // 4           32-bit integer  transaction_id
    interval: u32,             // 8           32-bit integer  interval
    leechers: u32,             // 12          32-bit integer  leechers
    seeders: u32,              // 16          32-bit integer  seeders
    peers: Vec<PeerEndpoint>,  // 20 + 6 * n  32-bit integer  IP address
                               // 24 + 6 * n  16-bit integer  TCP port
}

impl AnnonuceResponse {
    fn from(buf: &[u8]) -> Result<AnnonuceResponse, Box<dyn Error>> {
        if buf.len() < 20 {
            return Err("Invalid announce response".into());
        }

        let action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
        let transaction_id = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        let interval = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let leechers = u32::from_be_bytes(buf[12..16].try_into().unwrap());
        let seeders = u32::from_be_bytes(buf[16..20].try_into().unwrap());

        if action != 1 {
            return Err(format!("action = {}, expected 1", action).into());
        }

        let peer_count = leechers + seeders;
        let expected_len: usize = (20 + peer_count * 6) as usize;
        if buf.len() != expected_len {
            return Err(format!("Invalid response length: expected {}, got {}", expected_len, buf.len()).into());
        }

        let mut peers: Vec<PeerEndpoint> = Vec::new();

        for i in 0..peer_count {
            let offset: usize = (20 + i * 6) as usize;
            // if offset + 6 > buf.len() {
            //     break;
            // }
            peers.push(PeerEndpoint {
                ip: u32::from_be_bytes(buf[offset..offset + 4].try_into().unwrap()),
                port: u16::from_be_bytes(buf[offset + 4..offset + 6].try_into().unwrap()),
            })
        }

        Ok(AnnonuceResponse {
            action,
            transaction_id,
            interval,
            leechers,
            seeders,
            peers,
        })
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let mut rng = rand::thread_rng();

    let args: Vec<String> = std::env::args().collect();

    let tracker = match args.get(1) {
        Some(tracker) => tracker,
        None => {
            eprintln!("No tracker specified");
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
    let info_hash = &torrent.info_hash.data;
    println!("info_hash = {}", BinaryData(info_hash));

    let peer_id: [u8; 20] = [0xf2, 0x25, 0x27, 0x6a, 0xee, 0x14, 0x16, 0xa5, 0xe2, 0x45,
                             0x60, 0x6d, 0xd4, 0x8a, 0xf3, 0x4f, 0x88, 0xc0, 0x1d, 0x15];
    println!("peer_id = {}", BinaryData(&peer_id));


    let tracker_addr: SocketAddr = lookup_host(tracker).await?.next().unwrap();


    println!("tracker_addr = {}", tracker_addr);
    let transaction_id: f64 = rng.gen();

    let mut rng = rand::thread_rng();
    // let y: f64 = rng.gen(); // generates a float between 0 and 1
    println!("transaction_id = {}", transaction_id);


    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    let sock_addr = sock.local_addr()?;
    println!("UDP client socket address = {}", sock_addr);
    sock.connect(tracker_addr).await?;

    // connect request:
    // Offset  Size            Name            Value
    // 0       64-bit integer  protocol_id     0x41727101980 // magic constant
    // 8       32-bit integer  action          0 // connect
    // 12      32-bit integer  transaction_id
    // 16


    let mut request: [u8; 16] = [0; 16];
    // let other: [u8; 8] = [0; 8];

    let connect_magic: u64 = 0x41727101980;
    let action: u32 = 0;
    let transaction_id: u32 = rng.gen();
    println!("transaction_id = {}", transaction_id);

    request[0..8].copy_from_slice(&connect_magic.to_be_bytes());
    request[8..12].copy_from_slice(&action.to_be_bytes());
    request[12..16].copy_from_slice(&transaction_id.to_be_bytes());

    sock.send(&request).await?;
    println!("Sent request");
    let mut buf: [u8; 1024] = [0; 1024];
    let r = sock.recv(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));

    if r != 16 {
        eprintln!("Incorrectly-sized connect response");
        std::process::exit(1);
    }

    // connect response:

    // Offset  Size            Name            Value
    // 0       32-bit integer  action          0 // connect
    // 4       32-bit integer  transaction_id
    // 8       64-bit integer  connection_id
    // 16

    // let action_bytes:
    // let resp_action: u32 = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    // let resp_transaction_id: u32 = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    // let resp_connection_id: u64 = u64::from_be_bytes(buf[8..16].try_into().unwrap());
    // println!("resp_action = {}", resp_action);
    // println!("resp_transaction_id = {}", resp_transaction_id);
    // println!("resp_connection_id = {}", resp_connection_id);
    let connect_response = ConnectResponse::from(&buf[..r])?;
    println!("connect_response.action = {}", connect_response.action);
    println!("connect_response.transaction_id = {}", connect_response.transaction_id);
    println!("connect_response.connection_id = {}", connect_response.connection_id);
    let my_ip_address: u32 = 0x679996cb;
    let connection_id = connect_response.connection_id;

    let announce_request = AnnounceRequest {
        connection_id: connection_id,  // 0       64-bit integer  connection_id
        action: 1,         // 8       32-bit integer  action          1 // announce
        transaction_id: transaction_id, // 12      32-bit integer  transaction_id
        info_hash: *info_hash, // 16      20-byte string  info_hash
        peer_id: peer_id,   // 36      20-byte string  peer_id
        downloaded: 0,     // 56      64-bit integer  downloaded
        left: 0,           // 64      64-bit integer  left
        uploaded: 0,       // 72      64-bit integer  uploaded
        event: 0,          // 80      32-bit integer  event           0 // 0: none; 1: completed; 2: started; 3: stopped
        ip_address: my_ip_address,     // 84      32-bit integer  IP address      0 // default
        key: 0,            // 88      32-bit integer  key
        num_want: -1,       // 92      32-bit integer  num_want        -1 // default
        port: 1234,           // 96      16-bit integer  port
    };

    println!("Before sending announce request");
    sock.send(&announce_request.to_bytes()).await?;
    println!("Sent announce request");

    let mut buf: [u8; 65536] = [0; 65536];
    let r = sock.recv(&mut buf).await?;
    // println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    // std::fs::write("announce_response", &buf[..r])?;


    let response = AnnonuceResponse::from(&buf[0..r])?;
    println!("action = {}", response.action);
    println!("transaction_id = {}", response.transaction_id);
    println!("interval = {}", response.interval);
    println!("leechers = {}", response.leechers);
    println!("seeders = {}", response.seeders);
    for peer in response.peers.iter() {
        let n0 = (peer.ip >> 24) & 0xFF;
        let n1 = (peer.ip >> 16) & 0xFF;
        let n2 = (peer.ip >> 8) & 0xFF;
        let n3 = (peer.ip >> 0) & 0xFF;
        println!("{}.{}.{}.{}:{}", n0, n1, n2, n3, peer.port);
    }

    Ok(())
}
