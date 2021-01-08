#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use torrent::util::{escape_string, BinaryData, DebugHexDump};
use torrent::binary::{BinaryReader, FromBinary};
use torrent::tls::types::*;

// The record layer fragments information blocks into TLSPlaintext records carrying data in chunks of 2^14
const TLS_RECORD_SIZE: usize = 16384;

 // uint16 ProtocolVersion;
 //      opaque Random[32];

 //      uint8 CipherSuite[2];    /* Cryptographic suite selector */

 //      struct {
 //          ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
 //          Random random;
 //          opaque legacy_session_id<0..32>;
 //          CipherSuite cipher_suites<2..2^16-2>;
 //          opaque legacy_compression_methods<1..2^8-1>;
 //          Extension extensions<8..2^16-1>;
 //      } ClientHello;



async fn process_connection_inner(mut socket: TcpStream, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    println!("Received connection from {}", addr);
    println!("local_addr = {}", socket.local_addr()?);
    println!("peer_addr = {}", socket.peer_addr()?);



    // let mut buf: [u8; TLS_RECORD_SIZE] = [0; TLS_RECORD_SIZE];
    // let r = socket.read(&mut buf).await?;
    // println!("Read {} bytes", r);
    // // let s: String = String::from_utf8_lossy(&buf[0..r]).into();
    // // println!("Text: {}", escape_string(&s));
    // println!("Data:\n{:#?}", DebugHexDump(&buf[0..r]));
    // std::fs::write("received.bin", &buf[0..r])?;
    // let raw_data = &buf[0..r];

    // if raw_data.len() < 5 {
    //     return Err("Invalid record".into());
    // }

    let mut record_header: [u8; 5] = [0; 5];
    let r = socket.read_exact(&mut record_header).await?;
    // println!("Read {} bytes", r);

    let content_type = ContentType::from_raw(record_header[0]);
    println!("content_type = {:?}", content_type);

    // let protocol_version_raw = raw_data.get(1..2).ok_or_else(|| "Missing protocol version");
    let mut protocol_version_bytes: [u8; 2] = Default::default();
    protocol_version_bytes.copy_from_slice(&record_header[1..3]);
    let protocol_version = u16::from_be_bytes(protocol_version_bytes);
    println!("protocol_version = {} 0x{:04x}", protocol_version, protocol_version);


    let mut length_bytes: [u8; 2] = Default::default();
    length_bytes.copy_from_slice(&record_header[3..5]);
    let length = u16::from_be_bytes(length_bytes) as usize;
    println!("length = {} 0x{:04x}", length, length);

    if length > TLS_RECORD_SIZE {
        // TODO: TLSPlaintext.fragment.  The length MUST NOT exceed 2^14 bytes.  An
        // endpoint that receives a record that exceeds this length MUST
        // terminate the connection with a "record_overflow" alert.
        return Err("Record overflow".into());
    }

    let mut data_full: [u8; 65536] = [0; 65536];
    let mut data = &mut data_full[0..length];
    socket.read_exact(data).await?;
    // let data = data;
    println!("Data:");
    println!("{:#?}", DebugHexDump(data));

    let plaintext = TLSPlaintext {
        content_type: content_type,
        legacy_record_version: protocol_version,
        fragment: data.to_vec(),
    };
    println!("Created TLSPlaintext struct");

    let mut full: Vec<u8> = Vec::new();
    full.append(&mut record_header.to_vec());
    full.append(&mut data.to_vec());

    std::fs::write("handshake.bin", &full)?;

    println!("plaintext.fragment.len() = {}", plaintext.fragment.len());
    let mut reader = BinaryReader::new(&plaintext.fragment);
    let handshake = reader.read_item::<Handshake>()?;



    Ok(())
}

async fn process_connection(socket: TcpStream, addr: SocketAddr) {
    match process_connection_inner(socket, addr).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error processing connection: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.01:8080").await?;
    println!("Listening for connections");
    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(process_connection(socket, addr));
        // let x: TcpStream = socket;
        // let y: SocketAddr = addr;
    }


    // Ok(())
}
