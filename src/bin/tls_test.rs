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
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
use torrent::tls::types::handshake::*;
use torrent::tls::types::extension::*;
use torrent::tls::types::record::*;

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

fn make_client_hello() -> ClientHello {
    ClientHello {
        legacy_version: 0x0303,
        random: Default::default(), // TODO
        legacy_session_id: Vec::new(), // TODO
        cipher_suites: Vec::new(), // TODO
        legacy_compression_methods: Vec::new(), // TODO
        extensions: Vec::new(), // TODO
    }
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    Ok(())
}

fn process_record<'a>(record: &'a TLSPlaintext, record_raw: &'a [u8]) -> Result<(), Box<dyn Error>> {
    let received_filename = "record-received.bin";
    std::fs::write(received_filename, record_raw)?;
    println!("Wrote {}", received_filename);

    let mut reader = BinaryReader::new(record.fragment);
    let handshake = reader.read_item::<Handshake>()?;

    println!("{:#?}", handshake);

    // println!("--------------------------");
    let mut writer = BinaryWriter::new();
    writer.write_item(&handshake)?;

    let output_record = TLSPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: &Vec::<u8>::from(writer),
    };

    let serialized_filename = "record-serialized.bin";
    std::fs::write(serialized_filename, &output_record.to_vec())?;
    println!("Wrote {}", serialized_filename);

    Ok(())
}

async fn process_connection_inner(mut socket: TcpStream, addr: SocketAddr) -> Result<(), Box<dyn Error>> {
    println!("Received connection from {}", addr);
    println!("local_addr = {}", socket.local_addr()?);
    println!("peer_addr = {}", socket.peer_addr()?);
    const READ_SIZE: usize = 1024;

    let mut incoming_data: Vec<u8> = Vec::new();

    loop {


        let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
        let r = socket.read(&mut buf).await?;
        if r == 0 {
            println!("Connection closed by peer");
            return Ok(())
        }
        incoming_data.extend_from_slice(&buf[0..r]);

        match TLSPlaintext::from_raw_data(&incoming_data) {
            Err(TLSPlaintextError::InsufficientData) => {
                // need to read some more data from the socket before we can decode the record
                continue;
            }
            Err(TLSPlaintextError::InvalidLength) => {
                println!("Client sent record with invalid length");
                return Ok(())
            }
            Ok((record, bytes_consumed)) => {
                process_record(&record, &incoming_data[0..bytes_consumed])?;
                incoming_data = incoming_data.split_off(bytes_consumed);
            }
        }
    }
}

async fn process_connection(socket: TcpStream, addr: SocketAddr) {
    match process_connection_inner(socket, addr).await {
        Ok(()) => {},
        Err(e) => {
            eprintln!("Error processing connection: {}", e);
        }
    }
}

async fn test_server() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.01:8080").await?;
    println!("Listening for connections");
    loop {
        let (socket, addr) = listener.accept().await?;
        tokio::spawn(process_connection(socket, addr));
        // let x: TcpStream = socket;
        // let y: SocketAddr = addr;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let command = match std::env::args().nth(1) {
        Some(command) => command,
        None => {
            eprintln!("No command specified");
            std::process::exit(1);
        }
    };

    match command.as_str() {
        "client" => test_client().await,
        "server" => test_server().await,
        _ => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
    }
}
