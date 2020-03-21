#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use tokio::net::{lookup_host};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::prelude::*;
// use native_tls;
// use tokio_tls;
use super::result::general_error;
use super::util::{BinaryData, escape_string};
use super::protobuf::{PBufReader, VarInt};

pub async fn p2p_test(server_addr_str: &str) -> Result<(), Box<dyn Error>> {
    let peer_addr: SocketAddr = match lookup_host(server_addr_str).await?.next() {
        Some(v) => v,
        None => return general_error(&format!("Cannot resolve host: {}", server_addr_str)),
    };

    println!("Before opening connection");
    let mut stream = TcpStream::connect(peer_addr).await?;
    println!("After opening connection");

    let mut buf: [u8; 65536] = [0; 65536];
    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];

    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("msg = {}", escape_string(&msg));

    let mut tosend: Vec<u8> = Vec::new();
    let tosend_str = "/multistream/1.0.0\n";
    let tosend_bytes = tosend_str.as_bytes();
    tosend.push(tosend_bytes.len() as u8);
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    println!("Sent {} bytes", w);





    let mut tosend: Vec<u8> = Vec::new();
    let tosend_str = "/tls/1.0.0\n";
    let tosend_bytes = tosend_str.as_bytes();
    tosend.push(tosend_bytes.len() as u8);
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    println!("Sent {} bytes", w);

    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];
    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("msg = {}", escape_string(&msg));


    // let cx = native_tls::TlsConnector::builder()
    //     .min_protocol_version(Some(native_tls::Protocol::Tlsv13))
    //     .max_protocol_version(Some(native_tls::Protocol::Tlsv13))
    //     .build()?;
    // let cx = tokio_tls::TlsConnector::from(cx);

    // let mut tls_stream = cx.connect("localhost", stream).await?;
    // println!("TLS Connection established");





    // let mut offset = 0;
    // let msg_len = match VarInt::read_from(&received, &mut offset) {
    //     Some(v) => v.to_usize(),
    //     None => return general_error("Cannot get message length"),
    // };
    // println!("msg_len = {}", msg_len);



    Ok(())
}
