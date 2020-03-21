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

async fn send_string(stream: &mut TcpStream, tosend_str: &str) -> Result<(), Box<dyn Error>> {
    let mut tosend: Vec<u8> = Vec::new();
    // let tosend_str = "/multistream/1.0.0\n";
    let tosend_bytes = tosend_str.as_bytes();
    // tosend.push(tosend_bytes.len() as u8);
    tosend.append(&mut VarInt::encode_usize(tosend_bytes.len()));
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);
    if w != tosend.len() {
        return general_error(&format!("Only sent {} bytes of {}", w, tosend.len()));
    }
    println!("Sent {}", escape_string(tosend_str));
    Ok(())

}

fn print_fields(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut reader = PBufReader::new(&data);
    while let Some(field) = reader.read_field()? {
        println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            field.offset, field.field_number, field.data);
        // println!();
        // match show_field(&field) {
        //     Ok(_) => (),
        //     Err(e) => {
        //         println!("    Error: {}", e);
        //     }
        // }
        // println!();
    }
    Ok(())
}

async fn recv_length_prefixed_binary(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut length_buf: [u8; 4] = [0; 4];
    let r = stream.read(&mut length_buf).await?;
    if r != 4 {
        return general_error("Insufficient data while reading message length");
    }
    println!("length_buf = {:?}", length_buf);
    let msglen = u32::from_be_bytes(length_buf) as usize;
    println!("msglen = {}", msglen);
    if msglen >= 0x800000 {
        return general_error(&format!("Message length {} exceeds allowed length", msglen));
    }
    let mut body: Vec<u8> = Vec::with_capacity(msglen as usize);

    let mut total_read  = 0;
    const CHUNK_SIZE: usize = 16;
    while total_read < msglen {
        let mut msg_buf: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
        let want: usize;
        if total_read + CHUNK_SIZE <= msglen {
            want = CHUNK_SIZE;
        }
        else {
            want = msglen - total_read;
        }
        let r = stream.read(&mut msg_buf[0..want]).await?;
        if r != want {
            println!("r = {}", r);
            break;
        }
        total_read += r;
        body.append(&mut Vec::from(&msg_buf[0..r]));
    }

    if total_read != msglen {
        return general_error(&format!("Insufficient data while reading message body; got {} bytes, expected {}", total_read, msglen));
    }


    // let r = stream.read(&mut body).await?;
    // if r != msglen {
    //     return general_error(&format!("Insufficient data while reading message body; got {} bytes, expected {}", r, msglen));
    // }
    Ok(body)
}

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
    // println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];

    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("Received {}", escape_string(&msg));

    // let mut tosend: Vec<u8> = Vec::new();
    // let tosend_str = "/multistream/1.0.0\n";
    // let tosend_bytes = tosend_str.as_bytes();
    // tosend.push(tosend_bytes.len() as u8);
    // tosend.append(&mut Vec::from(tosend_bytes));
    // let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);

    send_string(&mut stream, "/multistream/1.0.0\n").await?;




    // let mut tosend: Vec<u8> = Vec::new();
    // let tosend_str = "/secio/1.0.0\n";
    // let tosend_bytes = tosend_str.as_bytes();
    // tosend.push(tosend_bytes.len() as u8);
    // tosend.append(&mut Vec::from(tosend_bytes));
    // let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);

    send_string(&mut stream, "/secio/1.0.0\n").await?;

    // let r = stream.read(&mut buf).await?;
    // // println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    // let received = &buf[0..r];
    // let mut reader = PBufReader::new(received);
    // let msg = reader.read_length_delimited()?.to_string()?;
    // println!("Received {}", escape_string(&msg));






    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];
    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("Received {}", escape_string(&msg));








    let data = recv_length_prefixed_binary(&mut stream).await?;
    print_fields(&data)?;

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
