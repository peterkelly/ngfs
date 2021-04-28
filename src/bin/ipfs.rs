#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

use std::error::Error;
use std::net::SocketAddr;
use std::fmt;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, BufReader, BufWriter};
use torrent::util::{from_hex, escape_string, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
// use torrent::tls::types::alert::*;
// use torrent::tls::types::handshake::*;
// use torrent::tls::types::extension::*;
// use torrent::tls::types::record::*;
// use torrent::crypt::*;
use torrent::result::GeneralError;
use torrent::protobuf::VarInt;
use crypto::digest::Digest;
use crypto::sha2::Sha384;
use crypto::hkdf::{hkdf_extract, hkdf_expand};
use crypto::aes_gcm::AesGcm;
use ring::agreement::{PublicKey, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;

async fn read_multistream_varint(socket: &mut (impl AsyncRead + Unpin)) -> Result<usize, Box<dyn Error>> {
    let mut buf: [u8; 1] = [0; 1];
    let mut value: usize = 0;
    loop {
        let r = match socket.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(GeneralError::new("Unexpected end of input")),
            Ok(r) => {
                let b = buf[0];
                value = (value << 7) | ((b & 0x7f) as usize);
                if b & 0x80 == 0 {
                    break;
                }
            }
        };
    }
    Ok(value)
}

async fn read_multistream_data(socket: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Box<dyn Error>> {
    let expected_len = read_multistream_varint(socket).await?;
    // println!("expected_len = {}", expected_len);
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        let r = match socket.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(GeneralError::new("Unexpected end of input")),
            Ok(r) => {
                incoming_data.push(buf[0]);
                got_len += 1;
            }
        };
    }
    Ok(incoming_data)
}

async fn write_multistream_data(socket: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Box<dyn Error>> {
    let len_bytes = VarInt::encode_usize(data.len());

    // let mut temp: Vec<u8> = Vec::new();
    // temp.extend_from_slice(&len_bytes);
    // temp.extend_from_slice(data);
    // println!("Sending:\n{:#?}", &DebugHexDump(&temp));


    socket.write_all(&len_bytes).await?;
    socket.write_all(&data).await?;
    socket.flush().await?;
    Ok(())
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let mut socket = TcpStream::connect("localhost:4001").await?;
    let (reader, writer) = socket.split();
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    // const READ_SIZE: usize = 1024;

    write_multistream_data(&mut writer, b"/multistream/1.0.0\n").await?;
    let data = read_multistream_data(&mut reader).await?;
    // println!("{:#?}", &DebugHexDump(&data));

    if data == b"/multistream/1.0.0\n" {
        println!("Got expected /multistream/1.0.0");
    }
    else {
        println!("Got something else!");
        return Ok(());
    }


    write_multistream_data(&mut writer, b"/tls/1.0.0\n").await?;
    let data = read_multistream_data(&mut reader).await?;
    // println!("{:#?}", &DebugHexDump(&data));

    if data == b"/tls/1.0.0\n" {
        println!("Got expected /tls/1.0.0");
    }
    else {
        println!("Got something else!");
        return Ok(());
    }

    println!("Attempting TLS connection");









    // write_multistream_data(&mut socket, b"/plaintext/2.0.0\n").await?;
    // let data = read_multistream_data(&mut socket).await?;
    // println!("{:#?}", &DebugHexDump(&data));

    // if data == b"/plaintext/2.0.0\n" {
    //     println!("Got expected /plaintext/2.0.0");
    // }
    // else {
    //     println!("Got something else!");
    // }

    // println!("ls response:");
    // write_multistream_data(&mut socket, b"ls\n").await?;
    // let data = read_multistream_data(&mut socket).await?;
    // println!("{:#?}", &DebugHexDump(&data));


    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await
}
