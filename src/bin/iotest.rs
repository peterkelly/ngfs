#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use tokio;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{ReadHalf, WriteHalf};
use futures::future::{Future, select, Either};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;

type RWFuture<'a> = Box<dyn Future<Output=Result<usize, std::io::Error>> + 'a>;

struct ReadWrite<'a> {
    // socket: &'a Box<TcpStream>,
    read_future: &'a RWFuture<'a>,
    write_future: &'a RWFuture<'a>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let addr = "127.0.0.1:8080";

    let mut listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);
    let (mut socket, _) = listener.accept().await?;
    let mut socket = Box::new(socket);
    let (mut reader, mut writer) = socket.split();

    let mut buf: Box<[u8; 1]> = Box::new([0; 1]);
    let read_future = reader.read(&mut *buf);
    let write_future = writer.write(b"X");

    // let read_future = Box::new(read_future);
    // let write_future = Box::new(write_future);


    let read_future: Box<dyn Future<Output=Result<usize, std::io::Error>>> = Box::new(read_future);
    let write_future: Box<dyn Future<Output=Result<usize, std::io::Error>>> = Box::new(write_future);

    // let x: dyn Future<AsyncWrite + Unpin> = write_future;

    // let x: Box<dyn Future<Output=Result<usize, std::io::Error>>> = write_future;
    let rw = ReadWrite {
        // socket: &socket,
        read_future: &read_future,
        write_future: &write_future,
    };

    // write_future.await?;
    // read_future.await?;

    // let select_future = select(write_future, read_future);


    Ok(())
}
