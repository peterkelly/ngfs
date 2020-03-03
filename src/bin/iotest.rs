#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let addr = "127.0.0.1:8080";

    let mut listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);
    let (mut socket, _) = listener.accept().await?;

    let mut buf: [u8; 1] = [0; 1];

    let write_future = socket.write(b"X").await?;
    let read_future = socket.read(&mut buf).await?;


    Ok(())
}
