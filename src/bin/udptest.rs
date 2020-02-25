// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use tokio::net::{UdpSocket, lookup_host};
use std::error::Error;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let server_addr: SocketAddr = lookup_host("127.0.0.1:1234").await?.next().unwrap();
    let client_addr: SocketAddr = lookup_host("127.0.0.1:1235").await?.next().unwrap();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("client") => {
            client(&server_addr, &client_addr).await
        }
        Some("server") => {
            server(&server_addr).await
        }
        Some(command) => {
            eprintln!("Unknown command: {}", command);
            std::process::exit(1);
        }
        None => {
            eprintln!("Please specify command");
            std::process::exit(1);
        }
    }
}

async fn client(server_addr: &SocketAddr, client_addr: &SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut sock = UdpSocket::bind(client_addr).await?;
    println!("Client: Created socket");
    sock.send_to(b"hello", server_addr).await?;
    println!("Client: Sent data");
    Ok(())
}

async fn server(server_addr: &SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut sock = UdpSocket::bind(server_addr).await?;
    println!("Server: Created socket");

    loop {
        let mut buf: [u8; 1024] = [0; 1024];
        let r = sock.recv(&mut buf).await?;
        let sdata = String::from_utf8_lossy(&buf[..r]);
        println!("Server: Received \"{}\"", sdata);
    }
}
