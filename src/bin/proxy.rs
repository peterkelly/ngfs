#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use clap::{Clap, ArgEnum};
use clap;

use std::error::Error;
use std::fmt;
use std::time::Duration;
use tokio::time::sleep;
use tokio::net::{TcpListener, TcpStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clap, Clone, Debug)]
#[clap(name="sock")]
struct Opt {
    #[clap(long)]
    read_buf_size: Option<usize>,

    #[clap(long)]
    read_delay_ms: Option<u64>,

    #[clap(long)]
    write_buf_size: Option<usize>,

    #[clap(long)]
    write_delay_ms: Option<u64>,

    #[clap(long)]
    listen_port: u16,

    #[clap(long)]
    server_port: u16,
}

const DEFAULT_BUF_SIZE: usize = 4096;
const DEFAULT_DELAY_MS: u64 = 0;

// async fn process_connection(opt: Opt, mut stream: TcpStream) {
//     let read_buf_size = opt.read_buf_size.unwrap_or(DEFAULT_READ_BUF_SIZE);
//     let read_delay_ms = opt.read_delay_ms.unwrap_or(DEFAULT_READ_DELAY_MS);
// }

struct Bandwidth {
    buf_size: usize,
    delay_ms: u64,
}

#[derive(Debug)]
enum Side {
    ClientToServer,
    ServerToClient,
}

async fn proxy_loop(side: Side, bandwidth: Bandwidth, mut reader: OwnedReadHalf, mut writer: OwnedWriteHalf) {
    let mut buf: Vec<u8> = vec![0; bandwidth.buf_size];
    let mut total_read: usize = 0;
    let mut total_written: usize = 0;
    loop {
        match reader.read(&mut buf).await {
            Err(e) => {
                println!("{:?}:  read error: {}", side, e);
                break;
            }
            Ok(0) => {
                println!("{:?}:  read eof", side);
                break;
            }
            Ok(r) => {
                total_read += r;
                println!("{:?}:  read {} bytes (total {})", side, r, total_read);

                match writer.write_all(&buf[..r]).await {
                    Err(e) => {
                        println!("{:?}: write error: {}", side, e);
                        break;
                    }
                    Ok(()) => {
                        total_written += r;
                        println!("{:?}: wrote {} bytes (total {})", side, r, total_written);
                    }
                }


                if bandwidth.delay_ms > 0 {
                    sleep(Duration::from_millis(bandwidth.delay_ms)).await;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    println!("{:#?}", opt);

    // let addr = "127.0.0.1:8080";
    let mut listener = TcpListener::bind(&format!("127.0.0.1:{}", opt.listen_port)).await?;
    println!("Listening on: {}", opt.listen_port);

    let mut next_connection_id: usize = 0;
    loop {
        let (mut client_stream, client_addr) = listener.accept().await?;
        println!("Got connection from {}", client_addr);
        let connection_id = next_connection_id;
        next_connection_id += 1;

        let mut server_stream = TcpStream::connect(&format!("127.0.0.1:{}", opt.server_port)).await?;

        let up_bandwidth = Bandwidth {
            buf_size: opt.read_buf_size.unwrap_or(DEFAULT_BUF_SIZE),
            delay_ms: opt.read_delay_ms.unwrap_or(DEFAULT_DELAY_MS),
        };

        let down_bandwidth = Bandwidth {
            buf_size: opt.write_buf_size.unwrap_or(DEFAULT_BUF_SIZE),
            delay_ms: opt.write_delay_ms.unwrap_or(DEFAULT_DELAY_MS),
        };

        let (client_read_half, client_write_half) = client_stream.into_split();
        let (server_read_half, server_write_half) = server_stream.into_split();

        tokio::spawn(async move {
            proxy_loop(Side::ClientToServer, up_bandwidth, client_read_half, server_write_half).await;
        });
        tokio::spawn(async move {
            proxy_loop(Side::ServerToClient, down_bandwidth, server_read_half, client_write_half).await;
        });

        // let state = state.clone();
        // let opt = opt.clone();
        // let handle = tokio::spawn(async move {
        //     process_connection(opt, stream).await;
        // });
    }

    // Ok(())
}

