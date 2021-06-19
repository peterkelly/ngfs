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
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug)]
enum ServerMode {
    Read,
    Write,
    Echo,
}

impl std::str::FromStr for ServerMode {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "read" => Ok(ServerMode::Read),
            "write" => Ok(ServerMode::Write),
            "echo" => Ok(ServerMode::Echo),
            _ => Err("expected one of 'read', 'write', or 'echo'"),
        }
    }
}
impl fmt::Display for ServerMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[derive(Clap, Clone, Debug)]
#[clap(name="sock")]
struct Opt {
    #[clap(long, name = "read|write|echo")]
    mode: ServerMode,

    #[clap(long)]
    read_buf_size: Option<usize>,

    #[clap(long)]
    read_delay_ms: Option<u64>,

    #[clap(long)]
    port: u16,
}

const DEFAULT_READ_BUF_SIZE: usize = 4096;
const DEFAULT_READ_DELAY_MS: u64 = 0;

async fn process_connection(opt: Opt, mut stream: TcpStream) {
    let read_buf_size = opt.read_buf_size.unwrap_or(DEFAULT_READ_BUF_SIZE);
    let read_delay_ms = opt.read_delay_ms.unwrap_or(DEFAULT_READ_DELAY_MS);
    let mut read_buf: Vec<u8> = vec![0; read_buf_size];
    loop {
        match stream.read(&mut read_buf).await {
            Err(e) => {
                println!("Read error: {}", e);
                break;
            }
            Ok(0) => {
                println!("Read EOF");
                break;
            }
            Ok(r) => {
                println!("Read {} bytes", r);
                if read_delay_ms > 0 {
                    sleep(Duration::from_millis(read_delay_ms)).await;
                }
            }
        }

        // let r = match stream.read(&mut read_buf).await {
        //     Ok(r) => r,
        //     Err(e) => {
        //         println!("Read error: {}", e);
        //         break;
        //     }
        // };
        // if r == 0 {
        //     println!("Read EOF");
        //     break;
        // }
        // else {
        //     println!("Read {} bytes", r);
        // }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::parse();
    println!("{:#?}", opt);

    // let addr = "127.0.0.1:8080";
    let mut listener = TcpListener::bind(&format!("127.0.0.1:{}", opt.port)).await?;
    println!("Listening on: {}", opt.port);

    let mut next_connection_id: usize = 0;
    loop {
        let (mut stream, client_addr) = listener.accept().await?;
        println!("Got connection from {}", client_addr);
        let connection_id = next_connection_id;
        next_connection_id += 1;
        // let state = state.clone();
        let opt = opt.clone();
        let handle = tokio::spawn(async move {
            process_connection(opt, stream).await;
        });
    }

    // Ok(())
}

