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
use futures::future::{Future, Either, select, join};
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::net::SocketAddr;

type RWFuture<'a> = Box<dyn Future<Output=Result<usize, std::io::Error>> + 'a>;

// struct ReadWrite<'a> {
//     // socket: &'a Box<TcpStream>,
//     read_future: &'a RWFuture<'a>,
//     write_future: &'a RWFuture<'a>,
// }

struct Connection {
    // reader: ReadHalf<'a>,
    // writer: WriteHalf<'a>,
    receive_queue: Vec<u8>,
    send_queue: Vec<u8>,
}

async fn do_reading<'a>(reader: &mut ReadHalf<'a>) {
}

async fn do_writing<'a>(writer: &mut WriteHalf<'a>) {
}


async fn process<'a>(conn_ref: Arc<Mutex<Connection>>, reader: &mut ReadHalf<'a>, writer: &mut WriteHalf<'a>)
                    -> Result<(), Box<dyn Error>> {
    let read_handle = async move {
        loop {
            let mut buf: [u8; 1024] = [0; 1024];
            match reader.read(&mut buf).await {
                Ok(r) => {
                    println!("read {} bytes", r);
                    conn_ref.lock().unwrap().on_receive(&buf[0..r]);
                }
                Err(err) => {
                    println!("read error: {}", err);
                    break;
                }
            };
        };
    };

    let write_handle = async move {
        // loop {
            let welcome = "=======\nWelcome\n=======\n";
            match writer.write(welcome.as_bytes()).await {
                Ok(w) => {
                    println!("wrote {} bytes", w);
                }
                Err(err) => {
                    println!("write error: {}", err);
                    // break;
                }
            }
        // }
    };

    join(read_handle, write_handle).await;


    Ok(())
}

impl Connection {
    fn new() -> Connection {
        Connection {
            receive_queue: Vec::new(),
            send_queue: Vec::new(),
        }
    }

    fn send(&mut self, data: &[u8]) {
    }

    fn on_send(&mut self, num_bytes: usize) {
        if num_bytes > self.send_queue.len() {
            panic!("Sent more bytes than we have");
        }
        self.send_queue.drain(0..num_bytes);
    }

    fn on_receive(&mut self, data: &[u8]) {
        println!("Received: {}", String::from_utf8_lossy(data.clone()));
    }
}

async fn setup_connection(stream: &mut TcpStream, addr: SocketAddr) {
    let (mut reader, mut writer) = stream.split();
    let mut conn = Connection::new();
    let conn_ref = Arc::new(Mutex::new(conn));
    match process(conn_ref.clone(), &mut reader, &mut writer).await {
        Ok(_) => (),
        Err(e) => eprintln!("{}: {}", addr, e),
    };
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let addr = "127.0.0.1:8080";

    let mut listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    loop {
        let (mut stream, client_addr) = listener.accept().await?;
        println!("Got connection from {}", client_addr);
        // let mut connection = Connection::new(stream);
        let handle = tokio::spawn(async move {
            setup_connection(&mut stream, client_addr).await;
            // let (mut reader, mut writer) = stream.split();
            // let mut conn = Connection::new(reader, writer);
            // match conn.process().await {
            //     Ok(_) => (),
            //     Err(e) => {
            //         eprintln!("Error handling connection: {}", e);
            //     }
            // };
        });
    }

    // loop {
    //     // Asynchronously wait for an inbound socket.
    //     let (mut socket, _) = listener.accept().await?;
    // }

    // let mut socket = Box::new(socket);
    // let (mut reader, mut writer) = socket.split();

    // let mut buf: Box<[u8; 1]> = Box::new([0; 1]);
    // let read_future = reader.read(&mut *buf);
    // let write_future = writer.write(b"X");

    // // let read_future = Box::new(read_future);
    // // let write_future = Box::new(write_future);


    // let read_future: Box<dyn Future<Output=Result<usize, std::io::Error>>> = Box::new(read_future);
    // let write_future: Box<dyn Future<Output=Result<usize, std::io::Error>>> = Box::new(write_future);

    // // let x: dyn Future<AsyncWrite + Unpin> = write_future;

    // // let x: Box<dyn Future<Output=Result<usize, std::io::Error>>> = write_future;
    // let rw = ReadWrite {
    //     // socket: &socket,
    //     read_future: &read_future,
    //     write_future: &write_future,
    // };

    // // write_future.await?;
    // // read_future.await?;

    // // let select_future = select(write_future, read_future);


    // Ok(())
}
