#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use std::sync::Arc;
use tokio::net::tcp::{ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use std::net::SocketAddr;
use futures::future::join;
use torrent::util::escape_string;

struct State {
    connections: Vec<Connection>,
}

impl State {
    async fn broadcast(&mut self, msg: &str) {
        for conn in self.connections.iter_mut() {
            conn.send(msg).await;
        }
    }
}

impl State {
    fn new() -> State {
        State {
            connections: Vec::new(),
        }
    }
}

struct Connection {
    connection_id: usize,
    tx: UnboundedSender<WriterMessage>,
}

impl Connection {
    fn new(connection_id: usize, tx: UnboundedSender<WriterMessage>) -> Connection {
        Connection { connection_id, tx }
    }

    async fn send(&mut self, msg: &str) {
    }
}

enum WriterMessage {
    Write(Vec<u8>),
    Close,
}

async fn connection_reader<'a>(conn: Arc<Connection>, mut reader: ReadHalf<'a>) {
    let mut buf: [u8; 1024] = [0; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                println!("{}: Connection closed", conn.connection_id);
                break;
            }
            Ok(r) => {
                let s = String::from_utf8_lossy(&buf[..r]);
                println!("{}: Received {} bytes: {}", conn.connection_id, r, escape_string(&s));
            }
            Err(e) => {
                println!("{}: Connection error: {}", conn.connection_id, e);
                break;
            }
        };
    }
}

async fn connection_writer<'a>(conn: Arc<Connection>, mut writer: WriteHalf<'a>,
                mut rx: UnboundedReceiver<WriterMessage>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            WriterMessage::Write(data) => {
                let mut pos: usize = 0;
                while pos < data.len() {
                    match writer.write(&data[pos..]).await {
                        Ok(bytes_written) => {
                            println!("{}: Wrote {} bytes", conn.connection_id, bytes_written);
                            pos += bytes_written;
                        }
                        Err(e) => {
                            println!("{}: Error writing to connection: {}", conn.connection_id, e);
                            return;
                        }
                    }
                }
            }
            WriterMessage::Close => {
                return;
            }
        }
    }
}

async fn process_connection(state: Arc<State>, stream: &mut TcpStream,
                            client_addr: SocketAddr, connection_id: usize) {
    let (mut reader, mut writer) = stream.split();
    let (mut tx1, mut rx1) = mpsc::unbounded_channel::<WriterMessage>();
    let mut tx: UnboundedSender<WriterMessage> = tx1;
    let mut rx: UnboundedReceiver<WriterMessage> = rx1;
    let conn = Arc::new(Connection::new(connection_id, tx));

    let reader_future = connection_reader(conn.clone(), reader);
    let writer_future = connection_writer(conn.clone(), writer, rx);
    join(reader_future, writer_future).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let state = Arc::new(State::new());

    let addr = "127.0.0.1:8080";
    let mut listener = TcpListener::bind(&addr).await?;
    println!("Listening on: {}", addr);

    let mut next_connection_id: usize = 0;
    loop {
        let (mut stream, client_addr) = listener.accept().await?;
        println!("Got connection from {}", client_addr);
        // let mut connection = Connection::new(stream);
        let connection_id = next_connection_id;
        next_connection_id += 1;
        let state = state.clone();
        let handle = tokio::spawn(async move {
            process_connection(state, &mut stream, client_addr, connection_id).await;
        });
    }
}
