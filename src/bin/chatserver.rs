#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(clippy::single_match)]

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
use ngfs::util::util::escape_string;

struct StateInner {
    total_sent: usize,
    total_received: usize,
    connlist: Vec<Arc<Connection>>,
}

impl StateInner {
    fn add_connection(&mut self, conn: Arc<Connection>) {
        println!("StateInner: Added connection {}", conn.connection_id);
        self.connlist.push(conn);
    }

    fn remove_connection(&mut self, conn: Arc<Connection>) {
        let mut index: Option<usize> = None;
        for (i, other) in self.connlist.iter().enumerate() {
            if Arc::ptr_eq(other, &conn) {
                index = Some(i);
                break;
            }
        }
        if let Some(i) = index {
            self.connlist.remove(i);
            println!("StateInner: Removed connection {}", conn.connection_id);
        }
        else {
            println!("StateInner: Could not find connection {} to remove", conn.connection_id);
        }
    }
}

struct State {
    inner: Mutex<StateInner>,
}

impl State {
    fn new() -> State {
        State {
            inner: Mutex::new(StateInner {
                total_sent: 0,
                total_received: 0,
                connlist: Vec::new(),
            }),
        }
    }

    async fn broadcast(&self, data: &[u8]) {
        let connections = self.get_connections().await;
        for conn in connections.iter() {
            match conn.send(data).await {
                Ok(_) => {},
                Err(_) => {}
            };
        }
    }

    async fn get_connections(&self) -> Vec<Arc<Connection>> {
        self.inner.lock().await.connlist.clone()
    }

    async fn add_connection(&self, conn: Arc<Connection>) {
        self.inner.lock().await.add_connection(conn);
    }
    async fn remove_connection(&self, conn: Arc<Connection>) {
        self.inner.lock().await.remove_connection(conn);
    }

    async fn on_receive(&self, conn: &Arc<Connection>, data: &[u8]) {
        let s = String::from_utf8_lossy(data);
        println!("Connection {} on_receive {}", conn.connection_id, escape_string(&s));

        let total_received: usize;
        {
            let mut inner = self.inner.lock().await;
            inner.total_received += data.len();
            total_received = inner.total_received;
        }

        let response: String = format!("Received from {}: {}\n", conn.connection_id, escape_string(&s));

        let response_bytes = response.as_bytes();
        // match conn.tx.send(WriterMessage::Write(Vec::from(response_bytes))) {
        //     Ok(()) => {},
        //     Err(e) => {
        //         println!("Error sending: {}", e);
        //     }
        // };
        self.broadcast(response_bytes).await;

        let total_sent: usize;
        {
            let mut inner = self.inner.lock().await;
            inner.total_sent += response_bytes.len();
            total_sent = inner.total_sent;
        }

        println!("received {}, sent {}", total_received, total_sent);

    }

    async fn on_receive_close(&self, conn: &Arc<Connection>) {
        match conn.close().await {
            Ok(()) => {},
            Err(e) => {
                println!("Error closing connection {}: {}", conn.connection_id, e);
            }
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

    async fn send(&self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.tx.send(WriterMessage::Write(Vec::from(data)))?;
        Ok(())
    }

    async fn close(&self) -> Result<(), Box<dyn Error>> {
        self.tx.send(WriterMessage::Close)?;
        Ok(())
    }
}

#[derive(Debug)]
enum WriterMessage {
    Write(Vec<u8>),
    Close,
}

async fn connection_reader(state: Arc<State>, conn: Arc<Connection>, mut reader: ReadHalf<'_>) {
    let mut buf: [u8; 1024] = [0; 1024];
    loop {
        match reader.read(&mut buf).await {
            Ok(0) => {
                println!("{}: Connection closed", conn.connection_id);
                state.on_receive_close(&conn).await;
                break;
            }
            Ok(r) => {
                let s = String::from_utf8_lossy(&buf[..r]);
                // println!("{}: Received {} bytes: {}", conn.connection_id, r, escape_string(&s));
                state.on_receive(&conn, &buf[..r]).await;
            }
            Err(e) => {
                println!("{}: Connection error: {}", conn.connection_id, e);
                state.on_receive_close(&conn).await;
                break;
            }
        };
    }
    println!("connection_reader {} finished", conn.connection_id);
}

async fn connection_writer(
    state: Arc<State>,
    conn: Arc<Connection>,
    mut writer: WriteHalf<'_>,
    mut rx: UnboundedReceiver<WriterMessage>,
) {
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
                            println!("connection_writer {} finished", conn.connection_id);
                            return;
                        }
                    }
                }
            }
            WriterMessage::Close => {
                println!("connection_writer {} finished", conn.connection_id);
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
    state.add_connection(conn.clone()).await;

    let reader_future = connection_reader(state.clone(), conn.clone(), reader);
    let writer_future = connection_writer(state.clone(), conn.clone(), writer, rx);
    join(reader_future, writer_future).await;
    state.remove_connection(conn.clone()).await;
    println!("process_connection {} finished", connection_id);
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
