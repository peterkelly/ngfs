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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite, BufReader, BufWriter};
use tokio::sync::{Notify};
use futures::future::join;
use torrent::util::{from_hex, escape_string, vec_with_len, BinaryData, DebugHexDump, Indent};
use torrent::binary::{BinaryReader, FromBinary, BinaryWriter, ToBinary};
// use torrent::tls::types::alert::*;
// use torrent::tls::types::handshake::*;
// use torrent::tls::types::extension::*;
// use torrent::tls::types::record::*;
// use torrent::crypt::*;
use torrent::result::GeneralError;
use torrent::protobuf::VarInt;
// use crypto::digest::Digest;
// use crypto::sha2::Sha384;
// use crypto::hkdf::{hkdf_extract, hkdf_expand};
// use crypto::aes_gcm::AesGcm;
// use ring::agreement::{PublicKey, EphemeralPrivateKey, UnparsedPublicKey, X25519};
// use ring::rand::SystemRandom;
use rustls::Session;

async fn read_multistream_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<usize, Box<dyn Error>> {
    let mut buf: [u8; 1] = [0; 1];
    let mut value: usize = 0;
    loop {
        let r = match reader.read(&mut buf).await {
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

async fn read_multistream_data(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Box<dyn Error>> {
    let expected_len = read_multistream_varint(reader).await?;
    // println!("expected_len = {}", expected_len);
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        let r = match reader.read(&mut buf).await {
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

async fn write_multistream_data(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Box<dyn Error>> {
    let len_bytes = VarInt::encode_usize(data.len());

    // let mut temp: Vec<u8> = Vec::new();
    // temp.extend_from_slice(&len_bytes);
    // temp.extend_from_slice(data);
    // println!("Sending:\n{:#?}", &DebugHexDump(&temp));


    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

struct IncomingData {
    data: Vec<u8>,
}

impl IncomingData {
    pub fn new() -> Self {
        IncomingData {
            data: Vec::new(),
        }
    }
}

impl std::io::Read for IncomingData {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        unimplemented!()
    }
}

struct OutgoingData {
    data: Vec<u8>,
}

impl OutgoingData {
    pub fn new() -> Self {
        OutgoingData {
            data: Vec::new(),
        }
    }
}

impl std::io::Write for IncomingData {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        unimplemented!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        unimplemented!()
    }
}

#[derive(Clone)]
enum ConnectionError {
    TLSError(rustls::TLSError),
    Other(String),
}

struct ConnectionInner {
}

struct Connection {
    session: Mutex<rustls::ClientSession>,
    incoming: Mutex<IncomingData>,
    outgoing: Mutex<OutgoingData>,
    read_not: Notify,
    write_not: Notify,
    error: Mutex<Option<ConnectionError>>,
    done: Mutex<bool>,
}

impl Connection {
    fn new(session: rustls::ClientSession) -> Self {
        Connection {
            session: Mutex::new(session),
            incoming: Mutex::new(IncomingData::new()),
            outgoing: Mutex::new(OutgoingData::new()),
            read_not: Notify::new(),
            write_not: Notify::new(),
            error: Mutex::new(None),
            done: Mutex::new(false),
        }
    }

    fn get_error(&self) -> Option<ConnectionError> {
        self.error.lock().unwrap().clone()
    }

    fn set_error(&self, error: Option<ConnectionError>) {
        *self.error.lock().unwrap() = error;
    }

    fn wants_read(&self) -> bool {
        self.session.lock().unwrap().wants_read()
    }

    fn on_receive_close(&self) {
    }

    fn on_receive_error(&self) {
    }

    fn on_receive_data(&self, data: &[u8]) {
        let mut incoming = self.incoming.lock().unwrap();
        let mut session = self.session.lock().unwrap();
        incoming.data.extend_from_slice(data);
        match session.read_tls(&mut *incoming) {
            Ok(res) => {
                // unimplemented!()
            }
            Err(e) => {
                self.set_error(Some(ConnectionError::Other(format!("{}", e))));
                *self.done.lock().unwrap() = true;
                return;
            }
        };
        match session.process_new_packets() {
            Ok(res) => {
                // unimplemented!()
            }
            Err(e) => {
                self.set_error(Some(ConnectionError::TLSError(e)));
                *self.done.lock().unwrap() = true;
                return;
            }
        };
        if session.wants_write() {
            self.write_not.notify_one();
        }
        unimplemented!()
    }
}

async fn connection_reader<'a>(conn: Arc<Connection>, mut reader: impl AsyncRead + Unpin) {
    const READ_SIZE: usize = 1024;
    let mut count = 0;
    // println!("connection_reader: start");
    loop {
        // let wants_read = conn.session.lock().unwrap().wants_read();
        if conn.wants_read() {

            let mut buf: [u8; READ_SIZE] = [0; READ_SIZE];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        // println!("{}: Connection closed", conn.connection_id);
                        conn.on_receive_close();
                        break;
                    }
                    Ok(r) => {
                        // let s = String::from_utf8_lossy(&buf[..r]);
                        // println!("{}: Received {} bytes: {}", conn.connection_id, r, escape_string(&s));
                        // state.on_receive(&conn, &buf[..r]).await;
                        conn.on_receive_data(&buf[..r]);
                    }
                    Err(e) => {
                        // println!("{}: Connection error: {}", conn.connection_id, e);
                        conn.on_receive_error();
                        break;
                    }
                };
            }

        }
        println!("connection_reader: count = {}", count);

        conn.read_not.notified().await;
        count += 1;

    //     match conn.read_sem.acquire().await {
    //         Ok(x) => {
    //             println!("connection_reader: Acquired permit");
    //         }
    //         Err(e) => {
    //             println!("connection_reader: Failed to acquire permit");
    //             return;
    //         }
    //     }
    }
}

async fn connection_writer<'a>(conn: Arc<Connection>, mut writer: impl AsyncWrite + Unpin) {
    loop {
        // println!("writer");
        sleep(Duration::from_millis(1000)).await;
        conn.read_not.notify_one();
    }
}

async fn test_client() -> Result<(), Box<dyn Error>> {
    let mut socket = TcpStream::connect("188.166.210.80:443").await?;
    println!("Connected to server");
    let (reader, writer) = socket.split();

    let mut config = rustls::ClientConfig::new();
    config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    let rc_config = std::sync::Arc::new(config);
    let server_name = webpki::DNSNameRef::try_from_ascii_str("pmkelly.net")?;
    // let mut session = rustls::ClientSession::new(&rc_config, server_name);
    let mut conn = Arc::new(Connection::new(rustls::ClientSession::new(&rc_config, server_name)));


    let reader_future = connection_reader(conn.clone(), reader);
    let writer_future = connection_writer(conn.clone(), writer);
    join(reader_future, writer_future).await;
    println!("Finished");

    Ok(())
}

// async fn test_client() -> Result<(), Box<dyn Error>> {
//     let mut socket = TcpStream::connect("localhost:4001").await?;
//     let (reader, writer) = socket.split();
//     let mut reader = BufReader::new(reader);
//     let mut writer = BufWriter::new(writer);
//     // const READ_SIZE: usize = 1024;

//     write_multistream_data(&mut writer, b"/multistream/1.0.0\n").await?;
//     let data = read_multistream_data(&mut reader).await?;
//     // println!("{:#?}", &DebugHexDump(&data));

//     if data == b"/multistream/1.0.0\n" {
//         println!("Got expected /multistream/1.0.0");
//     }
//     else {
//         println!("Got something else!");
//         return Ok(());
//     }


//     write_multistream_data(&mut writer, b"/tls/1.0.0\n").await?;
//     let data = read_multistream_data(&mut reader).await?;
//     // println!("{:#?}", &DebugHexDump(&data));

//     if data == b"/tls/1.0.0\n" {
//         println!("Got expected /tls/1.0.0");
//     }
//     else {
//         println!("Got something else!");
//         return Ok(());
//     }

//     println!("Attempting TLS connection");



//     Ok(())
// }

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    test_client().await
}
