#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use futures::future::{select, join, Either};
use futures::pin_mut;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::future::Future;
use std::pin::{Pin};
use std::task::{Context, Poll};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{UnboundedSender, UnboundedReceiver};
use ring::rand::{SystemRandom, SecureRandom};
use quiche;

use torrent::util::{escape_string, DebugHexDump};

const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Debug)]
enum SenderMessage {
    Data(Vec<u8>),
    Done,
}

#[derive(Debug)]
enum RecevierMessage {
    Done,
}

struct State {
    sock: Arc<UdpSocket>,
    config: Arc<Mutex<quiche::Config>>,
    conn: Arc<Mutex<Pin<Box<quiche::Connection>>>>,
}

async fn send_task_inner(state: Arc<State>,
                         mut sender_rx: UnboundedReceiver<SenderMessage>,
                         receiver_tx: UnboundedSender<RecevierMessage>) -> Result<(), Box<dyn Error>> {
    let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];

    loop {
        // println!("**** Sender: Start of loop iteration");
        let msg = sender_rx.recv().await;
        match msg {
            Some(SenderMessage::Data(data)) => {
                // println!("**** Sender: Asked to send {} bytes", data.len());
                let r = state.sock.send(&data).await?;
                println!("**** Sender: Sent {} bytes", r);
            }
            Some(SenderMessage::Done) => {
                // println!("**** Sender: received Done message");
                break;
            }
            None => {
                // println!("**** Sender: msg is None");
                break;
            }
        }
    }
    // println!("**** Sender: Finished");
    Ok(())
}

async fn send_task(state: Arc<State>, sender_rx: UnboundedReceiver<SenderMessage>,
                   receiver_tx: UnboundedSender<RecevierMessage>) {
    match send_task_inner(state, sender_rx, receiver_tx).await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Send task error: {}", e);
        }
    }
}

async fn conn_send_loop(state: &Arc<State>, sender_tx: &UnboundedSender<SenderMessage>) -> Result<(), Box<dyn Error>> {
    let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    loop {
        let write_len = {
            let mut conn = state.conn.lock().unwrap();
            match conn.send(&mut buf) {
                Ok(write_len) => {
                    // println!("conn.send() returned {}", write_len);
                    write_len
                }
                Err(e) => {
                    if e == quiche::Error::Done {
                        // println!("conn.send() had error {}", e);
                        return Ok(())
                    }
                    else {
                        return Err(e.into())
                    }
                }
            }
        };

        match sender_tx.send(SenderMessage::Data(Vec::from(&buf[0..write_len]))) {
            Ok(()) => (),
            Err(e) => {
                println!("sender_tx.send() failed: {}", e);
                return Err(e.into());
            }
        };
    }
}

async fn recv_one(state: &Arc<State>) -> Result<(), Box<dyn Error>> {
    let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let (len, addr) = state.sock.recv_from(&mut buf).await?;
    println!("Receiver: Got {} bytes from {}", len, addr);

    {
        let mut conn = state.conn.lock().unwrap();
        let processed = conn.recv(&mut buf[0..len])?;
        println!("Receiver: Processed {} bytes (established? {}, closed? {})",
            processed, conn.is_established(), conn.is_closed());

        // let s: String = String::from_utf8_lossy(&buf[0..len]).into();
        // println!("Receiver: content {}", escape_string(&s));

    }
    Ok(())
}

async fn recv_task_inner(state: Arc<State>,
                         sender_tx: UnboundedSender<SenderMessage>,
                         mut receiver_rx: UnboundedReceiver<RecevierMessage>,
                         ) -> Result<(), Box<dyn Error>> {
    println!("Receive task started");


    loop {
        let old_established = { state.conn.lock().unwrap().is_established() };

        recv_one(&state).await?;
        {
            let mut conn = state.conn.lock().unwrap();

            if conn.is_closed() {
                println!("================ CONNECTION CLOSED ================");
                return Ok(());
            }
        }
        let new_established = { state.conn.lock().unwrap().is_established() };


        if !old_established && new_established {
            println!("================ CONNECTION ESTABLISHED ================");
            {
                let mut conn = state.conn.lock().unwrap();
                conn.stream_send(0, "GET /\r\n".as_bytes(), true)?;
            };
        }

        {
            let mut conn = state.conn.lock().unwrap();
            if conn.is_established() {
                for s in conn.readable() {
                    loop {
                        let mut read_buf: [u8; 65536] = [0; 65536];
                        match conn.stream_recv(s, &mut read_buf) {
                            Ok((len, fin)) => {
                                let data_string: String = String::from_utf8_lossy(&read_buf[0..len]).into();
                                println!("stream_recv() s {} returned {} bytes, fin? {}: {}", s, len, fin,
                                    escape_string(&data_string));
                                println!("-- {:?}", DebugHexDump(&read_buf[0..len]));
                                if fin {
                                    break;
                                }
                            }
                            Err(e) => {
                                if e == quiche::Error::Done {
                                    break;
                                }
                                println!("stream_recv() error: {}", e);
                            }
                        }
                    }
                }
            }
        }

        conn_send_loop(&state, &sender_tx).await?;



        // let s: String = String::from_utf8_lossy(&buf[0..len]).into();
        // println!("Received {} bytes from {}: {}", len, addr, escape_string(&s));
    }

    // loop {

    //     let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];

    //     let udp_recv_future = state.sock.recv_from(&mut buf);
    //     let mpsc_recv_future = receiver_rx.recv();
    //     pin_mut!(udp_recv_future);
    //     pin_mut!(mpsc_recv_future);

    //     match select(udp_recv_future, mpsc_recv_future).await {
    //         Either::Left((a, b)) => {
    //             let res: Result<(usize, SocketAddr), std::io::Error> = a;
    //             let z: Pin<&mut dyn futures::Future<Output = Option<RecevierMessage>>> = b;

    //             match res {
    //                 Ok((len, addr)) => {
    //                     let s: String = String::from_utf8_lossy(&buf[0..len]).into();
    //                     println!("Received {} bytes from {}: {}", len, addr, escape_string(&s));
    //                 }
    //                 Err(e) => {
    //                     eprintln!("recv_from() call failed: {}", e);
    //                     return Ok(())
    //                 }
    //             }
    //         }
    //         Either::Right((a, b)) => {
    //             let res: Option<RecevierMessage> = a;
    //             let z: Pin<&mut dyn futures::Future<Output = Result<(usize, SocketAddr), std::io::Error>>> = b;

    //             match res {
    //                 None => return Ok(()),
    //                 Some(RecevierMessage::Done) => return Ok(()),
    //             }
    //         }
    //     }
    // }

    // loop {

    //     let (len, addr) = state.sock.recv_from(&mut buf).await?;
    //     println!("Received {} bytes", len);
    // }
    // Ok(())
}

async fn recv_task(state: Arc<State>,
                   sender_tx: UnboundedSender<SenderMessage>,
                   receiver_rx: UnboundedReceiver<RecevierMessage>) {
    match recv_task_inner(state, sender_tx, receiver_rx).await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Receive task error: {}", e);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;

    // *CAUTION*: this should not be set to `false` in production!!!
    config.verify_peer(false);

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_udp_payload_size(MAX_DATAGRAM_SIZE as u64);
    // config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);



    let mut scid = vec![0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();
    println!("quiche::MAX_CONN_ID_LEN = {}", quiche::MAX_CONN_ID_LEN);
    println!("scid = {:?}", DebugHexDump(&scid));

    // let scid = quiche::ConnectionId::from_vec(scid);
    // let scid: Vec<u8> = vec![1, 2, 3];


    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    println!("Bound socket");
    sock.connect("quic.tech:8443").await?;
    println!("Connected socket");


    let conn: Pin<Box<quiche::Connection>> = quiche::connect(Some("quic.tech:8443"), &scid, &mut config)?;
    println!("Created connection");

    let mut state = Arc::new(State {
        sock: Arc::new(sock),
        config: Arc::new(Mutex::new(config)),
        conn: Arc::new(Mutex::new(conn)),
    });


    let (sender_tx, mut sender_rx) = mpsc::unbounded_channel::<SenderMessage>();
    let (receiver_tx, mut receiver_rx) = mpsc::unbounded_channel::<RecevierMessage>();


    conn_send_loop(&state, &sender_tx.clone()).await?;

    let send_state = state.clone();
    let recv_state = state.clone();

    let send_handle = tokio::spawn(send_task(send_state, sender_rx, receiver_tx));
    let recv_handle = tokio::spawn(recv_task(recv_state, sender_tx.clone(), receiver_rx));

    sender_tx.send(SenderMessage::Data(Vec::from("Hello\n".as_bytes())))?;

    let (r1, r2) = join(send_handle, recv_handle).await;
    r1?;
    r2?;

    sender_tx.send(SenderMessage::Done)?;


    Ok(())
}
