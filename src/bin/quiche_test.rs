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
use tokio::net::UdpSocket;
use ring::rand::{SystemRandom, SecureRandom};
use quiche;

use torrent::util::{escape_string, DebugHexDump};

const MAX_DATAGRAM_SIZE: usize = 1350;


struct State {
    sock: Arc<UdpSocket>,
    config: Arc<Mutex<quiche::Config>>,
    conn: Arc<Mutex<Pin<Box<quiche::Connection>>>>,
}

async fn send_task_inner(state: Arc<State>) -> Result<(), Box<dyn Error>> {
    println!("Send task started");
    Ok(())
}

async fn send_task(state: Arc<State>) {
    match send_task_inner(state).await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Send task error: {}", e);
        }
    }
}


async fn recv_task_inner(state: Arc<State>) -> Result<(), Box<dyn Error>> {
    println!("Receive task started");
    let mut buf: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    loop {
        let (len, addr) = state.sock.recv_from(&mut buf).await?;
        println!("Received {} bytes", len);
    }
    // Ok(())
}

async fn recv_task(state: Arc<State>) {
    match recv_task_inner(state).await {
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


    let conn: Pin<Box<quiche::Connection>> = quiche::connect(Some("quic.tech:4433"), &scid, &mut config)?;
    println!("Created connection");

    let mut state = Arc::new(State {
        sock: Arc::new(sock),
        config: Arc::new(Mutex::new(config)),
        conn: Arc::new(Mutex::new(conn)),
    });

    let send_state = state.clone();
    let recv_state = state.clone();

    let send_handle = tokio::spawn(send_task(send_state));
    let recv_handle = tokio::spawn(recv_task(recv_state));

    let (r1, r2) = join(send_handle, recv_handle).await;
    r1?;
    r2?;


    Ok(())
}
