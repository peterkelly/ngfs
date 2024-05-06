use futures::future::{select, Either};
use futures::pin_mut;
use std::error::Error;
use std::sync::Arc;
use std::future::Future;
use std::pin::{Pin};
use std::task::{Context, Poll};
use tokio::net::UdpSocket;

use ngfs::util::util::escape_string;

struct Receiver<A, B> {
    a: Pin<Box<dyn Future<Output = A>>>,
    b: Pin<Box<dyn Future<Output = B>>>,
}

enum MyResult<A, B> {
    First(A),
    Second(B),
}

impl<A, B> Future for Receiver<A, B> {
    type Output = MyResult<A, B>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if let Poll::Ready(res) = Future::poll(self.a.as_mut(), cx) {
            return Poll::Ready(MyResult::First(res));
        }
        if let Poll::Ready(res) = Future::poll(self.b.as_mut(), cx) {
            return Poll::Ready(MyResult::Second(res));
        }
        Poll::Pending
    }
}



async fn heap_task_inner() -> Result<(), Box<dyn Error>> {
    let sock1 = Arc::new(UdpSocket::bind("127.0.0.1:3401").await?);
    let sock2 = Arc::new(UdpSocket::bind("127.0.0.1:3402").await?);

    loop {
        let sock1 = sock1.clone();
        let sock2 = sock2.clone();


        let read1_future = async move {
            let mut buf: [u8; 1024] = [0; 1024];
            match sock1.recv_from(&mut buf).await {
                Ok((len, _)) => Ok(Vec::from(&buf[0..len])),
                Err(e) => Err(e),
            }
        };

        let read2_future = async move {
            let mut buf: [u8; 1024] = [0; 1024];
            match sock2.recv_from(&mut buf).await {
                Ok((len, _)) => Ok(Vec::from(&buf[0..len])),
                Err(e) => Err(e),
            }
        };

        let receiver = Receiver {
            a: Box::pin(read1_future),
            b: Box::pin(read2_future),
        };


        println!("Waiting to receive");
        match receiver.await {
            MyResult::First(res) => {
                match res {
                    Ok(data) => {
                        let s: String = String::from_utf8_lossy(&data).into();
                        println!("First: Received {} bytes: {}", data.len(), escape_string(&s));
                    }
                    Err(e) => {
                        println!("First: Error: {}", e);
                    }
                }
            }
            MyResult::Second(res) => {
                match res {
                    Ok(data) => {
                        let s: String = String::from_utf8_lossy(&data).into();
                        println!("Second: Received {} bytes: {}", data.len(), escape_string(&s));
                    }
                    Err(e) => {
                        println!("Second: Error: {}", e);
                    }
                }
            }
        }
    }
}

async fn heap_task() {
    match heap_task_inner().await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Receive task error: {}", e);
        }
    }
}


async fn stack_task_inner() -> Result<(), Box<dyn Error>> {
    let sock1 = Arc::new(UdpSocket::bind("127.0.0.1:3401").await?);
    let sock2 = Arc::new(UdpSocket::bind("127.0.0.1:3402").await?);

    loop {
        let sock1 = sock1.clone();
        let sock2 = sock2.clone();

        let read1_future = async move {
            let mut buf: [u8; 1024] = [0; 1024];
            match sock1.recv_from(&mut buf).await {
                Ok((len, _)) => Ok(Vec::from(&buf[0..len])),
                Err(e) => Err(e),
            }
        };

        let read2_future = async move {
            let mut buf: [u8; 1024] = [0; 1024];
            match sock2.recv_from(&mut buf).await {
                Ok((len, _)) => Ok(Vec::from(&buf[0..len])),
                Err(e) => Err(e),
            }
        };

        pin_mut!(read1_future);
        pin_mut!(read2_future);

        match select(read1_future, read2_future).await {
            Either::Left((res, _)) => {
                match res {
                    Ok(data) => {
                        let s: String = String::from_utf8_lossy(&data).into();
                        println!("First: Received {} bytes: {}", data.len(), escape_string(&s));
                    }
                    Err(e) => {
                        println!("First: Error: {}", e);
                    }
                }
            }
            Either::Right((res, _)) => {

                match res {
                    Ok(data) => {
                        let s: String = String::from_utf8_lossy(&data).into();
                        println!("Second: Received {} bytes: {}", data.len(), escape_string(&s));
                    }
                    Err(e) => {
                        println!("Second: Error: {}", e);
                    }
                }
            }
        };
    }
}

async fn stack_task() {
    match stack_task_inner().await {
        Ok(_) => (),
        Err(e) => {
            eprintln!("Receive task error: {}", e);
        }
    }
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mode: String = match std::env::args().nth(1) {
        Some(mode) => mode,
        None => {
            eprintln!("Please specify mode ('heap' or 'stack')");
            std::process::exit(1);
        }
    };

    match mode.as_str() {
        "heap" => heap_task().await,
        "stack" => stack_task().await,
        _ => {
            eprintln!("Unknown mode: {}", mode);
            std::process::exit(1);
        }
    }

    Ok(())
}
