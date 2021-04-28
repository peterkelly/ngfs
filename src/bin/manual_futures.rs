const PRODUCER_COUNT: usize = 10;
const CONSUMER_COUNT: usize = 5;
const PRODUCER_DELAY_MS: u64 = 500;

use std::pin::Pin;
use std::task::{Context, Poll};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::error::Error;
use tokio::time::sleep;
use futures::future::join;

struct Shared {
    count: usize,
    consumer_waker: Option<std::task::Waker>,
}

async fn producer(shared: Arc<Mutex<Shared>>) {
    loop {
        sleep(Duration::from_millis(PRODUCER_DELAY_MS)).await;
        {
            let mut shared = shared.lock().unwrap();
            shared.count += 1;
            println!("producer: count = {}", shared.count);
            if shared.count >= PRODUCER_COUNT {
                return;
            }
        }
    }
}

struct ConsumerFuture {
    shared: Arc<Mutex<Shared>>,
}

impl ConsumerFuture {
    fn new(shared: Arc<Mutex<Shared>>) -> Self {
        ConsumerFuture {
            shared: shared,
        }
    }
}

impl Future for ConsumerFuture {
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut shared = self.shared.lock().unwrap();
        println!("ConsumerFuture::poll: count = {}", shared.count);
        if shared.count >= CONSUMER_COUNT {
            Poll::Ready(shared.count)
        }
        else {
            shared.consumer_waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}

fn consumer2<'a>(shared: Arc<Mutex<Shared>>) -> impl Future<Output = usize> {
    ConsumerFuture::new(shared)
}

async fn consumer<'a>(shared: Arc<Mutex<Shared>>) {
    let res = consumer2(shared).await;
    println!("consumer: res = {}", res);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let shared = Arc::new(Mutex::new(Shared {
        count: 0,
        consumer_waker: None,
    }));
    let producer_future = producer(shared.clone());
    let consumer_future = consumer(shared.clone());
    join(producer_future, consumer_future).await;
    Ok(())
}
