use std::sync::{Arc, Mutex};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

struct ClockImpl {
    current_time: u64,
    wakers: Vec<Waker>,
}

impl ClockImpl {
    fn notify_waiters(&mut self) {
        for waker in self.wakers.drain(..) {
            waker.wake();
        }
    }
}

#[derive(Clone)]
pub struct Clock {
    imp: Arc<Mutex<ClockImpl>>,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            imp: Arc::new(Mutex::new(ClockImpl {
                current_time: 0,
                wakers: Vec::new(),
            }))
        }
    }

    pub fn current_time(&self) -> u64 {
        self.imp.lock().unwrap().current_time
    }

    pub fn set(&mut self, time: u64) {
        self.imp.lock().unwrap().current_time = time;
        self.imp.lock().unwrap().notify_waiters();
    }

    pub fn advance_by(&mut self, delta: u64) {
        self.imp.lock().unwrap().current_time += delta;
        self.imp.lock().unwrap().notify_waiters();
    }

    pub fn wait_until(&self, target_time: u64) -> WaitUntil {
        WaitUntil {
            clock: Clock { imp: self.imp.clone() },
            target_time: target_time,
        }
    }

    fn poll_wait_until(&self, cx: &mut Context<'_>, target_time: u64) -> Poll<()> {
        if self.current_time() >= target_time {
            Poll::Ready(())
        }
        else {
            self.imp.lock().unwrap().wakers.push(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl Default for Clock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct WaitUntil {
    clock: Clock,
    target_time: u64,
}

impl Future for WaitUntil {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.clock.poll_wait_until(cx, self.target_time)
    }
}
