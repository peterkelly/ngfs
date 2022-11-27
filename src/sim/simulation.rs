use std::sync::{Arc, Mutex};
use rand::{RngCore, Rng};
use rand::distributions::{Standard, Distribution};
use super::clock::Clock;

struct SimulationImpl {
    clock: Clock,
    rng: Arc<Mutex<dyn RngCore>>,
}

#[derive(Clone)]
pub struct Simulation {
    imp: Arc<Mutex<SimulationImpl>>,
}

impl Simulation {
    pub fn new(rng: Arc<Mutex<dyn RngCore>>) -> Self {
        let clock = Clock::new();
        Simulation {
            imp: Arc::new(Mutex::new(SimulationImpl {
                clock: clock,
                rng: rng,
            }))
        }
    }

    pub fn current_time(&self) -> u64 {
        self.imp.lock().unwrap().clock.current_time()
    }

    pub fn set_time(&mut self, time: u64) {
        self.imp.lock().unwrap().clock.set(time);
    }

    pub fn advance_time_by(&mut self, delta: u64) {
        self.imp.lock().unwrap().clock.advance_by(delta);
    }

    pub fn gen_random<T>(&mut self) -> T where Standard: Distribution<T> {
        self.imp.lock().unwrap().rng.lock().unwrap().gen::<T>()
    }

    pub fn trace(&mut self, component: &str, msg: &str) {
        let time = self.current_time();
        let seconds = time / 1000;
        let ms = time % 1000;
        println!("{:05}.{:03} {:<12} {}", seconds, ms, component, msg);
    }

    pub fn trace_channel_send(&mut self, channel_name: &str, message_no: u64, message_desc: &str) {
        self.trace(channel_name, &format!("send {}: {}", message_no, message_desc))
    }

    pub fn trace_channel_recv(&mut self, channel_name: &str, message_no: u64, message_desc: &str) {
        self.trace(channel_name, &format!("recv {}: {}", message_no, message_desc))
    }

    pub fn trace_channel_drop(&mut self, channel_name: &str, message_no: u64, message_desc: &str) {
        self.trace(channel_name, &format!("drop {}: {}", message_no, message_desc))
    }
}
