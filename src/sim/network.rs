use std::sync::{Arc, Mutex};
use super::simulation::Simulation;
use super::opt_min;

#[derive(Clone)]
pub struct ChannelParameters {
    // number of ms between a packet having been injected into the network, and it arriving at
    // its destination
    pub latency_min: u64,
    pub latency_max: u64,


    // number of ms between two attempts to inject a packet into the network
    pub inv_bandwidth: u64,

    // probability that a packet, once injected into the network, will be duplicated (determined
    // before loss)
    pub dup_probability: f64,

    // probability that a packet, once injected into the network, will be lost along the way
    pub loss_probability: f64,
}

struct MessageInTransit<M> {
    message_no: u64,
    recv_time: u64,
    recv_priority: u64,
    message: M,
}

pub trait ChannelMessage {
    fn size(&self) -> usize;

    fn description(&self) -> String;
}

pub struct Channel<M : ChannelMessage + Clone> {
    sim: Simulation,
    name: String,
    messages: Vec<MessageInTransit<M>>,
    next_message_no: u64,
    next_send_time: u64,
    parameters: ChannelParameters,
}

impl<M> Channel<M> where M : ChannelMessage + Clone {
    pub fn new(name: &str, sim: &Simulation, parameters: &ChannelParameters) -> Self {
        Channel {
            name: String::from(name),
            sim: sim.clone(),
            messages: Vec::new(),
            next_message_no: 0,
            next_send_time: 0,
            parameters: parameters.clone(),
        }
    }

    pub fn next_send_time(&self) -> u64 {
        self.next_send_time
    }

    pub fn send(&mut self, message: M) {
        let p = &self.parameters;
        let send_time = self.next_send_time;
        self.next_send_time += p.inv_bandwidth;

        let count =
        if self.sim.gen_random::<f64>() <= p.dup_probability { 2 } else { 1 };

        for _ in 0..count {
            let message_no = self.next_message_no;
            self.next_message_no += 1;


            let mut latency: u64 = p.latency_min;
            if let Some(delta) = p.latency_max.checked_sub(p.latency_min) {
                latency += (self.sim.gen_random::<f64>() * (delta as f64)) as u64;
            }

            let recv_time = send_time + latency;

            if self.sim.gen_random::<f64>() <= p.loss_probability {
                self.sim.trace_channel_drop(&self.name, message_no, &message.description());
                return;
            }

            let recv_priority = self.sim.gen_random::<u64>();

            self.sim.trace_channel_send(&self.name, message_no, &message.description());
            self.messages.push(MessageInTransit {
                message_no,
                recv_time,
                recv_priority,
                message: message.clone(),
            });
        }
    }

    pub fn next_recv_time(&self) -> Option<u64> {
        let mut result: Option<u64> = None;

        for mit in self.messages.iter() {
            match result {
                None => {
                    result = Some(mit.recv_time);
                }
                Some(next) => {
                    if next > mit.recv_time {
                        result = Some(mit.recv_time);
                    }
                }
            }
        }

        return result;
    }

    pub fn recv(&mut self) -> Option<M> {
        let next_recv_time: u64 = match self.next_recv_time() {
            Some(v) => v,
            None => return None,
        };

        let mut best_index: Option<usize> = None;
        for i in 0..self.messages.len() {
            if self.messages[i].recv_time == next_recv_time {
                match best_index {
                    None => {
                        best_index = Some(i);
                    }
                    Some(bi) => {
                        if self.messages[bi].recv_priority > self.messages[i].recv_priority {
                            best_index = Some(i);
                        }
                    }
                }
            }
        }

        match best_index {
            None => {
                return None;
            }
            Some(i) => {
                let mit = self.messages.remove(i);
                self.sim.trace_channel_recv(&self.name, mit.message_no, &mit.message.description());
                return Some(mit.message);

            }
        }
    }
}

pub struct Endpoint<M> where M : ChannelMessage + Clone {
    send_channel: Arc<Mutex<Channel<M>>>,
    recv_channel: Arc<Mutex<Channel<M>>>,
}

impl<M> Endpoint<M> where M : ChannelMessage + Clone {
    pub fn make_pair(
        name1: &str,
        name2: &str,
        sim: &Simulation,
        parameters: &ChannelParameters,
    ) -> (Endpoint<M>, Endpoint<M>) {
        let fst = Arc::new(Mutex::new(Channel::new(name1, sim, parameters)));
        let snd = Arc::new(Mutex::new(Channel::new(name2, sim, parameters)));

        let fs = Endpoint {
            send_channel: fst.clone(),
            recv_channel: snd.clone(),
        };

        let sf = Endpoint {
            send_channel: snd.clone(),
            recv_channel: fst.clone(),
        };

        (fs, sf)
    }

    pub fn next_send_time(&self) -> u64 {
        self.send_channel.lock().unwrap().next_send_time()
     }

    pub fn next_recv_time(&self) -> Option<u64> {
        self.recv_channel.lock().unwrap().next_recv_time()
    }

    pub fn send(&mut self, message: M) {
        self.send_channel.lock().unwrap().send(message)
    }

    pub fn recv(&mut self) -> Option<M> {
        self.recv_channel.lock().unwrap().recv()
    }

    pub fn next_event_time(&self) -> Option<u64> {
        opt_min(&[Some(self.next_send_time()), self.next_recv_time()])
    }
}
