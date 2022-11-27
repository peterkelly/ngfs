// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]
#![allow(clippy::redundant_field_names)]
#![allow(clippy::collapsible_if)]

use std::sync::{Arc, Mutex};
use std::cmp::Ordering;
use rand::rngs::StdRng;
use rand::{SeedableRng, RngCore};
use torrent::sim::{
    ChannelParameters,
    Endpoint,
    ChannelMessage,
    Simulation,
};

const RETRANSMIT_DELAY: u64 = 1000;

#[derive(Clone)]
struct DataMessage {
    seq: u64,
    data: String,
}

#[derive(Clone)]
struct AckMessage {
    ack: u64,
}

#[derive(Clone)]
enum Message {
    Data(DataMessage),
    Ack(AckMessage),
}

impl ChannelMessage for Message {
    fn size(&self) -> usize {
        1
    }

    fn description(&self) -> String {
        match self {
            Message::Data(m) => format!("Data(seq = {})", m.seq),
            Message::Ack(m) => format!("Ack(ack = {})", m.ack),
        }
    }
}

struct Peer {
    name: String,
    sim: Simulation,
    endpoint: Endpoint<Message>,
    seq: u64,
    count: u64,
    ack: u64,
    retransmit_time: Option<u64>,
}

impl Peer {
    fn new(name: &str, sim: &Simulation, endpoint: Endpoint<Message>, count: u64) -> Self {
        Peer {
            name: String::from(name),
            sim: sim.clone(),
            endpoint: endpoint,
            seq: 0,
            ack: 0,
            count: count,
            retransmit_time: None,
        }
    }

    fn can_send(&self) -> bool {
        self.sim.current_time() >= self.endpoint.next_send_time()
    }

    fn step(&mut self) {
        while let Some(message) = self.endpoint.recv() {
            match message {
                Message::Data(m) => {
                    match self.ack.cmp(&m.seq) {
                        Ordering::Less => {
                            // future
                            self.sim.trace(
                                &self.name,
                                &format!("received message with seq = {}, data = {:?} [FUTURE]",
                                    m.seq, m.data));
                        }
                        Ordering::Equal => {
                            // ok
                            self.sim.trace(
                                &self.name,
                                &format!("received message with seq = {}, data = {:?} (ok)",
                                    m.seq, m.data));
                            self.ack = m.seq + 1;
                            self.endpoint.send(Message::Ack(AckMessage { ack: self.ack }));
                        }
                        Ordering::Greater => {
                            // duplicate
                            self.sim.trace(
                                &self.name,
                                &format!("received message with seq = {}, data = {:?} [DUP]",
                                    m.seq, m.data));
                            self.endpoint.send(Message::Ack(AckMessage { ack: self.ack }));
                        }
                    }






                    // self.endpoint.send(Message::Ack(AckMessage { ack: m.seq + 1 }));
                }
                Message::Ack(m) => {
                    match self.ack.cmp(&m.ack) {
                        Ordering::Less => {
                            self.ack = m.ack;
                            self.retransmit_time = None;
                            self.sim.trace(&self.name, &format!("received ack with ack_no = {}", m.ack));
                        }
                        Ordering::Equal => {
                            self.sim.trace(&self.name, &format!("received ack with ack_no = {} [DUP]", m.ack));
                        }
                        Ordering::Greater => {
                            self.sim.trace(&self.name, &format!("received ack with ack_no = {} [STALE]", m.ack));
                        }
                    }
                }
            }
        }

        match self.retransmit_time {
            None => {},
            Some(retransmit_time) => {
                if retransmit_time >= self.sim.current_time() && self.can_send() {
                    self.seq = self.ack;
                    self.sim.trace(&self.name, &format!("Triggering retransmit of seq {}", self.seq));
                }
            }
        }

        if self.ack == self.seq && self.can_send() {
            if self.seq < self.count {
                let message = Message::Data(DataMessage {
                    seq: self.seq,
                    data: format!("Message {}", self.seq),
                });
                self.endpoint.send(message);
                self.seq += 1;
                self.retransmit_time = Some(self.sim.current_time() + RETRANSMIT_DELAY);
            }
        }






        // if self.seq < self.count && self.sim.current_time() >= self.endpoint.next_send_time() {
        //     let sequence_no = self.seq;
        //     self.seq += 1;
        //     let message = Message::Data(DataMessage {
        //         sequence_no: sequence_no as u64,
        //         data: format!("Message {}", sequence_no),
        //     });
        //     self.sim.trace("producer", "adding message");
        //     self.endpoint.send(message);
        // }

        // while let Some(message) = self.endpoint.recv() {
        //     match message {
        //         Message::Data(m) => {
        //             self.sim.trace("producer", &format!("received message with sequence_no = {}, data = {:?}",
        //                 m.sequence_no, m.data));
        //         }
        //         Message::Ack(m) => {
        //             self.sim.trace("producer", &format!("received ack with ack_no = {}",
        //                 m.ack_no));
        //         }
        //     }
        // }
    }
}

// struct Consumer {
//     sim: Simulation,
//     endpoint: Endpoint<Message>,
//     received: usize,
// }

// impl Consumer {
//     fn new(sim: &Simulation, endpoint: Endpoint<Message>) -> Self {
//         Consumer {
//             sim: sim.clone(),
//             endpoint: endpoint,
//             received: 0,
//         }
//     }

//     fn step(&mut self) {
//         while let Some(message) = self.endpoint.recv() {
//             match message {
//                 Message::Data(m) => {
//                     self.sim.trace("consumer", &format!("received message with sequence_no = {}, data = {:?}",
//                         m.sequence_no, m.data));
//                     self.endpoint.send(Message::Ack(AckMessage { ack_no: m.sequence_no }));
//                 }
//                 Message::Ack(m) => {
//                     self.sim.trace("consumer", &format!("received ack with ack_no = {}",
//                         m.ack_no));
//                 }
//             }
//         }
//     }
// }

struct Processes {
    producer: Peer,
    consumer: Peer,
}

fn main() {
    let parameters = ChannelParameters {
        latency_min: 200,
        latency_max: 600,
        inv_bandwidth: 523,
        dup_probability: 0.0,
        loss_probability: 0.7,
    };


    let rng: Arc<Mutex<dyn RngCore>> = Arc::new(Mutex::new(StdRng::seed_from_u64(0)));
    let mut sim = Simulation::new(rng.clone());
    let max_time = 100_000;

    let (p2c, c2p) = Endpoint::make_pair("p->c", "c->p", &sim, &parameters);

    let mut processes = Processes {
        producer: Peer::new("producer", &sim, p2c, 5),
        consumer: Peer::new("consumer", &sim, c2p, 0),
    };

    for i in 0..max_time {
        sim.set_time(i);
        processes.producer.step();
        processes.consumer.step();
    }
    println!("Done");
}
