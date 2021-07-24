#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::sync::{Arc, Mutex};
use crate::io::AsyncStream;
use crate::ipfs::bitswap::bitswap::Bitswap;

pub struct IPFSNode {
    pub dalek_keypair: ed25519_dalek::Keypair,
    pub bitswap: Bitswap,
}

impl IPFSNode {
    pub fn new(dalek_keypair: ed25519_dalek::Keypair) -> Self {
        IPFSNode {
            dalek_keypair: dalek_keypair,
            bitswap: Bitswap::new(),
        }
    }
}

type Handler = Box<&'static (dyn Fn(Arc<IPFSNode>, Box<dyn AsyncStream>) -> () + Send + Sync + 'static)>;

pub struct Service {
    pub name: String,
    pub bname: Vec<u8>,
    pub handler: Handler,
}

pub struct ServiceRegistry {
    pub entries: Vec<Service>,
}

impl ServiceRegistry {
    pub fn new() -> Self {
        ServiceRegistry {
            entries: Vec::new()
            // phantom: std::marker::PhantomData,
        }
    }

    pub fn add(&mut self, name: &str, handler: Handler) {
        self.entries.push(Service {
            name: String::from(name),
            bname: Vec::from(format!("{}\n", name).as_bytes()),
            handler: handler,
        });
    }

    pub fn lookup(&self, bname: &[u8]) -> Option<&Handler> {
        for service in self.entries.iter() {
            if service.bname == bname {
                return Some(&service.handler);
            }
        }
        return None;
    }
}
