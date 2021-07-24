#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]


use std::sync::{Arc, Mutex};

struct ConnectedPeer {
}

struct BitswapShared {
}

impl BitswapShared {
    pub fn new() -> Self {
        BitswapShared {
        }
    }
}

pub struct Bitswap {
    shared: Arc<Mutex<BitswapShared>>,
}

impl Bitswap {
    pub fn new() -> Self {
        Bitswap {
            shared: Arc::new(Mutex::new(BitswapShared::new())),
        }
    }
}

impl Clone for Bitswap {
    fn clone(&self) -> Self {
        Bitswap {
            shared: self.shared.clone()
        }
    }
}
