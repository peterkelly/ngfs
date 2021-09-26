#[derive(Debug, Clone, Copy)]
pub struct ConnectionId(pub [u8; 20]);

#[derive(Debug, Clone, Copy)]
pub struct StreamId(pub u64);

impl StreamId {
    pub fn initiator(&self) -> StreamInitiator {
        if self.0 & 0x01 == 0 {
            StreamInitiator::Client
        }
        else {
            StreamInitiator::Server
        }
    }

    pub fn direction(&self) -> StreamDirection {
        if self.0 & 0x02 == 0 {
            StreamDirection::Bidirectional
        }
        else {
            StreamDirection::Unidirectional
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum StreamInitiator {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy)]
pub enum StreamDirection {
    Bidirectional,
    Unidirectional,
}
