use std::fmt;
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::{BufMut};
use crate::util::BinaryData;
use crate::protobuf::VarInt;

enum DecodeVarintError {
    UnexpectedEof,
}

fn decode_varint_u64(data: &[u8]) -> Result<(u64, usize), DecodeVarintError>
{
    let mut parts: Vec<u8> = Vec::new();
    let mut offset = 0;
    loop {
        match data.get(offset) {
            None => return Err(DecodeVarintError::UnexpectedEof),
            Some(b) => {
                offset += 1;
                parts.push(*b);
                if *b & 0x80 == 0 {
                    break;
                }
            }
        }
    }

    Ok((VarInt(&parts).to_u64(), offset))
}

#[derive(Clone)]
pub enum Addr {
    IP4(Ipv4Addr),
    IP6(Ipv6Addr),
    TCP(u16),
    UDP(u16),
    QUIC,
    Unknown(u64, Vec<u8>),
    Invalid(Vec<u8>),
}

const PROTOCOL_IP4: u64 = 0x0004;
const PROTOCOL_IP6: u64 = 0x0029;
const PROTOCOL_TCP: u64 = 0x0006;
const PROTOCOL_UDP: u64 = 0x0111;
const PROTOCOL_QUIC: u64 = 0x01cc;

impl Addr {
    fn read(bytes: &[u8]) -> (Addr, usize) {
        let (protocol_num, data_offset) = match decode_varint_u64(bytes) {
            Ok((p, n)) => (p, n),
            Err(_) => {
                return (Addr::Invalid(Vec::from(bytes)), bytes.len());
            }
        };
        match protocol_num {
            PROTOCOL_IP4 => {
                if data_offset + 4 <= bytes.len() {
                    let mut octets: [u8; 4] = Default::default();
                    octets.copy_from_slice(&bytes[data_offset..data_offset + 4]);
                    let ip = Ipv4Addr::from(octets);
                    let end_offset = data_offset + 4;
                    (Addr::IP4(ip), end_offset)
                }
                else {
                    (Addr::Invalid(Vec::from(bytes)), bytes.len())
                }
            }
            PROTOCOL_IP6 => {
                if data_offset + 16 <= bytes.len() {
                    let mut octets: [u8; 16] = Default::default();
                    octets.copy_from_slice(&bytes[data_offset..data_offset + 16]);
                    let ip = Ipv6Addr::from(octets);
                    let end_offset = data_offset + 16;
                    (Addr::IP6(ip), end_offset)
                }
                else {
                    (Addr::Invalid(Vec::from(bytes)), bytes.len())
                }
            }
            PROTOCOL_TCP => {
                if data_offset + 2 <= bytes.len() {
                    let be_bytes: [u8; 2] = [
                        bytes[data_offset + 0],
                        bytes[data_offset + 1],
                    ];

                    let port = u16::from_be_bytes(be_bytes);
                    let end_offset = data_offset + 2;

                    (Addr::TCP(port), end_offset)
                }
                else {
                    (Addr::Invalid(Vec::from(bytes)), bytes.len())
                }
            }
            PROTOCOL_UDP => {
                if data_offset + 2 <= bytes.len() {
                    let be_bytes: [u8; 2] = [
                        bytes[data_offset + 0],
                        bytes[data_offset + 1],
                    ];

                    let port = u16::from_be_bytes(be_bytes);
                    let end_offset = data_offset + 2;

                    (Addr::UDP(port), end_offset)
                }
                else {
                    (Addr::Invalid(Vec::from(bytes)), bytes.len())
                }
            }
            PROTOCOL_QUIC => {
                let end_offset = data_offset;
                (Addr::QUIC, end_offset)
            }
            _ => (Addr::Invalid(Vec::from(bytes)), bytes.len()),
        }
    }

    fn encode<T>(&self, out: &mut T) where T : BufMut {
        match self {
            Addr::IP4(ip) => {
                out.put_slice(&VarInt::encode_u64(PROTOCOL_IP4));
                out.put_slice(&ip.octets());
            }
            Addr::IP6(ip) => {
                out.put_slice(&VarInt::encode_u64(PROTOCOL_IP6));
                out.put_slice(&ip.octets());
            }
            Addr::TCP(port) => {
                out.put_slice(&VarInt::encode_u64(PROTOCOL_TCP));
                out.put_slice(&port.to_be_bytes());
            }
            Addr::UDP(port) => {
                out.put_slice(&VarInt::encode_u64(PROTOCOL_UDP));
                out.put_slice(&port.to_be_bytes());
            }
            Addr::QUIC => {
                out.put_slice(&VarInt::encode_u64(PROTOCOL_QUIC));
            }
            Addr::Unknown(proto, data) => {
                out.put_slice(&VarInt::encode_u64(*proto));
                out.put_slice(data);
            }
            Addr::Invalid(data) => {
                out.put_slice(data);
            }
        }
    }
}

impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Addr::IP4(ip) => write!(f, "/ipv4/{}", ip),
            Addr::IP6(ip) => write!(f, "/ipv6/{}", ip),
            Addr::TCP(port) => write!(f, "/tcp/{}", port),
            Addr::UDP(port) => write!(f, "/udp/{}", port),
            Addr::QUIC => write!(f, "/quic"),
            Addr::Unknown(proto, data) => write!(f, "/unknown/{}/{:?}", proto, BinaryData(data)),
            Addr::Invalid(data) => write!(f, "/invalid/{:?}", BinaryData(data)),
        }
    }
}


#[derive(Clone)]
pub struct MultiAddr(pub Vec<Addr>);

impl MultiAddr {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let mut addrs: Vec<Addr> = Vec::new();
        let mut offset = 0;
        while offset < bytes.len() {
            let (addr, consumed) = Addr::read(&bytes[offset..]);
            addrs.push(addr);
            offset += consumed;
        }
        Ok(MultiAddr(addrs))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        self.encode(&mut result);
        result
    }

    fn encode<T>(&self, out: &mut T) where T : BufMut {
        for addr in self.0.iter() {
            addr.encode(out);
        }
    }
}

impl fmt::Display for MultiAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for addr in self.0.iter() {
            write!(f, "{}", addr)?;
        }
        Ok(())
    }
}

impl fmt::Debug for MultiAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", format!("{}", self))?;
        Ok(())
    }
}
