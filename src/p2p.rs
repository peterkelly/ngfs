#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use tokio::net::{lookup_host};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::prelude::*;
// use native_tls;
// use tokio_tls;
use openssl::rsa::Rsa;
use rand::prelude::Rng;
use super::result::{GeneralError, general_error};
use super::util::{BinaryData, escape_string};
use super::protobuf::{PBufReader, PBufWriter, VarInt};

#[derive(Debug, Clone)]
pub enum KeyType {
    RSA = 0,
    Ed25519 = 1,
    Secp256k1 = 2,
    ECDSA = 3,
}

#[derive(Clone)]
pub struct PublicKey {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

impl PublicKey {
    pub fn from_pb(raw_data: &[u8]) -> Result<PublicKey, Box<dyn Error>> {
        let mut key_type: Option<KeyType> = None;
        let mut data: Option<Vec<u8>> = None;

        let mut reader = PBufReader::new(&raw_data);
        while let Some(field) = reader.read_field()? {
            // println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            //     field.offset, field.field_number, field.data);
            match field.field_number {
                1 => {
                    let key_type_int = field.data.to_u64()?;
                    key_type = match key_type_int {
                        0 => Some(KeyType::RSA),
                        1 => Some(KeyType::Ed25519),
                        2 => Some(KeyType::Secp256k1),
                        3 => Some(KeyType::ECDSA),
                        _ => {
                            return general_error(&format!("Unknown key type: {}", key_type_int));
                        }
                    }
                }
                2 => {
                    data = Some(Vec::from(field.data.to_bytes()?));
                }
                _ => {
                }
            }
        }

        let key_type: KeyType = key_type.ok_or_else(|| GeneralError::new(&format!("Missing field: key_type")))?;
        let data: Vec<u8> = data.ok_or_else(|| GeneralError::new(&format!("Missing field: data")))?;

        Ok(PublicKey {
            key_type,
            data,
        })
    }

    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_uint64(1, self.key_type.clone() as u64);
        writer.write_bytes(2, &self.data);
        writer.data
    }
}

pub struct PrivateKey {
    pub key_type: KeyType,
    pub data: Vec<u8>,
}

impl PrivateKey {
    pub fn from_pb(raw_data: &[u8]) -> Result<PrivateKey, Box<dyn Error>> {
        let k = PublicKey::from_pb(raw_data)?;
        Ok(PrivateKey { key_type: k.key_type, data: k.data })
    }
}

struct Propose {
    rand: Vec<u8>,
    pubkey: PublicKey,
    exchanges: Vec<String>,
    ciphers: Vec<String>,
    hashes: Vec<String>,
}

impl Propose {
    fn from_pb(raw_data: &[u8]) -> Result<Propose, Box<dyn Error>> {
        let mut reader = PBufReader::new(&raw_data);

        let mut rand: Option<Vec<u8>> = None;
        let mut pubkey: Option<Vec<u8>> = None;
        let mut exchanges: Option<String> = None;
        let mut ciphers: Option<String> = None;
        let mut hashes: Option<String> = None;


        while let Some(field) = reader.read_field()? {
            // println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            //     field.offset, field.field_number, field.data);
            match field.field_number {
                1 => {
                    rand = Some(Vec::from(field.data.to_bytes()?));
                }
                2 => {
                    pubkey = Some(Vec::from(field.data.to_bytes()?));
                }
                3 => {
                    exchanges = Some(field.data.to_string()?);
                }
                4 => {
                    ciphers = Some(field.data.to_string()?);
                }
                5 => {
                    hashes = Some(field.data.to_string()?);
                }
                _ => {
                }
            }
        }

        let rand: Vec<u8> = rand.ok_or_else(|| GeneralError::new(&format!("Missing field: rand")))?;
        let pubkey: Vec<u8> = pubkey.ok_or_else(|| GeneralError::new(&format!("Missing field: pubkey")))?;
        let exchanges: String = exchanges.ok_or_else(|| GeneralError::new(&format!("Missing field: exchanges")))?;
        let ciphers: String = ciphers.ok_or_else(|| GeneralError::new(&format!("Missing field: ciphers")))?;
        let hashes: String = hashes.ok_or_else(|| GeneralError::new(&format!("Missing field: hashes")))?;

        Ok(Propose {
            rand,
            pubkey: PublicKey::from_pb(&pubkey)?,
            exchanges: exchanges.split(',').map(|s| String::from(s)).collect(),
            ciphers: ciphers.split(',').map(|s| String::from(s)).collect(),
            hashes: hashes.split(',').map(|s| String::from(s)).collect(),
        })
    }

    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        // writer.write_uint64(1, self.key_type.clone() as u64);
        // writer.write_bytes(2, &self.data);
        writer.write_bytes(1, &self.rand);
        writer.write_bytes(2, &self.pubkey.to_pb());
        writer.write_string(3, &join_strings(&self.exchanges, ","));
        writer.write_string(4, &join_strings(&self.ciphers, ","));
        writer.write_string(5, &join_strings(&self.hashes, ","));
        writer.data
    }
}

fn join_strings(strings: &Vec<String>, joiner: &str) -> String {
    let mut result = String::new();
    for (i, s) in strings.iter().enumerate() {
        if i > 0 {
            result.push_str(joiner);
        }
        result.push_str(s);
    }
    return result;
}


async fn send_string(stream: &mut TcpStream, tosend_str: &str) -> Result<(), Box<dyn Error>> {
    send_bytes(stream, &tosend_str.as_bytes()).await?;
    println!("Sent {}", escape_string(tosend_str));
    Ok(())
}

async fn send_bytes(stream: &mut TcpStream, tosend_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut tosend: Vec<u8> = Vec::new();
    tosend.append(&mut VarInt::encode_usize(tosend_bytes.len()));
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);
    if w != tosend.len() {
        return general_error(&format!("Only sent {} bytes of {}", w, tosend.len()));
    }
    Ok(())
}

async fn send_length_prefixed_bytes(stream: &mut TcpStream, tosend_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut tosend: Vec<u8> = Vec::new();
    tosend.append(&mut Vec::from(&(tosend_bytes.len() as u32).to_be_bytes()[..]));
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);
    if w != tosend.len() {
        return general_error(&format!("Only sent {} bytes of {}", w, tosend.len()));
    }
    Ok(())
}

pub fn print_fields(data: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut reader = PBufReader::new(&data);
    while let Some(field) = reader.read_field()? {
        println!("offset 0x{:04x}, field_number {:2}, data {:?}",
            field.offset, field.field_number, field.data);
        // println!();
        // match show_field(&field) {
        //     Ok(_) => (),
        //     Err(e) => {
        //         println!("    Error: {}", e);
        //     }
        // }
        // println!();
    }
    Ok(())
}

async fn recv_length_prefixed_binary(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    println!("recv_length_prefixed_binary");
    let mut length_buf: [u8; 4] = [0; 4];
    let r = stream.read(&mut length_buf).await?;
    if r != 4 {
        return general_error("Insufficient data while reading message length");
    }
    println!("length_buf = {:?}", length_buf);
    let msglen = u32::from_be_bytes(length_buf) as usize;
    println!("msglen = {}", msglen);
    if msglen >= 0x800000 {
        return general_error(&format!("Message length {} exceeds allowed length", msglen));
    }
    let mut body: Vec<u8> = Vec::with_capacity(msglen as usize);

    let mut total_read  = 0;
    const CHUNK_SIZE: usize = 16;
    while total_read < msglen {
        let mut msg_buf: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
        let want: usize;
        if total_read + CHUNK_SIZE <= msglen {
            want = CHUNK_SIZE;
        }
        else {
            want = msglen - total_read;
        }
        let r = stream.read(&mut msg_buf[0..want]).await?;
        if r != want {
            println!("r = {}", r);
            break;
        }
        total_read += r;
        body.append(&mut Vec::from(&msg_buf[0..r]));
    }

    if total_read != msglen {
        return general_error(&format!("Insufficient data while reading message body; got {} bytes, expected {}", total_read, msglen));
    }


    // let r = stream.read(&mut body).await?;
    // if r != msglen {
    //     return general_error(&format!("Insufficient data while reading message body; got {} bytes, expected {}", r, msglen));
    // }
    Ok(body)
}

fn make_propose(rng: &mut impl Rng, pubkey: &PublicKey) -> Propose {
    // let transaction_id: f64 = rng.gen();

    let mut rand_bytes: Vec<u8> = Vec::with_capacity(16);
    for i in 0..16 {
        rand_bytes.push(rng.gen());
    }

    // let exchanges: Vec<String> = vec![String::from("P-256")];
    // let ciphers: Vec<String> = vec![String::from("AES-256")];
    // let hashes: Vec<String> = vec![String::from("SHA256")];


    let exchanges: Vec<String> = vec![String::from("P-256"), String::from("P-384"), String::from("P-521")];
    let ciphers: Vec<String> = vec![String::from("AES-256"), String::from("AES-128"), String::from("Blowfish")];
    let hashes: Vec<String> = vec![String::from("SHA256"), String::from("SHA512")];

    Propose {
        rand: Vec::from(rand_bytes),
        pubkey: pubkey.clone(),
        exchanges,
        ciphers,
        hashes,
    }
}

pub async fn p2p_test(server_addr_str: &str) -> Result<(), Box<dyn Error>> {
    println!("Before generate");
    let local_rsa_private_key = Rsa::generate(4096)?;
    println!("After generate");
    // let local_rsa_public_key_bytes = local_rsa_private_key.private_key_to_pem()?;
    let local_rsa_public_key_bytes = local_rsa_private_key.public_key_to_der()?;
    println!("After public_key_to_der_pkcs1: {}", BinaryData(&local_rsa_public_key_bytes));
    std::fs::write("my-public-key", &local_rsa_public_key_bytes)?;





    let mut rng = rand::thread_rng();
    let peer_addr: SocketAddr = match lookup_host(server_addr_str).await?.next() {
        Some(v) => v,
        None => return general_error(&format!("Cannot resolve host: {}", server_addr_str)),
    };

    println!("Before opening connection");
    let mut stream = TcpStream::connect(peer_addr).await?;
    println!("After opening connection");

    let mut buf: [u8; 65536] = [0; 65536];
    let r = stream.read(&mut buf).await?;
    // println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];

    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("Received {}", escape_string(&msg));

    // let mut tosend: Vec<u8> = Vec::new();
    // let tosend_str = "/multistream/1.0.0\n";
    // let tosend_bytes = tosend_str.as_bytes();
    // tosend.push(tosend_bytes.len() as u8);
    // tosend.append(&mut Vec::from(tosend_bytes));
    // let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);

    send_string(&mut stream, "/multistream/1.0.0\n").await?;




    // let mut tosend: Vec<u8> = Vec::new();
    // let tosend_str = "/secio/1.0.0\n";
    // let tosend_bytes = tosend_str.as_bytes();
    // tosend.push(tosend_bytes.len() as u8);
    // tosend.append(&mut Vec::from(tosend_bytes));
    // let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);

    send_string(&mut stream, "/secio/1.0.0\n").await?;

    // let r = stream.read(&mut buf).await?;
    // // println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    // let received = &buf[0..r];
    // let mut reader = PBufReader::new(received);
    // let msg = reader.read_length_delimited()?.to_string()?;
    // println!("Received {}", escape_string(&msg));




    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];
    let mut reader = PBufReader::new(received);
    let msg = reader.read_length_delimited()?.to_string()?;
    println!("Received {}", escape_string(&msg));








    let data = recv_length_prefixed_binary(&mut stream).await?;
    let remote_propose = Propose::from_pb(&data)?;

    println!();
    println!("Propose");

    println!("    rand = {}", BinaryData(&remote_propose.rand));
    println!("    pubkey =");

    println!("        type = {:?}", remote_propose.pubkey.key_type);
    println!("        data = {}", BinaryData(&remote_propose.pubkey.data));

    // println!("    exchanges = {}", remote_propose.exchanges);
    // println!("    ciphers = {}", remote_propose.ciphers);
    // println!("    hashes = {}", remote_propose.hashes);

    println!("    exchanges");
    for item in remote_propose.exchanges.iter() {
        println!("        {}", item);
    }
    println!("    ciphers");
    for item in remote_propose.ciphers.iter() {
        println!("        {}", item);
    }
    println!("    hashes");
    for item in remote_propose.hashes.iter() {
        println!("        {}", item);
    }

    // let rsa_public_key = Rsa::public_key_from_der(&remote_propose.pubkey.data)?;
    // println!("got rsa_public_key");
    // println!("n = {}", BinaryData(&rsa_public_key.n().to_vec()));
    // println!("e = {}", rsa_public_key.e());


    std::fs::write("remote-public-key", &remote_propose.pubkey.data)?;


    // Send our proposal
    let local_public_key = PublicKey {
        key_type: KeyType::RSA,
        data: local_rsa_public_key_bytes,
        // data: remote_propose.pubkey.data.clone(),
    };
    let local_propose = make_propose(&mut rng, &local_public_key);
    send_length_prefixed_bytes(&mut stream, &local_propose.to_pb()).await?;


    // send_bytes(&mut stream, &received).await?;





    let r = stream.read(&mut buf).await?;
    println!("Received {} bytes: {}", r, BinaryData(&buf[..r]));
    let received = &buf[0..r];
    print_fields(received)?;


    // let cx = native_tls::TlsConnector::builder()
    //     .min_protocol_version(Some(native_tls::Protocol::Tlsv13))
    //     .max_protocol_version(Some(native_tls::Protocol::Tlsv13))
    //     .build()?;
    // let cx = tokio_tls::TlsConnector::from(cx);

    // let mut tls_stream = cx.connect("localhost", stream).await?;
    // println!("TLS Connection established");





    // let mut offset = 0;
    // let msg_len = match VarInt::read_from(&received, &mut offset) {
    //     Some(v) => v.to_usize(),
    //     None => return general_error("Cannot get message length"),
    // };
    // println!("msg_len = {}", msg_len);



    Ok(())
}
