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

use openssl::bn::BigNumContext;
use openssl::ec::*;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
// use openssl::ec::PointConversionForm;


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

struct Exchange {
    epubkey: Vec<u8>,
    signature: Vec<u8>,
}

impl Exchange {
    fn from_pb(raw_data: &[u8]) -> Result<Exchange, Box<dyn Error>> {
        let mut reader = PBufReader::new(&raw_data);

        let mut epubkey: Option<Vec<u8>> = None;
        let mut signature: Option<Vec<u8>> = None;

        while let Some(field) = reader.read_field()? {
            match field.field_number {
                1 => epubkey = Some(Vec::from(field.data.to_bytes()?)),
                2 => signature = Some(Vec::from(field.data.to_bytes()?)),
                _ => {
                }
            }
        }

        let epubkey: Vec<u8> = epubkey.ok_or_else(|| GeneralError::new(&format!("Missing field: epubkey")))?;
        let signature: Vec<u8> = signature.ok_or_else(|| GeneralError::new(&format!("Missing field: signature")))?;

        Ok(Exchange {
            epubkey,
            signature,
        })
    }

    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.epubkey);
        writer.write_bytes(2, &self.signature);
        writer.data
    }
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
    receive_exact(stream, msglen).await
}

async fn receive_exact(stream: &mut TcpStream, msglen: usize) -> Result<Vec<u8>, Box<dyn Error>> {
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


    // let exchanges: Vec<String> = vec![String::from("P-256"), String::from("P-384"), String::from("P-521")];
    // let ciphers: Vec<String> = vec![String::from("AES-256"), String::from("AES-128"), String::from("Blowfish")];
    // let hashes: Vec<String> = vec![String::from("SHA256"), String::from("SHA512")];


    let exchanges: Vec<String> = vec![String::from("P-256")];
    let ciphers: Vec<String> = vec![String::from("AES-256")];
    let hashes: Vec<String> = vec![String::from("SHA256")];

    Propose {
        rand: Vec::from(rand_bytes),
        pubkey: pubkey.clone(),
        exchanges,
        ciphers,
        hashes,
    }
}

const MAX_VARINT_BYTES: usize = 10;

async fn receive_varint_length_prefixed(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut length_bytes: Vec<u8> = Vec::new();
    loop {
        let mut single_buf: [u8; 1] = [0; 1];
        let r: usize = stream.read(&mut single_buf).await?;
        if r == 0 {
            return general_error("Premature end of stream while reading varint length");
        }
        let b = single_buf[0];
        // println!("b = 0x{:02x}", b);
        length_bytes.push(b);
        if length_bytes.len() > MAX_VARINT_BYTES {
            return general_error("Length varint is too long");
        }
        // if length_bytes.len() == 99 {
        //     break;
        // }
        if b & 0x80 == 0 {
            break;
        }
        // break;
    }
    // println!("length_bytes = {}", BinaryData(&length_bytes));
    let mut offset = 0;
    let length_varint = VarInt::read_from(&length_bytes, &mut offset).ok_or_else(|| GeneralError::new("Invalid varint"))?;
    let length = length_varint.to_usize();
    // println!("length = {}", length);


    Ok(receive_exact(stream, length).await?)
}

fn print_propose(propose: &Propose) {
    println!("    rand = {}", BinaryData(&propose.rand));
    println!("    pubkey =");
    println!("        type = {:?}", propose.pubkey.key_type);
    println!("        data = {}", BinaryData(&propose.pubkey.data));
    println!("    exchanges");
    for item in propose.exchanges.iter() {
        println!("        {}", item);
    }
    println!("    ciphers");
    for item in propose.ciphers.iter() {
        println!("        {}", item);
    }
    println!("    hashes");
    for item in propose.hashes.iter() {
        println!("        {}", item);
    }
}

pub async fn p2p_test(server_addr_str: &str) -> Result<(), Box<dyn Error>> {
    let mut rng = rand::thread_rng();

    // Generate out private key (our peer id can be derived from this)
    let local_rsa_private_key = Rsa::generate(4096)?;
    let local_rsa_public_key_bytes = local_rsa_private_key.public_key_to_der()?;

    // Open the connection
    let peer_addr: SocketAddr = match lookup_host(server_addr_str).await?.next() {
        Some(v) => v,
        None => return general_error(&format!("Cannot resolve host: {}", server_addr_str)),
    };

    println!("Before opening connection");
    let mut stream = TcpStream::connect(peer_addr).await?;
    println!("After opening connection");

    // Receive first message; should be "/multistream/1.0.0\n"
    let inmsg1_bytes = receive_varint_length_prefixed(&mut stream).await?;
    let inmsg1_str = String::from_utf8(inmsg1_bytes)?;
    println!("Received inmsg1: {}", escape_string(&inmsg1_str));

    // Tell the server we also want to use multistream
    send_string(&mut stream, "/multistream/1.0.0\n").await?;
    // Tell the server we want to use secio
    send_string(&mut stream, "/secio/1.0.0\n").await?;

    // Receive confirmation that the server is willing to use secio
    let inmsg2_bytes = receive_varint_length_prefixed(&mut stream).await?;
    let inmsg2_str = String::from_utf8(inmsg2_bytes)?;
    println!("Received inmsg2: {}", escape_string(&inmsg2_str));

    // Receive the server's proposal
    let remote_propose_bytes = recv_length_prefixed_binary(&mut stream).await?;
    let remote_propose = Propose::from_pb(&remote_propose_bytes)?;
    println!();
    println!("Propose");
    print_propose(&remote_propose);

    // std::fs::write("remote-public-key", &remote_propose.pubkey.data)?;
    //
    // let remote_public_key = Rsa::public_key_from_der()

    let remote_rsa_public_key = Rsa::public_key_from_der(&remote_propose.pubkey.data)?;
    println!("got remote_rsa_public_key");
    println!("n = {}", BinaryData(&remote_rsa_public_key.n().to_vec()));
    println!("e = {}", remote_rsa_public_key.e());


    // Send our proposal
    let local_public_key = PublicKey {
        key_type: KeyType::RSA,
        data: local_rsa_public_key_bytes,
    };
    let local_propose = make_propose(&mut rng, &local_public_key);
    let local_propose_bytes = local_propose.to_pb();
    send_length_prefixed_bytes(&mut stream, &local_propose_bytes).await?;
    println!("Sent our proposal");

    // Receive the server's key exchange
    let data = recv_length_prefixed_binary(&mut stream).await?;
    println!("Received remote exchange");
    let remote_exchange = Exchange::from_pb(&data)?;
    println!("    epubkey = {}", BinaryData(&remote_exchange.epubkey));
    println!("    signature = {}", BinaryData(&remote_exchange.signature));

    // get bytes from somewhere, i.e. this will not produce a valid key
    let public_key: Vec<u8> = vec![];

    // create an EcKey from the binary form of a EcPoint
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, &remote_exchange.epubkey, &mut ctx)?;
    let remote_eckey = EcKey::from_public_key(&group, &point);

    let mut remote_corpus: Vec<u8> = Vec::new();
    remote_corpus.append(&mut remote_propose_bytes.clone());
    remote_corpus.append(&mut local_propose_bytes.clone());
    remote_corpus.append(&mut remote_exchange.epubkey.clone());

    let remote_pkey = PKey::from_rsa(remote_rsa_public_key)?;
    let mut remote_verifier = Verifier::new(MessageDigest::sha256(), &remote_pkey)?;
    remote_verifier.update(&remote_corpus)?;
    let remote_verify_ok = remote_verifier.verify(&remote_exchange.signature)?;
    println!("remote_verify_ok = {}", remote_verify_ok);
    // let sig = EcdsaSig::from_der(&remote_exchange.signature)?;
    // println!("Created EcdsaSig");

    let local_eckey = EcKey::generate(&group)?;
    let local_eckey_public_point = local_eckey.public_key();
    let local_eckey_public_bytes = local_eckey_public_point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;


    let mut local_corpus: Vec<u8> = Vec::new();
    local_corpus.append(&mut local_propose_bytes.clone());
    local_corpus.append(&mut remote_propose_bytes.clone());
    local_corpus.append(&mut local_eckey_public_bytes.clone());

    let local_pkey = PKey::from_rsa(local_rsa_private_key.clone())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &local_pkey)?;
    signer.update(&local_corpus)?;
    let signature = signer.sign_to_vec()?;

    let mut local_verifier = Verifier::new(MessageDigest::sha256(), &local_pkey)?;
    local_verifier.update(&local_corpus)?;
    let local_verify_ok = local_verifier.verify(&signature)?;
    println!("local_verify_ok = {}", local_verify_ok);

    let local_exchange = Exchange {
        epubkey: local_eckey_public_bytes,
        signature: signature,
    };
    let local_exchange_bytes = local_exchange.to_pb();
    send_length_prefixed_bytes(&mut stream, &local_exchange_bytes).await?;

    // let mut newbuf: [u8; 16384] = [0; 16384];
    // let r = stream.read(&mut newbuf).await?;
    // println!("r = {}", r);
    // let received = &newbuf[..r];

    let next_data = recv_length_prefixed_binary(&mut stream).await?;
    println!("Received: {}", BinaryData(&next_data));

    Ok(())
}
