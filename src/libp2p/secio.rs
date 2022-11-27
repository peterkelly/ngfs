
#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::fmt;
use std::error::Error;
use tokio::net::{lookup_host};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
// use native_tls;
// use tokio_tls;
use openssl::rsa::Rsa;
use rand::prelude::Rng;
use crate::error;
use crate::util::util::{BinaryData, escape_string};
use crate::formats::protobuf::protobuf::{PBufReader, PBufWriter, VarInt};
use crate::crypto::hmac::{HmacSha256, SHA256_DIGEST_SIZE};
use crate::formats::protobuf::varint;

use openssl::bn::{BigNum, BigNumRef, BigNumContext};
use openssl::ec::*;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::sign::{Signer, Verifier};
use openssl::sha::Sha256;
use openssl::symm::{Crypter, Cipher, Mode};
// use openssl::ec::PointConversionForm;


enum Preference {
    Remote,
    Local,
}

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

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("key_type", &self.key_type)
            .field("data", &BinaryData(&self.data))
            .finish()
    }
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
                    let key_type_int = field.data.to_uint64()?;
                    key_type = match key_type_int {
                        0 => Some(KeyType::RSA),
                        1 => Some(KeyType::Ed25519),
                        2 => Some(KeyType::Secp256k1),
                        3 => Some(KeyType::ECDSA),
                        _ => {
                            return Err(error!("Unknown key type: {}", key_type_int));
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

        let key_type: KeyType = key_type.ok_or_else(|| error!("Missing field: key_type"))?;
        let data: Vec<u8> = data.ok_or_else(|| error!("Missing field: data"))?;

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
    pubkey: Vec<u8>,
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

        let rand: Vec<u8> = rand.ok_or_else(|| error!("Missing field: rand"))?;
        let pubkey: Vec<u8> = pubkey.ok_or_else(|| error!("Missing field: pubkey"))?;
        let exchanges: String = exchanges.ok_or_else(|| error!("Missing field: exchanges"))?;
        let ciphers: String = ciphers.ok_or_else(|| error!("Missing field: ciphers"))?;
        let hashes: String = hashes.ok_or_else(|| error!("Missing field: hashes"))?;

        Ok(Propose {
            rand,
            pubkey: pubkey,
            exchanges: exchanges.split(',').map(|s| String::from(s)).collect(),
            ciphers: ciphers.split(',').map(|s| String::from(s)).collect(),
            hashes: hashes.split(',').map(|s| String::from(s)).collect(),
        })
    }

    pub fn to_pb(&self) -> Vec<u8> {
        let mut writer = PBufWriter::new();
        writer.write_bytes(1, &self.rand);
        writer.write_bytes(2, &self.pubkey);
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

        let epubkey: Vec<u8> = epubkey.ok_or_else(|| error!("Missing field: epubkey"))?;
        let signature: Vec<u8> = signature.ok_or_else(|| error!("Missing field: signature"))?;

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
    varint::encode_usize(tosend_bytes.len(), &mut tosend);
    tosend.append(&mut Vec::from(tosend_bytes));
    let w = stream.write(&tosend).await?;
    // println!("Sent {} bytes", w);
    if w != tosend.len() {
        return Err(error!("Only sent {} bytes of {}", w, tosend.len()));
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
        return Err(error!("Only sent {} bytes of {}", w, tosend.len()));
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
        return Err(error!("Insufficient data while reading message length"));
    }
    println!("length_buf = {:?}", length_buf);
    let msglen = u32::from_be_bytes(length_buf) as usize;
    println!("msglen = {}", msglen);
    if msglen >= 0x800000 {
        return Err(error!("Message length {} exceeds allowed length", msglen));
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
        return Err(error!("Insufficient data while reading message body; got {} bytes, expected {}", total_read, msglen));
    }


    // let r = stream.read(&mut body).await?;
    // if r != msglen {
    //     return Err(error!("Insufficient data while reading message body; got {} bytes, expected {}", r, msglen));
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
        pubkey: pubkey.to_pb(),
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
            return Err(error!("Premature end of stream while reading varint length"));
        }
        let b = single_buf[0];
        // println!("b = 0x{:02x}", b);
        length_bytes.push(b);
        if length_bytes.len() > MAX_VARINT_BYTES {
            return Err(error!("Length varint is too long"));
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
    let length_varint = VarInt::read_from(&length_bytes, &mut offset).ok_or_else(|| error!("Invalid varint"))?;
    let length = length_varint.to_usize()?;
    // println!("length = {}", length);


    Ok(receive_exact(stream, length).await?)
}

fn print_propose(propose: &Propose, pubkey: &PublicKey) {
    println!("    rand = {}", BinaryData(&propose.rand));
    println!("    pubkey =");
    println!("        type = {:?}", pubkey.key_type);
    println!("        data = {}", BinaryData(&pubkey.data));
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
        None => return Err(error!("Cannot resolve host: {}", server_addr_str)),
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
    println!("remote_propose_bytes = {}", BinaryData(&remote_propose_bytes));
    let remote_propose = Propose::from_pb(&remote_propose_bytes)?;
    let remote_propose_pubkey = PublicKey::from_pb(&remote_propose.pubkey)?;
    println!();
    println!("Propose");
    print_propose(&remote_propose, &remote_propose_pubkey);

    // std::fs::write("remote-public-key", &remote_propose.pubkey.data)?;
    //
    // let remote_public_key = Rsa::public_key_from_der()


    // Send our proposal
    let local_public_key = PublicKey {
        key_type: KeyType::RSA,
        data: local_rsa_public_key_bytes,
    };
    let local_propose = make_propose(&mut rng, &local_public_key);
    let local_propose_bytes = local_propose.to_pb();
    println!("local_propose_bytes = {}", BinaryData(&local_propose_bytes));
    send_length_prefixed_bytes(&mut stream, &local_propose_bytes).await?;
    println!("Sent our proposal with nonce {}", BinaryData(&local_propose.rand));

    // oh1 := sha256(concat(remotePeerPubKeyBytes, myNonce))
    let mut oh1_hasher = Sha256::new();
    // println!("oh1 part1 = {}", BinaryData(&remote_propose.pubkey));
    // println!("oh1 part2 = {}", BinaryData(&local_propose.rand));
    // let mut oh1_both: Vec<u8> = Vec::new();
    // oh1_both.append(&mut Vec::from(&remote_propose.pubkey[..]));
    // oh1_both.append(&mut Vec::from(&local_propose.rand[..]));
    // println!("oh1 both = {}", BinaryData(&oh1_both));
    oh1_hasher.update(&remote_propose.pubkey);
    oh1_hasher.update(&local_propose.rand);

    // oh1_hasher.update(&oh1_both);
    let oh1_raw = oh1_hasher.finish();
    let mut oh1: [u8; 34] = [0; 34];
    oh1[0] = 0x12;
    oh1[1] = 0x20;
    oh1[2..34].copy_from_slice(&oh1_raw);

    // oh2 := sha256(concat(myPubKeyBytes, remotePeerNonce))
    let mut oh2_hasher = Sha256::new();
    // println!("oh2 part1 = {}", BinaryData(&local_propose.pubkey));
    // println!("oh2 part2 = {}", BinaryData(&remote_propose.rand));
    // let mut oh2_both: Vec<u8> = Vec::new();
    // oh2_both.append(&mut Vec::from(&local_propose.pubkey[..]));
    // oh2_both.append(&mut Vec::from(&remote_propose.rand[..]));
    // println!("oh2 both = {}", BinaryData(&oh2_both));
    oh2_hasher.update(&local_propose.pubkey);
    oh2_hasher.update(&remote_propose.rand);
    // oh2_hasher.update(&oh2_both);
    let oh2_raw = oh2_hasher.finish();

    let mut oh2: [u8; 34] = [0; 34];
    oh2[0] = 0x12;
    oh2[1] = 0x20;
    oh2[2..34].copy_from_slice(&oh2_raw);


    println!("oh1 = {}", BinaryData(&oh1));
    println!("oh2 = {}", BinaryData(&oh2));

    let preference: Preference = if oh1_raw == oh2_raw {
        return Err(error!("Talking to self"));
    }
    else if oh1_raw < oh2_raw {
        Preference::Remote
    }
    else {
        Preference::Local
    };

    // Receive the server's key exchange
    let data = recv_length_prefixed_binary(&mut stream).await?;
    // println!("Received remote exchange");
    let remote_exchange = Exchange::from_pb(&data)?;
    // println!("    epubkey = {}", BinaryData(&remote_exchange.epubkey));
    // println!("    signature = {}", BinaryData(&remote_exchange.signature));

    // get bytes from somewhere, i.e. this will not produce a valid key
    let public_key: Vec<u8> = vec![];

    // create an EcKey from the binary form of a EcPoint
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut ctx = BigNumContext::new()?;
    println!("remote_exchange.epubkey = {}", BinaryData(&remote_exchange.epubkey));
    let point = EcPoint::from_bytes(&group, &remote_exchange.epubkey, &mut ctx)?;
    let remote_eckey = EcKey::from_public_key(&group, &point)?;

    // let mut remote_corpus: Vec<u8> = Vec::new();
    // remote_corpus.append(&mut remote_propose_bytes.clone());
    // remote_corpus.append(&mut local_propose_bytes.clone());
    // remote_corpus.append(&mut remote_exchange.epubkey.clone());

    // Verify remote exchange message
    let remote_pkey_rsa = Rsa::public_key_from_der(&remote_propose_pubkey.data)?;
    let remote_pkey = PKey::from_rsa(remote_pkey_rsa)?;
    let mut remote_verifier = Verifier::new(MessageDigest::sha256(), &remote_pkey)?;
    remote_verifier.update(&remote_propose_bytes)?;
    remote_verifier.update(&local_propose_bytes)?;
    remote_verifier.update(&remote_exchange.epubkey)?;
    if !remote_verifier.verify(&remote_exchange.signature)? {
        return Err(error!("Invalid signature for remote exchange message"));
    }


    // Send out local exchange message

    let local_eckey = EcKey::generate(&group)?;
    let local_eckey_public_point = local_eckey.public_key();
    let local_eckey_public_bytes = local_eckey_public_point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;

    let mut local_x: BigNum = BigNum::new()?;
    let mut local_y: BigNum = BigNum::new()?;
    local_eckey.public_key().affine_coordinates_gfp(&group, &mut local_x, &mut local_y, &mut ctx)?;
    println!("local_x = {}", BinaryData(&local_x.to_vec()));
    println!("local_y = {}", BinaryData(&local_y.to_vec()));


    let local_pkey = PKey::from_rsa(local_rsa_private_key.clone())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &local_pkey)?;
    signer.update(&local_propose_bytes)?;
    signer.update(&remote_propose_bytes)?;
    signer.update(&local_eckey_public_bytes)?;
    let signature = signer.sign_to_vec()?;

    let local_exchange = Exchange {
        epubkey: local_eckey_public_bytes,
        signature: signature,
    };
    let local_exchange_bytes = local_exchange.to_pb();
    send_length_prefixed_bytes(&mut stream, &local_exchange_bytes).await?;









    let mut shared_secret_point = EcPoint::new(&group)?;
    let mut remote_x: BigNum = BigNum::new()?;
    let mut remote_y: BigNum = BigNum::new()?;
    remote_eckey.public_key().affine_coordinates_gfp(&group, &mut remote_x, &mut remote_y, &mut ctx)?;

    println!("remote_x = {}", BinaryData(&remote_x.to_vec()));
    println!("remote_y = {}", BinaryData(&remote_y.to_vec()));


    // println!("x_prime = {}", x_prime.to_dec_str()?);
    // println!("y_prime = {}", y_prime.to_dec_str()?);
    // println!("x_bin   = {}", x_bin.to_dec_str()?);
    // println!("y_bin   = {}", y_bin.to_dec_str()?);






    shared_secret_point.mul(&group, &remote_eckey.public_key(), &local_eckey.private_key(), &mut ctx)?;
    let mut shared_secret_x: BigNum = BigNum::new()?;
    let mut shared_secret_y: BigNum = BigNum::new()?;
    shared_secret_point.affine_coordinates_gfp(&group, &mut shared_secret_x, &mut shared_secret_y, &mut ctx)?;

    // let local_eckey_public_bytes = local_eckey_public_point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    let shared_secret_bytes = shared_secret_x.to_vec();

    // let shared_secret_bytes = shared_secret_point.to_bytes(&group, PointConversionForm::UNCOMPRESSED, &mut ctx)?;
    println!("shared_secret_bytes.len() = {}", shared_secret_bytes.len());
    println!("shared_secret_bytes = {}", BinaryData(&shared_secret_bytes));

    let cipher_key_size = 32; // for AES-256
    let iv_size = 16; // for AES-256
    let mac_key_size = 20; // in all cases, as per spec
    let output_size = 2 * (cipher_key_size + iv_size + mac_key_size);
    // println!("need output_size of {}", output_size);

    let mut hmac = HmacSha256::new(&shared_secret_bytes);
    hmac.update("key expansion".as_bytes());
    let mut a: [u8; 32] = hmac.finish();
    // let mut a: Vec<u8> = Vec::from("key expansion".as_bytes());
    // let mut count = 0;
    let mut output: Vec<u8> = Vec::new();
    while output.len() < output_size {
        // println!("output.len() = {}, output_size = {}", output.len(), output_size);
        // compute digest b by feeding a and the seed value into the HMAC:
        // b := hmac_digest(concat(a, "key expansion"))
        // let mut b_input: Vec<u8> = Vec::new();
        // b_input.append(&mut Vec::from(&a[..]));
        // b_input.append(&mut Vec::from("key expansion".as_bytes()));
        // hmac.update(&b_input);
        hmac.update(&a[..]);
        hmac.update("key expansion".as_bytes());
        let b: [u8; 32] = hmac.finish();
        output.append(&mut Vec::from(&b[..]));
        // count += 1;
        // if count > 10 {
        //     break;
        // }
        hmac.update(&a[..]);
        a = hmac.finish();
    }
    // println!("finished with output.len() = {}", output.len());
    output.resize_with(output_size, Default::default);
    // println!("finished with output.len() = {}", output.len());
    println!("output = {}", BinaryData(&output));

    // println!("{}", offset);
    let mut output_offset = 0;

    let k1_iv: Vec<u8> = Vec::from(&output[output_offset..output_offset + iv_size]);
    output_offset += iv_size;

    let k1_cipher_key: Vec<u8> = Vec::from(&output[output_offset..output_offset + cipher_key_size]);
    output_offset += cipher_key_size;

    let k1_mac_key: Vec<u8> = Vec::from(&output[output_offset..output_offset + mac_key_size]);
    output_offset += mac_key_size;

    let k2_iv: Vec<u8> = Vec::from(&output[output_offset..output_offset + iv_size]);
    output_offset += iv_size;

    let k2_cipher_key: Vec<u8> = Vec::from(&output[output_offset..output_offset + cipher_key_size]);
    output_offset += cipher_key_size;

    let k2_mac_key: Vec<u8> = Vec::from(&output[output_offset..output_offset + mac_key_size]);
    output_offset += mac_key_size;
    assert!(output_offset == output_size);

    let k1 = AESKey { iv: k1_iv, cipher_key: k1_cipher_key, mac_key: k1_mac_key };
    let k2 = AESKey { iv: k2_iv, cipher_key: k2_cipher_key, mac_key: k2_mac_key };


    // match preference {
    //     Preference::Remote => {
    //         std::mem::swap(&mut k1, &mut k2);
    //     }
    //     Preference::Local => {
    //     }
    // };
    let (local_keys, remote_keys) = match preference {
        Preference::Remote => {
            (k2, k1)
        }
        Preference::Local => {
            (k1, k2)
        }
    };


    println!("local_keys.iv = {}", &BinaryData(&local_keys.iv));
    println!("local_keys.cipher_key = {}", &BinaryData(&local_keys.cipher_key));
    println!("local_keys.mac_key = {}", &BinaryData(&local_keys.mac_key));

    println!("remote_keys.iv = {}", &BinaryData(&remote_keys.iv));
    println!("remote_keys.cipher_key = {}", &BinaryData(&remote_keys.cipher_key));
    println!("remote_keys.mac_key = {}", &BinaryData(&remote_keys.mac_key));

    assert!(remote_keys.iv.len() == iv_size);
    assert!(remote_keys.cipher_key.len() == cipher_key_size);
    assert!(remote_keys.mac_key.len() == mac_key_size);

    assert!(local_keys.iv.len() == iv_size);
    assert!(local_keys.cipher_key.len() == cipher_key_size);
    assert!(local_keys.mac_key.len() == mac_key_size);


    let msg_parts = recv_length_prefixed_binary(&mut stream).await?;
    println!("Received: {}", BinaryData(&msg_parts));
    if msg_parts.len() < SHA256_DIGEST_SIZE {
        return Err(error!("Encrypted data is smaller than digest size"));
    }
    let message_enc = &msg_parts[..msg_parts.len() - SHA256_DIGEST_SIZE];
    let message_mac = &msg_parts[msg_parts.len() - SHA256_DIGEST_SIZE..];

    println!("message_enc = ({} bytes) {}", message_enc.len(), BinaryData(message_enc));
    println!("message_mac = ({} bytes) {}", message_mac.len(), BinaryData(message_mac));


    println!("Trying decrption with remote_keys:");
    test_decryption(message_enc, message_mac, &remote_keys)?;

    // println!("Trying decrption with local_keys:");
    // test_decryption(message_enc, message_mac, &local_keys)?;

    // let hmac_signer = HmacSha256::new(&k1.mac_key);

    Ok(())
}

fn test_decryption(message_enc: &[u8], message_mac: &[u8], keys: &AESKey) -> Result<(), Box<dyn Error>> {
    let cipher: Cipher = Cipher::aes_256_ctr();
    let block_size = cipher.block_size();
    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &keys.cipher_key, Some(&keys.iv))?;
    let mut plaintext: Vec<u8> = vec![0; message_enc.len() + block_size];
    let mut decrpyted_count = decrypter.update(message_enc, &mut plaintext)?;
    println!("    decrpyted_count = {}", decrpyted_count);
    println!("    plaintext.len() = {}", plaintext.len());
    plaintext.truncate(decrpyted_count);
    println!("    plaintext = {}", BinaryData(&plaintext));
    // println!("expected  = {}", BinaryData(&local_propose.rand));

    let mut message_hmac = HmacSha256::new(&keys.mac_key);
    message_hmac.update(&message_enc);
    let computed_mac = message_hmac.finish();
    println!("    message_mac  = ({} bytes) {}", message_mac.len(), BinaryData(message_mac));
    println!("    computed_mac = ({} bytes) {}", computed_mac.len(), BinaryData(&computed_mac));

    if message_mac != computed_mac {
        return Err(error!("MAC mismatch"));
    }

    Ok(())
}

struct AESKey {
    iv: Vec<u8>,
    cipher_key: Vec<u8>,
    mac_key: Vec<u8>,
}
