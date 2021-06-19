// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

use std::error::Error;
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use torrent::util::{escape_string, vec_with_len, DebugHexDump};
use torrent::error;
use torrent::protobuf::VarInt;
use torrent::libp2p::tls::generate_certificate;
use torrent::tls::protocol::client::{
    ServerAuth,
    ClientAuth,
    ClientConfig,
    EstablishedConnection,
    establish_connection,
};

async fn read_multistream_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<usize, Box<dyn Error>> {
    let mut buf: [u8; 1] = [0; 1];
    let mut value: usize = 0;
    loop {
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(error!("Unexpected end of input")),
            Ok(_) => {
                let b = buf[0];
                value = (value << 7) | ((b & 0x7f) as usize);
                if b & 0x80 == 0 {
                    break;
                }
            }
        };
    }
    Ok(value)
}

async fn read_multistream_data(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Box<dyn Error>> {
    let expected_len = read_multistream_varint(reader).await?;
    // println!("expected_len = {}", expected_len);
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(error!("Unexpected end of input")),
            Ok(_) => {
                incoming_data.push(buf[0]);
                got_len += 1;
            }
        };
    }
    Ok(incoming_data)
}

async fn write_multistream_data(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Box<dyn Error>> {
    let len_bytes = VarInt::encode_usize(data.len());
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_multistream_data_client(
    conn: &mut EstablishedConnection,
    data: &[u8],
) -> Result<(), Box<dyn Error>>
{
    let len_bytes = VarInt::encode_usize(data.len());
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&len_bytes);
    buf.extend_from_slice(&data);
    conn.write_all(&buf).await?;
    conn.flush().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let mut rng = rand::rngs::OsRng {};
    let dalek_keypair: ed25519_dalek::Keypair = ed25519_dalek::Keypair::generate(&mut rng);

    let client_key = openssl::rsa::Rsa::generate(2048)?.private_key_to_der()?;
    let rsa_key_pair = ring::signature::RsaKeyPair::from_der(&client_key)?;
    let certificate = generate_certificate(&rsa_key_pair, &dalek_keypair)?;

    println!("Generated certificate");

    let config = ClientConfig {
        client_auth: ClientAuth::Certificate {
            cert: certificate,
            key: client_key,
        },
        server_auth: ServerAuth::SelfSigned,
        server_name: None,
    };

    let mut socket = TcpStream::connect("localhost:4001").await?;


    write_multistream_data(&mut socket, b"/multistream/1.0.0\n").await?;
    write_multistream_data(&mut socket, b"/tls/1.0.0\n").await?;

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    println!("Before establish_connection()");
    let mut conn = establish_connection(socket, config).await?;
    println!("After establish_connection()");

    let mut buf = vec_with_len(65536);
    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    write_multistream_data_client(&mut conn, b"/multistream/1.0.0\n").await?;
    // write_multistream_data_client(&mut conn, b"ls\n").await?;

    write_multistream_data_client(&mut conn, b"/mplex/6.7.0\n").await?;

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    // let data = read_multistream_data(&mut socket).await?;
    // println!("{:#?}", &DebugHexDump(&data));
    // println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    Ok(())
}
