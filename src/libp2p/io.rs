// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::protobuf::VarInt;

pub async fn read_varint<T>(reader: &mut T) -> Result<u64, io::Error>
    where T : AsyncRead + Unpin
{
    let mut buf: [u8; 1] = [0; 1];
    let mut value: u64 = 0;
    loop {
        match reader.read(&mut buf).await {
            Err(e) => return Err(e),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => {
                let b = buf[0];
                value = (value << 7) | ((b & 0x7f) as u64);
                if b & 0x80 == 0 {
                    break;
                }
            }
        };
    }
    Ok(value)
}

pub async fn read_length_prefixed_data<T>(reader: &mut T) -> Result<Vec<u8>, io::Error>
    where T : AsyncRead + Unpin
{
    let expected_len = read_varint(reader).await? as usize;
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => {
                incoming_data.push(buf[0]);
                got_len += 1;
            }
        };
    }
    Ok(incoming_data)
}

pub async fn write_length_prefixed_data<T>(writer: &mut T, data: &[u8]) -> Result<(), io::Error>
    where T : AsyncWrite + Unpin
{
    let len_bytes = VarInt::encode_usize(data.len());
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    Ok(())
}
