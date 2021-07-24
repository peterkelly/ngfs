// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use std::io;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use crate::protobuf::VarInt;

pub async fn read_opt_varint<T>(reader: &mut T) -> Result<Option<u64>, io::Error>
    where T : AsyncRead + Unpin
{
    let mut parts: Vec<u8> = Vec::new();
    loop {
        let b = match reader.read_u8().await {
            Ok(b) => b,
            Err(e) => {
                if parts.len() == 0 && e.kind() == io::ErrorKind::UnexpectedEof {
                    return Ok(None);
                }
                else {
                    return Err(e);
                }
            }
        };

        parts.push(b);
        if b & 0x80 == 0 {
            break;
        }
    }

    Ok(Some(VarInt(&parts).to_u64()))
}

pub async fn read_varint<T>(reader: &mut T) -> Result<u64, io::Error>
    where T : AsyncRead + Unpin
{
    read_opt_varint(reader).await?
        .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

pub async fn write_varint<T>(writer: &mut T, value: u64) -> Result<(), io::Error>
    where T : AsyncWrite + Unpin
{
    let value_bytes = VarInt::encode_u64(value);
    writer.write_all(&value_bytes).await?;
    Ok(())
}

pub async fn read_opt_length_prefixed_data<T>(reader: &mut T) -> Result<Option<Vec<u8>>, io::Error>
    where T : AsyncRead + Unpin
{
    let expected_len = match read_opt_varint(reader).await? {
        Some(v) => v as usize,
        None => return Ok(None),
    };

    let mut reader = reader.take(expected_len as u64);
    let mut incoming_data: Vec<u8> = Vec::new();
    while incoming_data.len() < expected_len {
        let mut buf: [u8; 1024] = [0; 1024];
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(r) => incoming_data.extend_from_slice(&buf[0..r]),
        };
    }
    Ok(Some(incoming_data))
}

pub async fn read_length_prefixed_data<T>(reader: &mut T) -> Result<Vec<u8>, io::Error>
    where T : AsyncRead + Unpin
{
    read_opt_length_prefixed_data(reader).await?
        .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

pub async fn write_length_prefixed_data<T>(writer: &mut T, data: &[u8]) -> Result<(), io::Error>
    where T : AsyncWrite + Unpin
{
    let len_bytes = VarInt::encode_usize(data.len());
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    Ok(())
}
