use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::formats::protobuf::varint;
use crate::formats::protobuf::varint::{U64Decoder, DecoderResult};


#[doc(hidden)]
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct ReadOptVarInt<'a, T> where T : AsyncRead + Unpin {
    reader: &'a mut T,
    decoder: U64Decoder,
    num_bytes: usize,
}

impl<'a, T> Future for ReadOptVarInt<'a, T>
    where T : AsyncRead + Unpin
{
    type Output = Result<Option<u64>, io::Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let iself = Pin::into_inner(self);

        loop {
            let mut raw_buf: [u8; 1] = [0; 1];
            let mut buf = ReadBuf::new(&mut raw_buf);
            match Pin::new(&mut iself.reader).poll_read(cx, &mut buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    if iself.num_bytes == 0 && e.kind() == io::ErrorKind::UnexpectedEof {
                        return Poll::Ready(Ok(None));
                    }
                    else {
                        return Poll::Ready(Err(e));
                    }
                }
                Poll::Ready(Ok(())) => {
                    if buf.filled().is_empty() {
                        if iself.num_bytes == 0 {
                            return Poll::Ready(Ok(None));
                        }
                        else {
                            return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                        }
                    }
                    iself.num_bytes += 1;
                    match iself.decoder.input(raw_buf[0]) {
                        DecoderResult::Finished(value) => {
                            return Poll::Ready(Ok(Some(value)));
                        }
                        DecoderResult::Overflow => {
                            return Poll::Ready(Err(io::ErrorKind::InvalidData.into()));
                        }
                        DecoderResult::Pending => {
                            // continue with another loop iteration, reading the next byte
                        }
                    }
                }
            }
        }
    }
}

pub fn read_opt_varint<T>(reader: &mut T) -> ReadOptVarInt<T>
    where T : AsyncRead + Unpin
{
    ReadOptVarInt {
        reader,
        decoder: U64Decoder::new(),
        num_bytes: 0,
    }
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
    let mut value_bytes: Vec<u8> = Vec::new();
    varint::encode_u64(value, &mut value_bytes);
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
            Err(e) => return Err(e),
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
    let mut len_bytes: Vec<u8> = Vec::new();
    varint::encode_usize(data.len(), &mut len_bytes);
    writer.write_all(&len_bytes).await?;
    writer.write_all(data).await?;
    Ok(())
}
