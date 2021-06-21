// #![allow(unused_variables)]
// #![allow(dead_code)]
// #![allow(unused_mut)]
// #![allow(unused_assignments)]
// #![allow(unused_imports)]
// #![allow(unused_macros)]

use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
use super::io::{write_length_prefixed_data, read_length_prefixed_data, read_varint};

const MAX_LS_RESPONSE_SIZE: u64 = 65536;

pub enum SelectResponse {
    Accepted,
    Unsupported,
}

pub async fn multistream_handshake<T>(stream: &mut T) -> Result<(), std::io::Error>
    where T: AsyncRead + AsyncWrite + Unpin
{
    match multistream_select(stream, b"/multistream/1.0.0\n").await {
        Ok(SelectResponse::Accepted) => Ok(()),
        Ok(SelectResponse::Unsupported) => Err(std::io::ErrorKind::InvalidData.into()),
        Err(e) => Err(e),
    }
}

pub async fn multistream_select<T>(
    stream: &mut T,
    protocol: &[u8],
) -> Result<SelectResponse, std::io::Error>
    where T: AsyncRead + AsyncWrite + Unpin
{
    write_length_prefixed_data(stream, protocol).await?;
    stream.flush().await?;
    let data = read_length_prefixed_data(stream).await?;
    if data == protocol {
        Ok(SelectResponse::Accepted)
    }
    else if data == b"na\n" {
        Ok(SelectResponse::Unsupported)
    }
    else {
        Err(std::io::ErrorKind::InvalidData.into())
    }
}

pub async fn multistream_list<T>(
    stream: &mut T
) -> Result<Vec<String>, std::io::Error>
    where T: AsyncRead + AsyncWrite + Unpin
{
    write_length_prefixed_data(stream, b"ls\n").await?;
    stream.flush().await?;

    let response_len = read_varint(stream).await?;
    if response_len > MAX_LS_RESPONSE_SIZE {
        return Err(std::io::ErrorKind::InvalidData.into());
    }

    let mut protocols: Vec<String> = Vec::new();
    let mut body_stream = stream.take(response_len);
    loop {
        let protocol_bin = match read_length_prefixed_data(&mut body_stream).await {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                else {
                    return Err(e);
                }
            }
        };
        protocols.push(String::from_utf8_lossy(&protocol_bin).into());
    }

    Ok(protocols)
}
