#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use bytes::{BytesMut, Buf};
use super::super::types::record::{
    Message,
    ContentType,
    TLSOwnedPlaintext,
    TLSPlaintext,
    TLSOutputPlaintext,
    TLSPlaintextError,
    TLS_RECORD_SIZE,
};
use super::super::types::handshake::{
    Handshake,
};
use super::super::super::util::{vec_with_len};
use super::super::error::TLSError;
use super::super::helpers::{
    EncryptionKey,
    Ciphers,
    TrafficSecrets,
    encrypt_traffic,
    decrypt_message,
};
use super::super::super::error;

pub struct AEncryption {
    pub traffic_secrets: TrafficSecrets,
    pub ciphers: Ciphers,
}

pub struct ReceiveRecord<'a> {
    reader: &'a mut Box<dyn AsyncReadWrite>,
    incoming_data: Vec<u8>,
}

impl<'a> ReceiveRecord<'a> {
    pub fn new(reader: &'a mut Box<dyn AsyncReadWrite>) -> ReceiveRecord<'a> {
        ReceiveRecord {
            reader: reader,
            incoming_data: Vec::new(),
        }
    }
}

impl<'a> Future for ReceiveRecord<'a> {
    type Output = Result<TLSOwnedPlaintext, Box<dyn Error>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut want: usize = 5;
        if self.incoming_data.len() >= 5 {
            let content_type = ContentType::from_raw(self.incoming_data[0]);

            let mut legacy_record_version_bytes: [u8; 2] = Default::default();
            legacy_record_version_bytes.copy_from_slice(&self.incoming_data[1..3]);
            let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);


            let mut length_bytes: [u8; 2] = Default::default();
            length_bytes.copy_from_slice(&self.incoming_data[3..5]);
            let length = u16::from_be_bytes(length_bytes) as usize;

            if length > TLS_RECORD_SIZE {
                return Poll::Ready(Err(TLSPlaintextError::InvalidLength.into()));
            }


            if self.incoming_data.len() >= 5 + length {
                println!("ReceiveRecord: Parsing fragment of len {}; content_type = {:?}",
                         length, content_type);
                let mut header: [u8; 5] = [
                    self.incoming_data[0],
                    self.incoming_data[1],
                    self.incoming_data[2],
                    self.incoming_data[3],
                    self.incoming_data[4],
                ];

                let mut fragment: Vec<u8> = Vec::new();
                fragment.extend_from_slice(&self.incoming_data[5..]);

                let mut raw: Vec<u8> = Vec::new();
                raw.extend_from_slice(&self.incoming_data);

                println!("ReceiveRecord: raw.len() = {}", raw.len());
                let record = TLSOwnedPlaintext {
                    content_type,
                    legacy_record_version,
                    header: header,
                    fragment: fragment,
                    raw: raw,
                };
                return Poll::Ready(Ok(record));
            }
            want = 5 + length;
        }

        let amt = want - self.incoming_data.len();
        let mut recv_data = vec_with_len(amt);
        let mut recv_buf = ReadBuf::new(&mut recv_data);
        let old_filled = recv_buf.filled().len();

        match AsyncRead::poll_read(Pin::new(&mut self.reader), cx, &mut recv_buf) {
            Poll::Ready(Err(e)) => {
                // println!("ReceiveRecord::poll(): inner returned error");
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready(Ok(())) => {
                // println!("ReceiveRecord::poll(): inner is ready");
                let new_filled = recv_buf.filled().len();
                // println!("data = {}", &BinaryData(recv_buf.filled()));
                let extra = new_filled - old_filled;
                // TODO: if extra is 0, either we have unexpected end of data or the connection
                // has been closed. RecordReceiver should actually return Option<Record> so that
                // it can use None to indicate there are no more records.
                // println!("# of bytes read = {}", extra);
                // self.ok_done()
                self.incoming_data.extend_from_slice(recv_buf.filled());

                // println!("want = {}, have = {}", want, self.incoming_data.len());
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                println!("ReceiveRecord::poll(): inner is not ready");
                Poll::Pending
            }
        }
        // let x: () = self.reader.read(&mut self.buf);
        // unimplemented!()
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub fn encrypt_record(
    to_send: &mut BytesMut,
    data_ref: &[u8],
    content_type: ContentType,
    traffic_secret: &EncryptionKey,
    client_sequence_no: u64,
    transcript: Option<&mut Vec<u8>>,
) -> Result<(), TLSError> {
    let mut data = data_ref.to_vec();

    match transcript {
        Some(transcript) => transcript.extend_from_slice(&data),
        None => (),
    }
    data.push(content_type.to_raw());
    encrypt_traffic(
        traffic_secret,
        client_sequence_no,
        &mut data)?;

    let output_record = TLSOutputPlaintext {
        content_type: ContentType::ApplicationData,
        legacy_record_version: 0x0303,
        fragment: &data,
    };
    output_record.encode(to_send);
    Ok(())
}

////////////////////////////////////////////////////////////////////////////////////////////////////

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin {}

pub struct EncryptedStream {
    pub inner: Box<dyn AsyncReadWrite>,
    pub client_sequence_no: u64,
    pub server_sequence_no: u64,
    pub encryption: AEncryption,
}

impl EncryptedStream {
    pub fn new(inner: Box<dyn AsyncReadWrite>, encryption: AEncryption) -> Self {
        EncryptedStream {
            inner: inner,
            client_sequence_no: 0,
            server_sequence_no: 0,
            encryption: encryption
        }
    }

    // formerly encode EncryptedToSend
    pub async fn send_direct(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        self.inner.write_all(data).await
    }

    // formerly encode UnencToSend
    pub async fn encrypt_and_send(
        &mut self,
        data: &[u8],
        content_type: ContentType,
    ) -> Result<(), Box<dyn Error>> {
        // unimplemented!()
        let mut dst = BytesMut::new();
        encrypt_record(
            &mut dst,
            &data,
            content_type,
            &self.encryption.traffic_secrets.client,
            self.client_sequence_no,
            None,
        )?;
        self.client_sequence_no += 1;
        self.send_direct(&dst).await?;
        Ok(())
    }

    // TODO: Allow receive_record to return None
    pub fn receive_record<'a>(&'a mut self) -> ReceiveRecord<'a> {
        ReceiveRecord::new(&mut self.inner)
    }

    pub async fn receive_record_ignore_cc(
        &mut self,
    ) -> Option<Result<TLSOwnedPlaintext, Box<dyn Error>>> {
        loop {
            match self.receive_record().await {
                Ok(record) => {
                    if record.content_type != ContentType::ChangeCipherSpec {
                        return Some(Ok(record));
                    }
                }
                Err(e) => {
                    return Some(Err(e));
                },
            }
        }
    }

    pub async fn receive_message(
        &mut self,
        transcript: Option<&mut Vec<u8>>,
    ) -> Result<Message, Box<dyn Error>> {
        let plaintext = match self.receive_record_ignore_cc().await {
            Some(Ok(v)) => v,
            Some(Err(e)) => return Err(e),
            None => return Err(error!("No more messages")),
        };
        println!("receive_message_framed: plaintext.raw.len() = {}, server_sequence_no =  {}",
            plaintext.raw.len(), self.server_sequence_no);
        // TODO: Support records containing multiple handshake messages
        // TODO: Cater for alerts
        let (message, message_raw) = decrypt_message(
            self.server_sequence_no,
            &self.encryption.traffic_secrets.server,
            &plaintext.raw)?;
        println!("receive_message_framed: after decryption");
        self.server_sequence_no += 1;
        match transcript {
            Some(transcript) => transcript.extend_from_slice(&message_raw),
            None => (),
        }

        Ok(message)
    }
}
