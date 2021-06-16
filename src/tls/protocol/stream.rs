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
use bytes::{Bytes, BytesMut, Buf, BufMut};
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

pub struct Encryption {
    pub traffic_secrets: TrafficSecrets,
    pub ciphers: Ciphers,
}

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin {}

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

fn poll_receive_record(
    cx: &mut Context<'_>,
    reader: &mut Box<dyn AsyncReadWrite>,
    incoming_data: &mut BytesMut,
) -> Poll<Result<Option<TLSOwnedPlaintext>, Box<dyn Error>>> {
    let mut want: usize = 5;
    if incoming_data.remaining() >= 5 {
        let content_type = ContentType::from_raw(incoming_data[0]);

        let mut legacy_record_version_bytes: [u8; 2] = Default::default();
        legacy_record_version_bytes.copy_from_slice(&incoming_data[1..3]);
        let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);


        let mut length_bytes: [u8; 2] = Default::default();
        length_bytes.copy_from_slice(&incoming_data[3..5]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length > TLS_RECORD_SIZE {
            return Poll::Ready(Err(TLSPlaintextError::InvalidLength.into()));
        }


        if incoming_data.remaining() >= 5 + length {
            println!("ReceiveRecord: Parsing fragment of len {}; content_type = {:?}",
                     length, content_type);
            let mut header: [u8; 5] = [
                incoming_data[0],
                incoming_data[1],
                incoming_data[2],
                incoming_data[3],
                incoming_data[4],
            ];

            let mut fragment: Vec<u8> = Vec::new();
            fragment.extend_from_slice(&incoming_data[5..]);

            let mut raw: Vec<u8> = Vec::new();
            raw.extend_from_slice(&incoming_data);

            println!("ReceiveRecord: raw.len() = {}", raw.len());
            let record = TLSOwnedPlaintext {
                content_type,
                legacy_record_version,
                header: header,
                fragment: fragment,
                raw: raw,
            };

            assert!(incoming_data.remaining() == 5 + (length as usize)); // TODO: remove
            incoming_data.advance(5 + (length as usize));

            return Poll::Ready(Ok(Some(record)));
        }
        want = 5 + length;
    }

    let amt = want - incoming_data.remaining();
    let mut recv_data = vec_with_len(amt);
    let mut recv_buf = ReadBuf::new(&mut recv_data);
    let old_filled = recv_buf.filled().len();

    match AsyncRead::poll_read(Pin::new(reader), cx, &mut recv_buf) {
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
            // self_ok_done()
            incoming_data.extend_from_slice(recv_buf.filled());

            // println!("want = {}, have = {}", want, incoming_data.len());
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Poll::Pending => {
            println!("ReceiveRecord::poll(): inner is not ready");
            Poll::Pending
        }
    }
    // let x: () = reader.read(&mut self_buf);
    // unimplemented!()
}

fn poll_receive_record_ignore_cc(
    cx: &mut Context<'_>,
    reader: &mut Box<dyn AsyncReadWrite>,
    incoming_data: &mut BytesMut,
) -> Poll<Result<Option<TLSOwnedPlaintext>, Box<dyn Error>>> {
    loop {
        match poll_receive_record(cx, reader, incoming_data) {
            Poll::Ready(Ok(Some(record))) => {
                if record.content_type != ContentType::ChangeCipherSpec {
                    return Poll::Ready(Ok(Some(record)));
                }
            }
            Poll::Ready(Ok(None)) => {
                return Poll::Ready(Ok(None));
            }
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(e));
            }
            Poll::Pending => {
                return Poll::Pending;
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                         PlaintextStream                                        //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct PlaintextStream {
    pub inner: Box<dyn AsyncReadWrite>,
    pub incoming_data: BytesMut,
}

impl PlaintextStream {
    pub fn new(inner: Box<dyn AsyncReadWrite>, incoming_data: BytesMut) -> Self {
        PlaintextStream { inner, incoming_data }
    }

    pub fn receive_plaintext_message<'a, 'b>(
        &'a mut self,
        transcript: &'b mut Vec<u8>,
    ) -> ReceivePlaintextMessage<'a, 'b> {
        ReceivePlaintextMessage {
            reader: &mut self.inner,
            incoming_data: &mut self.incoming_data,
            transcript: transcript,
        }
    }
}

pub struct ReceivePlaintextMessage<'a, 'b> {
    reader: &'a mut Box<dyn AsyncReadWrite>,
    incoming_data: &'a mut BytesMut,
    transcript: &'b mut Vec<u8>,
}


impl<'a, 'b> Future for ReceivePlaintextMessage<'a, 'b> {
    type Output = Result<Option<Message>, Box<dyn Error>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let direct = Pin::into_inner(self);
        poll_receive_plaintext_message(cx, direct.reader, direct.incoming_data, direct.transcript)
    }
}

fn poll_receive_plaintext_message(
    cx: &mut Context<'_>,
    reader: &mut Box<dyn AsyncReadWrite>,
    incoming_data: &mut BytesMut,
    transcript: &mut Vec<u8>,
) -> Poll<Result<Option<Message>, Box<dyn Error>>> {
    match poll_receive_record_ignore_cc(cx, reader, incoming_data) {
        Poll::Ready(Ok(Some(plaintext))) => {
            // TODO: Support records containing multiple handshake messages
            transcript.extend_from_slice(&plaintext.fragment);
            let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)?;
            Poll::Ready(Ok(Some(message)))
        }
        Poll::Ready(Ok(None)) => {
            Poll::Ready(Ok(None))
        }
        Poll::Ready(Err(e)) => {
            Poll::Ready(Err(e))
        }
        Poll::Pending => {
            Poll::Pending
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                         EncryptedStream                                        //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub struct EncryptedStream {
    pub plaintext: PlaintextStream,
    pub client_sequence_no: u64,
    pub server_sequence_no: u64,
    pub encryption: Encryption,
}

impl EncryptedStream {
    pub fn new(
        plaintext: PlaintextStream,
        encryption: Encryption,
    ) -> Self {
        EncryptedStream {
            plaintext,
            client_sequence_no: 0,
            server_sequence_no: 0,
            encryption: encryption,
        }
    }

    // formerly encode EncryptedToSend
    pub async fn send_direct(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        self.plaintext.inner.write_all(data).await
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

    pub fn receive_message<'a, 'b>(
        &'a mut self,
        transcript: Option<&'b mut Vec<u8>>,
    ) -> ReceiveEncryptedMessage<'a, 'b> {
        ReceiveEncryptedMessage::new(
            &mut self.plaintext.inner,
            &mut self.plaintext.incoming_data,
            &mut self.server_sequence_no,
            &self.encryption,
            transcript)
    }

    pub fn poll_receive_encrypted_message<'a, 'b, 'c>(
        &'a mut self,
        cx: &'b mut Context<'_>,
        transcript: Option<&'c mut Vec<u8>>,
    ) -> Poll<Result<Option<Message>, Box<dyn Error>>> {
        poll_receive_encrypted_message(
            cx,
            &mut self.plaintext.inner,
            &mut self.plaintext.incoming_data,
            &mut self.server_sequence_no,
            &self.encryption,
            transcript)
    }
}

pub struct ReceiveEncryptedMessage<'a, 'b> {
    reader: &'a mut Box<dyn AsyncReadWrite>,
    incoming_data: &'a mut BytesMut,
    server_sequence_no: &'a mut u64,
    encryption: &'a Encryption,
    transcript: Option<&'b mut Vec<u8>>
}

impl ReceiveEncryptedMessage<'_, '_> {
    pub fn new<'a, 'b>(
        reader: &'a mut Box<dyn AsyncReadWrite>,
        incoming_data: &'a mut BytesMut,
        server_sequence_no: &'a mut u64,
        encryption: &'a Encryption,
        transcript: Option<&'b mut Vec<u8>>
    ) -> ReceiveEncryptedMessage<'a, 'b> {
        ReceiveEncryptedMessage {
            reader,
            incoming_data,
            server_sequence_no,
            encryption,
            transcript,
        }
    }
}

impl<'a, 'b> Future for ReceiveEncryptedMessage<'a, 'b> {
    type Output = Result<Option<Message>, Box<dyn Error>>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let direct = Pin::into_inner(self);
        let transcript: Option<&mut Vec<u8>> = match &mut direct.transcript {
            Some(v) => Some(v),
            None => None,
        };
        poll_receive_encrypted_message(
            cx,
            direct.reader,
            direct.incoming_data,
            direct.server_sequence_no,
            direct.encryption,
            transcript)
    }
}

fn poll_receive_encrypted_message(
    cx: &mut Context<'_>,
    reader: &mut Box<dyn AsyncReadWrite>,
    incoming_data: &mut BytesMut,
    server_sequence_no: &mut u64,
    encryption: &Encryption,
    transcript: Option<&mut Vec<u8>>
) -> Poll<Result<Option<Message>, Box<dyn Error>>> {
    match poll_receive_record_ignore_cc(cx, reader, incoming_data) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
        Poll::Ready(Ok(Some(plaintext))) => {
            println!("ReceiveEncryptedMessage: plaintext.raw.len() = {}, server_sequence_no =  {}",
                plaintext.raw.len(), server_sequence_no);
            // TODO: Support records containing multiple handshake messages
            // TODO: Cater for alerts
            let (message, message_raw) = decrypt_message(
                *server_sequence_no,
                &encryption.traffic_secrets.server,
                &plaintext.raw)?;
            println!("ReceiveEncryptedMessage: after decryption; message = {}",
                     message.name());
            *server_sequence_no += 1;
            match transcript {
                Some(transcript) => transcript.extend_from_slice(&message_raw),
                None => (),
            };
            Poll::Ready(Ok(Some(message)))
        }
    }
}
