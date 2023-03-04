const READ_SIZE: usize = 1024;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use bytes::{BytesMut, Buf};
use super::super::types::record::{
    Message,
    ContentType,
    TLSOwnedPlaintext,
    TLSOutputPlaintext,
    MAX_PLAINTEXT_RECORD_SIZE,
    MAX_CIPHERTEXT_RECORD_SIZE,
};
use super::super::error::TLSError;
use super::super::helpers::{
    Transcript,
    EncryptionKey,
    Ciphers,
    TrafficSecrets,
    encrypt_traffic,
    decrypt_message,
};
use crate::util::io::{AsyncStream};

pub struct Encryption {
    pub traffic_secrets: TrafficSecrets,
    pub ciphers: Ciphers,
}

pub fn encrypt_record(
    to_send: &mut BytesMut,
    data_ref: &[u8],
    content_type: ContentType,
    traffic_secret: &EncryptionKey,
    client_sequence_no: u64,
    transcript: Option<&mut Transcript>,
) -> Result<(), TLSError> {
    if data_ref.len() > MAX_PLAINTEXT_RECORD_SIZE {
        return Err(TLSError::InvalidPlaintextRecord);
    }

    let mut data = data_ref.to_vec();

    if let Some(transcript) = transcript {
        transcript.update(&data);
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

pub struct RecordReceiver {
    incoming_data: BytesMut,
    closed: bool,
}

impl RecordReceiver {
    pub fn new() -> Self {
        RecordReceiver {
            incoming_data: BytesMut::new(),
            closed: false,
        }
    }

    fn pop_record(&mut self) -> Poll<Result<Option<TLSOwnedPlaintext>, TLSError>> {
        if self.incoming_data.remaining() < 5 {
            if self.closed {
                return Poll::Ready(Ok(None));
            }
            else {
                return Poll::Pending;
            }
        }

        let content_type = ContentType::from_raw(self.incoming_data[0]);

        let mut legacy_record_version_bytes: [u8; 2] = Default::default();
        legacy_record_version_bytes.copy_from_slice(&self.incoming_data[1..3]);
        let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);


        let mut length_bytes: [u8; 2] = Default::default();
        length_bytes.copy_from_slice(&self.incoming_data[3..5]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length > MAX_CIPHERTEXT_RECORD_SIZE {
            return Poll::Ready(Err(TLSError::InvalidPlaintextRecord));
        }

        if self.incoming_data.remaining() < 5 + length {
            if self.closed {
                return Poll::Ready(Err(TLSError::InvalidPlaintextRecord));
            }
            else {
                return Poll::Pending;
            }
        }

        let header: [u8; 5] = [
            self.incoming_data[0],
            self.incoming_data[1],
            self.incoming_data[2],
            self.incoming_data[3],
            self.incoming_data[4],
        ];

        let mut fragment: Vec<u8> = Vec::new();
        fragment.extend_from_slice(&self.incoming_data[5..5 + length]);

        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&self.incoming_data[0..5 + length]);

        let record = TLSOwnedPlaintext {
            content_type,
            legacy_record_version,
            header,
            fragment,
            raw,
        };

        self.incoming_data.advance(5 + (length as usize));

        return Poll::Ready(Ok(Some(record)));
    }

    fn append_data(&mut self, data: &[u8]) {
        self.incoming_data.extend_from_slice(data);
    }

    fn close(&mut self) {
        self.closed = true;
    }
}

fn poll_receive_record(
    receiver: &mut RecordReceiver,
    cx: &mut Context<'_>,
    reader: &mut Pin<Box<dyn AsyncStream>>,
) -> Poll<Result<Option<TLSOwnedPlaintext>, TLSError>> {
    loop {
        match receiver.pop_record() {
            Poll::Ready(r) => return Poll::Ready(r),
            Poll::Pending => (),
        };

        match poll_receive_data(cx, reader) {
            Poll::Ready(Ok(Some(data))) => {
                receiver.append_data(&data);
            }
            Poll::Ready(Ok(None)) => {
                receiver.close();
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

fn poll_receive_data(
    cx: &mut Context<'_>,
    reader: &mut Pin<Box<dyn AsyncStream>>,
) -> Poll<Result<Option<Vec<u8>>, TLSError>> {
    let mut recv_data = vec![0; READ_SIZE];
    let mut recv_buf = ReadBuf::new(&mut recv_data);
    assert!(recv_buf.filled().len() == 0);

    match AsyncRead::poll_read(Pin::new(reader), cx, &mut recv_buf) {
        Poll::Ready(Err(e)) => {
            Poll::Ready(Err(TLSError::IOError(e.kind())))
        }
        Poll::Ready(Ok(())) => {
            // If len is 0, either we have unexpected end of data or the connection
            // has been closed.
            if recv_buf.filled().len() == 0 {
                Poll::Ready(Ok(None))
            }
            else {
                cx.waker().wake_by_ref();

                let v: Vec<u8> = Vec::from(recv_buf.filled());
                return Poll::Ready(Ok(Some(v)));
            }
        }
        Poll::Pending => {
            Poll::Pending
        }
    }
}

fn poll_receive_record_ignore_cc(
    cx: &mut Context<'_>,
    reader: &mut Pin<Box<dyn AsyncStream>>,
    receiver: &mut RecordReceiver,
) -> Poll<Result<Option<TLSOwnedPlaintext>, TLSError>> {
    loop {
        match poll_receive_record(receiver, cx, reader) {
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
    pub inner: Pin<Box<dyn AsyncStream>>,
    pub receiver: RecordReceiver,
}

impl PlaintextStream {
    pub fn new(inner: Pin<Box<dyn AsyncStream>>, receiver: RecordReceiver) -> Self {
        PlaintextStream { inner, receiver }
    }

    pub fn receive_plaintext_message<'a, 'b>(
        &'a mut self,
        transcript: &'b mut Vec<u8>,
    ) -> ReceivePlaintextMessage<'a, 'b> {
        ReceivePlaintextMessage {
            reader: &mut self.inner,
            receiver: &mut self.receiver,
            transcript,
        }
    }
}

pub struct ReceivePlaintextMessage<'a, 'b> {
    reader: &'a mut Pin<Box<dyn AsyncStream>>,
    receiver: &'a mut RecordReceiver,
    transcript: &'b mut Vec<u8>,
}


impl<'a, 'b> Future for ReceivePlaintextMessage<'a, 'b> {
    type Output = Result<Option<Message>, TLSError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let direct = Pin::into_inner(self);
        poll_receive_plaintext_message(cx, direct.reader, direct.receiver, direct.transcript)
    }
}

fn poll_receive_plaintext_message(
    cx: &mut Context<'_>,
    reader: &mut Pin<Box<dyn AsyncStream>>,
    receiver: &mut RecordReceiver,
    transcript: &mut Vec<u8>,
) -> Poll<Result<Option<Message>, TLSError>> {
    match poll_receive_record_ignore_cc(cx, reader, receiver) {
        Poll::Ready(Ok(Some(plaintext))) => {
            // TODO: Support records containing multiple handshake messages
            transcript.extend_from_slice(&plaintext.fragment);
            let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)
                .map_err(|_| TLSError::InvalidMessageRecord)?;
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
            encryption,
        }
    }

    // formerly encode EncryptedToSend
    pub async fn send_direct(&mut self, data: &[u8]) -> Result<(), std::io::Error> {
        self.plaintext.inner.write_all(data).await
    }

    pub fn receive_message<'a, 'b>(
        &'a mut self,
        transcript: Option<&'b mut Transcript>,
    ) -> ReceiveEncryptedMessage<'a, 'b> {
        ReceiveEncryptedMessage::new(
            &mut self.plaintext.inner,
            &mut self.plaintext.receiver,
            &mut self.server_sequence_no,
            &self.encryption,
            transcript)
    }

    pub fn poll_receive_encrypted_message(
        &mut self,
        cx: &mut Context<'_>,
        transcript: Option<&mut Transcript>,
    ) -> Poll<Result<Option<Message>, TLSError>> {
        poll_receive_encrypted_message(
            cx,
            &mut self.plaintext.inner,
            &mut self.plaintext.receiver,
            &mut self.server_sequence_no,
            &self.encryption,
            transcript)
    }
}

pub struct ReceiveEncryptedMessage<'a, 'b> {
    reader: &'a mut Pin<Box<dyn AsyncStream>>,
    receiver: &'a mut RecordReceiver,
    server_sequence_no: &'a mut u64,
    encryption: &'a Encryption,
    transcript: Option<&'b mut Transcript>
}

impl ReceiveEncryptedMessage<'_, '_> {
    pub fn new<'a, 'b>(
        reader: &'a mut Pin<Box<dyn AsyncStream>>,
        receiver: &'a mut RecordReceiver,
        server_sequence_no: &'a mut u64,
        encryption: &'a Encryption,
        transcript: Option<&'b mut Transcript>
    ) -> ReceiveEncryptedMessage<'a, 'b> {
        ReceiveEncryptedMessage {
            reader,
            receiver,
            server_sequence_no,
            encryption,
            transcript,
        }
    }
}

impl<'a, 'b> Future for ReceiveEncryptedMessage<'a, 'b> {
    type Output = Result<Option<Message>, TLSError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let direct = Pin::into_inner(self);
        let transcript: Option<&mut Transcript> = match &mut direct.transcript {
            Some(v) => Some(v),
            None => None,
        };
        poll_receive_encrypted_message(
            cx,
            direct.reader,
            direct.receiver,
            direct.server_sequence_no,
            direct.encryption,
            transcript)
    }
}

fn poll_receive_encrypted_message(
    cx: &mut Context<'_>,
    reader: &mut Pin<Box<dyn AsyncStream>>,
    receiver: &mut RecordReceiver,
    server_sequence_no: &mut u64,
    encryption: &Encryption,
    transcript: Option<&mut Transcript>
) -> Poll<Result<Option<Message>, TLSError>> {
    match poll_receive_record_ignore_cc(cx, reader, receiver) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
        Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
        Poll::Ready(Ok(Some(plaintext))) => {
            // TODO: Support records containing multiple handshake messages
            // TODO: Cater for alerts
            let (message, message_raw) = decrypt_message(
                *server_sequence_no,
                &encryption.traffic_secrets.server,
                &plaintext.raw)?;
            // println!("Received {}", message.name());
            *server_sequence_no += 1;
            if let Some(transcript) = transcript {
                 transcript.update(&message_raw);
            }
            Poll::Ready(Ok(Some(message)))
        }
    }
}
