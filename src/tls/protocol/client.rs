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
use tokio_util::codec::{Encoder, Decoder, Framed};
use futures::stream::StreamExt;
use futures::sink::SinkExt;
use bytes::{BytesMut, Buf};
use ring::agreement::EphemeralPrivateKey;
use super::super::helpers::{
    EncryptionKey,
    Ciphers,
    TrafficSecrets,
    get_server_hello_x25519_shared_secret,
    get_derived_prk,
    get_zero_prk,
    encrypt_traffic,
    decrypt_message,
    verify_finished,
    derive_secret,
    rsa_sign,
    rsa_verify,
};
use super::super::types::handshake::{
    Handshake,
    ServerHello,
    EncryptedExtensions,
    Certificate,
    CertificateEntry,
    CertificateRequest,
    CertificateVerify,
    Finished,
};
use super::super::types::extension::{
    Extension,
    SignatureScheme,
};
use super::super::types::record::{
    Message,
    ContentType,
    TLSOwnedPlaintext,
    TLSPlaintext,
    TLSOutputPlaintext,
    TLSPlaintextError,
    TLS_RECORD_SIZE,
};
use super::super::types::alert::{
    Alert,
};
use super::super::error::{
    TLSError,
};
use super::super::super::util::{from_hex, vec_with_len, BinaryData, DebugHexDump, Indent};
use super::super::super::error;
use super::super::super::crypt::{HashAlgorithm, AeadAlgorithm};
use super::super::super::binary::{BinaryReader, BinaryWriter};
use super::super::super::asn1;
use super::super::super::x509;

pub enum ServerAuth {
    None,
    CertificateAuthority(Vec<u8>),
}

pub enum ClientAuth {
    None,
    Certificate { cert: Vec<u8>, key: Vec<u8> },
}

pub struct ClientConfig {
    pub client_auth: ClientAuth,
    pub server_auth: ServerAuth,
}

////////////////////////////////////////////////////////////////////////////////////////////////////

fn encrypt_record(
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

enum Endpoint {
    Client,
    Server,
}

async fn send_finished(
    hash_alg: HashAlgorithm,
    new_transcript_hash: &[u8],
    framed: &mut Framed<impl AsyncWrite + Unpin, RecordDecoder>,
) -> Result<(), Box<dyn Error>> {
    let finished_key = derive_secret(
        hash_alg,
        &framed.codec().encryption.traffic_secrets.client.raw,
        b"finished", &[])?;
    let verify_data = hash_alg.hmac_sign(&finished_key, &new_transcript_hash)?;
    let client_finished = Handshake::Finished(Finished { verify_data });
    send_handshake(&client_finished, None, framed).await?;
    Ok(())
}

async fn send_client_certificate(
    hash_alg: HashAlgorithm,
    transcript: &mut Vec<u8>,
    client_cert_data: &[u8],
    client_key_data: &[u8],
    signature_scheme: SignatureScheme,
    rng: &dyn ring::rand::SecureRandom,
    framed: &mut Framed<impl AsyncWrite + Unpin, RecordDecoder>,
) -> Result<(), Box<dyn Error>> {
    let client_cert = x509::Certificate::from_bytes(client_cert_data)?;
    let handshake = Handshake::Certificate(Certificate {
        certificate_request_context: Vec::new(),
        certificate_list: vec![
            CertificateEntry {
                data: Vec::from(client_cert_data),
                certificate: client_cert,
                extensions: vec![],
            }
        ],
    });


    println!("old transcript len = {}", transcript.len());
    send_handshake(&handshake, Some(transcript), framed).await?;
    println!("new transcript len = {}", transcript.len());

    let thash: Vec<u8> = hash_alg.hash(transcript);

    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);

    let signature = rsa_sign(client_key_data, &verify_input, signature_scheme, rng)?;


    let handshake = Handshake::CertificateVerify(CertificateVerify {
        algorithm: signature_scheme,
        signature: signature,
    });
    send_handshake(&handshake, Some(transcript), framed).await?;

    Ok(())
}

async fn send_handshake(
    handshake: &Handshake,
    transcript: Option<&mut Vec<u8>>,
    framed: &mut Framed<impl AsyncWrite + Unpin, RecordDecoder>,
) -> Result<(), Box<dyn Error>> {
    let mut conn_to_send = BytesMut::new();


    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    encrypt_record(
        &mut conn_to_send,
        &finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &framed.codec().encryption.traffic_secrets.client,        // traffic_secret
        framed.codec().client_sequence_no, // sequence_no
        transcript,
    )?;

    framed.codec_mut().client_sequence_no += 1;
    framed.send(&EncryptedToSend { data: &conn_to_send }).await?;

    Ok(())
}

fn verify_certificate(ca_raw: &[u8], target_raw: &[u8]) -> Result<(), TLSError> {
    let ca_cert = x509::Certificate::from_bytes(&ca_raw)
        .map_err(|_| TLSError::InvalidCertificate)?;

    let mut target_reader = BinaryReader::new(&target_raw);
    let target_item = asn1::reader::read_item(&mut target_reader)
        .map_err(|_| TLSError::InvalidCertificate)?;
    let elements = target_item.as_exact_sequence(3)
        .map_err(|_| TLSError::InvalidCertificate)?;

    let tbs_certificate = x509::TBSCertificate::from_asn1(&elements[0])
        .map_err(|_| TLSError::InvalidCertificate)?;
    let signature_algorithm = x509::AlgorithmIdentifier::from_asn1(&elements[1])
        .map_err(|_| TLSError::InvalidCertificate)?;
    let signature_value_bit_string = elements[2].as_bit_string()
        .map_err(|_| TLSError::InvalidCertificate)?;
    let signature = &signature_value_bit_string.bytes;

    let rsa_parameters: &ring::signature::RsaParameters;
    if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_256_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_384_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA384;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_512_WITH_RSA_ENCRYPTION {
        rsa_parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA512;
    }
    else {
        return Err(TLSError::UnsupportedCertificateSignatureAlgorithm);
    }

    let ca_public_key_info = &ca_cert.tbs_certificate.subject_public_key_info;
    let ca_public_key = ring::signature::UnparsedPublicKey::new(
        rsa_parameters,
        &ca_public_key_info.subject_public_key.bytes);
    let tbs_data = &target_raw[elements[0].range.clone()];
    ca_public_key.verify(tbs_data, signature).map_err(|_| TLSError::VerifyCertificateFailed)?;

    Ok(())
}

fn make_verify_transcript_input(endpoint: Endpoint, thash: &[u8]) -> Vec<u8> {
    let mut verify_input: Vec<u8> = Vec::new();
    for _ in 0..64 {
        verify_input.push(0x20);
    }
    let context_string = match endpoint {
        Endpoint::Client => b"TLS 1.3, client CertificateVerify",
        Endpoint::Server => b"TLS 1.3, server CertificateVerify",
    };
    verify_input.extend_from_slice(context_string);
    verify_input.push(0);
    verify_input.extend_from_slice(thash);
    verify_input
}

fn verify_transcript(
    certificate_verify: &CertificateVerify,
    certificate_verify_thash: &[u8],
    public_key: &x509::SubjectPublicKeyInfo,
    endpoint: Endpoint,
) -> Result<(), TLSError> {
    let verify_input = make_verify_transcript_input(endpoint, certificate_verify_thash);
    rsa_verify(
        certificate_verify.algorithm,
        &public_key.subject_public_key.bytes,
        &verify_input,
        &certificate_verify.signature
    )
}

struct RecordDecoder {
    client_sequence_no: u64,
    server_sequence_no: u64,
    encryption: AEncryption,
}

impl RecordDecoder {
    fn new(encryption: AEncryption) -> Self {
        RecordDecoder {
            client_sequence_no: 0,
            server_sequence_no: 0,
            encryption,
        }
    }
}

impl Encoder<&EncryptedToSend<'_>> for RecordDecoder {
    type Error = Box<dyn Error>;

    fn encode(&mut self, item: &EncryptedToSend, dst: &mut BytesMut) -> Result<(), Box<dyn Error>> {
        dst.extend_from_slice(&item.data);
        Ok(())
    }
}

impl Encoder<&UnencToSend<'_>> for RecordDecoder {
    type Error = Box<dyn Error>;

    fn encode(&mut self, item: &UnencToSend, dst: &mut BytesMut) -> Result<(), Box<dyn Error>> {
        encrypt_record(
            dst,
            &item.data,
            item.content_type,
            &self.encryption.traffic_secrets.client,
            self.client_sequence_no,
            None,
        )?;
        self.client_sequence_no += 1;
        Ok(())
    }
}

impl Decoder for RecordDecoder {
    type Item = TLSOwnedPlaintext;
    type Error = Box<dyn Error>;
    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<TLSOwnedPlaintext>, Box<dyn Error>> {
        if src.len() < 5 {
            return Ok(None);
        }

        let content_type = ContentType::from_raw(src[0]);

        let mut legacy_record_version_bytes: [u8; 2] = Default::default();
        legacy_record_version_bytes.copy_from_slice(&src[1..3]);
        let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);

        let mut length_bytes: [u8; 2] = Default::default();
        length_bytes.copy_from_slice(&src[3..5]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length > TLS_RECORD_SIZE {
            return Err(TLSPlaintextError::InvalidLength.into());
        }
        // println!("Attempting to decode fragment of len {}", length);

        let total_length = 5 + length;
        if src.len() >= total_length {
            // println!("src.len() >= total_length");
            println!("RecordDecoder: Parsing fragment of len {}; content_type = {:?}",
                     length, content_type);


            let mut header: [u8; 5] = [
                src[0],
                src[1],
                src[2],
                src[3],
                src[4],
            ];

            let mut fragment: Vec<u8> = Vec::new();
            fragment.extend_from_slice(&src[5..total_length]);

            let mut raw: Vec<u8> = Vec::new();
            raw.extend_from_slice(&src[0..total_length]);
            src.advance(total_length);

            let record = TLSOwnedPlaintext {
                content_type,
                legacy_record_version,
                header: header,
                fragment: fragment,
                raw: raw,
            };
            return Ok(Some(record));
        }
        else {
            println!("src.len() < total_length");
        }

        src.reserve(total_length - src.len());

        return Ok(None)
    }
}

pub struct ReceiveRecord<'a, T : AsyncRead + Unpin> {
    reader: &'a mut T,
    incoming_data: Vec<u8>,
}

impl<'a, T : AsyncRead + Unpin> ReceiveRecord<'a, T> {
    fn new(reader: &'a mut T) -> ReceiveRecord<'a, T> {
        ReceiveRecord {
            reader: reader,
            incoming_data: Vec::new(),
        }
    }
}

impl<'a, T : AsyncRead + Unpin> Future for ReceiveRecord<'a, T> {
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

pub struct AEncryption {
    traffic_secrets: TrafficSecrets,
    ciphers: Ciphers,
}

async fn receive_record_framed_ignore_cc(
    framed: &mut Framed<impl AsyncRead + Unpin, RecordDecoder>,
) -> Option<Result<TLSOwnedPlaintext, Box<dyn Error>>> {
    loop {
        match framed.next().await {
            Some(Ok(record)) => {
                if record.content_type != ContentType::ChangeCipherSpec {
                    return Some(Ok(record));
                }
            }
            Some(Err(e)) => {
                return Some(Err(e));
            }
            None => {
                return None;
            }
        }
    }
}

async fn receive_message_framed(
    framed: &mut Framed<impl AsyncRead + Unpin, RecordDecoder>,
    transcript: Option<&mut Vec<u8>>,
) -> Result<Message, Box<dyn Error>> {
    let plaintext = match receive_record_framed_ignore_cc(framed).await {
        Some(Ok(v)) => v,
        Some(Err(e)) => return Err(e),
        None => return Err(error!("No more messages")),
    };
    println!("receive_message_framed: plaintext.raw.len() = {}, server_sequence_no =  {}",
        plaintext.raw.len(), framed.codec().server_sequence_no);
    // TODO: Support records containing multiple handshake messages
    // TODO: Cater for alerts
    let (message, message_raw) = decrypt_message(
        framed.codec().server_sequence_no,
        &framed.codec().encryption.traffic_secrets.server,
        &plaintext.raw)?;
    println!("receive_message_framed: after decryption");
    framed.codec_mut().server_sequence_no += 1;
    match transcript {
        Some(transcript) => transcript.extend_from_slice(&message_raw),
        None => (),
    }

    Ok(message)
}

fn receive_record<'a, T : AsyncRead + Unpin>(
    reader: &'a mut T,
) -> ReceiveRecord<'a, T> {
    ReceiveRecord::new(reader)
}

async fn receive_record_ignore_cc(
    reader: &mut (impl AsyncRead + Unpin),
) -> Result<TLSOwnedPlaintext, Box<dyn Error>> {
    loop {
        let record = receive_record(reader).await?;
        if record.content_type != ContentType::ChangeCipherSpec {
            return Ok(record)
        }
    }
}

pub struct EncryptedHandshake {
    transcript: Vec<u8>,
    config: ClientConfig,
}

impl EncryptedHandshake {
    pub fn new(
        config: ClientConfig,
        transcript: Vec<u8>,
    ) -> Self {
        EncryptedHandshake {
            transcript: transcript,
            config: config,
        }
    }

    async fn receive_handshake_framed(
        &mut self,
        framed: &mut Framed<impl AsyncRead + Unpin, RecordDecoder>,
    ) -> Result<Handshake, Box<dyn Error>> {
        let message = receive_message_framed(framed, Some(&mut self.transcript)).await?;
        match message {
            Message::Handshake(hs) => {
                Ok(hs)
            }
            _ => {
                Err(error!("Expected a handshake, got {:?}",
                    message.content_type()))
            }
        }
    }

}

async fn receive_plaintext_message(
    reader: &mut (impl AsyncRead + Unpin),
    transcript: &mut Vec<u8>,
) -> Result<Message, Box<dyn Error>> {
    let plaintext = receive_record_ignore_cc(reader).await?;
    // TODO: Support records containing multiple handshake messages
    transcript.extend_from_slice(&plaintext.fragment);
    let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)?;
    Ok(message)
}

async fn receive_plaintext_handshake(
    reader: &mut (impl AsyncRead + Unpin),
    transcript: &mut Vec<u8>,
) -> Result<Handshake, Box<dyn Error>> {
    let message = receive_plaintext_message(reader, transcript).await?;
    match message {
        Message::Handshake(hs) => Ok(hs),
        _ => Err(error!("Expected a handshake, got {:?}", message.content_type())),
    }
}

async fn receive_server_hello(
    reader: &mut (impl AsyncRead + Unpin),
    transcript: &mut Vec<u8>,
) -> Result<ServerHello, Box<dyn Error>> {
    let handshake = receive_plaintext_handshake(reader, transcript).await?;
    match handshake {
        Handshake::ServerHello(v) => Ok(v),
        _ => Err(error!("Expected ServerHello, got {}", handshake.name()))
    }
}

async fn write_plaintext_handshake(
    writer: &mut (impl AsyncWrite + Unpin),
    handshake: &Handshake,
    transcript: &mut Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let mut bin_writer = BinaryWriter::new();
    bin_writer.write_item(handshake)?;
    let fragment_vec = Vec::<u8>::from(bin_writer);

    let record = TLSOutputPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: &fragment_vec,
    };

    transcript.extend_from_slice(&record.fragment);
    let mut encoded = BytesMut::new();
    record.encode(&mut encoded);
    writer.write_all(&encoded).await?;
    Ok(())
}

pub async fn establish_connection<T>(
    config: ClientConfig,
    mut stream: T,
    client_hello: &Handshake,
    private_key: EphemeralPrivateKey,
) -> Result<EstablishedConnection<T>, Box<dyn Error>>
    where T : AsyncRead + AsyncWrite + Unpin
{
    let mut initial_transcript: Vec<u8> = Vec::new();
    write_plaintext_handshake(&mut stream, client_hello, &mut initial_transcript).await?;
    let server_hello = receive_server_hello(&mut stream, &mut initial_transcript).await?;

    let henc = get_handshake_encryption(&initial_transcript, &server_hello, private_key)?;
    let prk = henc.prk;

    let encryption = AEncryption {
        traffic_secrets: henc.traffic_secrets,
        ciphers: henc.ciphers,
    };

    let mut conn = EncryptedHandshake::new(config, initial_transcript);
    let mut framed = Framed::new(stream, RecordDecoder::new(encryption));
    let sm = receive_server_messages(&mut conn, &mut framed).await?;
    let p2 = do_phase_two(&mut conn, &prk, &sm, &mut framed).await?;


    framed.codec_mut().client_sequence_no = 0;
    framed.codec_mut().server_sequence_no = 0;
    framed.codec_mut().encryption = p2;

    println!("After  send_finished()");

    Ok(EstablishedConnection {
        framed: framed,
    })
}

struct HandshakeEncryption {
    prk: Vec<u8>,
    traffic_secrets: TrafficSecrets,
    ciphers: Ciphers,
}

fn get_handshake_encryption(
    transcript: &[u8],
    server_hello: &ServerHello,
    private_key: EphemeralPrivateKey,
) -> Result<HandshakeEncryption, Box<dyn Error>> {

    println!("PhaseOne: Received ServerHello");
    println!("{:#?}", &Indent(&server_hello));
    let ciphers = Ciphers::from_server_hello(&server_hello)?;

    let secret = get_server_hello_x25519_shared_secret(private_key, &server_hello)
        .ok_or_else(|| error!("Cannot get shared secret"))?;
    println!("Shared secret = {}", BinaryData(&secret));

    let prk = get_derived_prk(ciphers.hash_alg, &get_zero_prk(ciphers.hash_alg), &secret)?;
    let traffic_secrets = TrafficSecrets::derive_from(&ciphers, transcript, &prk, "hs")?;
    println!("KEY CLIENT_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&traffic_secrets.client.raw));
    println!("KEY SERVER_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&traffic_secrets.server.raw));
    Ok(HandshakeEncryption { traffic_secrets, ciphers, prk })
}

struct ServerMessages {
    encrypted_extensions: EncryptedExtensions,
    certificate_request: Option<CertificateRequest>,
    certificate: Option<Certificate>,
    certificate_verify: Option<(CertificateVerify, Vec<u8>)>,
    finished: (Finished, Vec<u8>),
}

async fn receive_server_messages(
    conn: &mut EncryptedHandshake,
    framed: &mut Framed<impl AsyncRead + Unpin, RecordDecoder>,
) -> Result<ServerMessages, Box<dyn Error>> {
    // TODO: Allow some of these to be absent depending on the config
    let handshake = conn.receive_handshake_framed(framed).await?;
    let encrypted_extensions = match handshake {
        Handshake::EncryptedExtensions(v) => v,
        _ => return Err(error!("Expected EncryptedExtensions, got {}", handshake.name())),
    };
    println!("Phase two: Got encrypted_extensions");

    let handshake = conn.receive_handshake_framed(framed).await?;
    let certificate_request = match handshake {
        Handshake::CertificateRequest(v) => Some(v),
        _ => return Err(error!("Expected CertificateRequest, got {}", handshake.name())),
    };
    println!("Phase two: Got certificate_request");

    let handshake = conn.receive_handshake_framed(framed).await?;
    let certificate = match handshake {
        Handshake::Certificate(v) => Some(v),
        _ => return Err(error!("Expected Certificate, got {}", handshake.name())),
    };

    println!("Phase two: Got certificate");
    let certificate_verify_thash = framed.codec().encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake_framed(framed).await?;
    let certificate_verify = match handshake {
        Handshake::CertificateVerify(v) => Some((v, certificate_verify_thash)),
        _ => return Err(error!("Expected CertificateVerify, got {}", handshake.name())),
    };

    println!("Phase two: Got certificate_verify");
    let finished_thash = framed.codec().encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake_framed(framed).await?;
    let finished = match handshake {
        Handshake::Finished(v) => (v, finished_thash),
        _ => return Err(error!("Expected Finished, got {}", handshake.name())),
    };

    println!("Phase two: Got finished");

    Ok(ServerMessages {
        encrypted_extensions,
        certificate_request,
        certificate,
        certificate_verify,
        finished,
    })
}

async fn do_phase_two(
    conn: &mut EncryptedHandshake,
    prk: &[u8],
    sm: &ServerMessages,
    framed: &mut Framed<impl AsyncWrite + Unpin, RecordDecoder>,
) -> Result<AEncryption, Box<dyn Error>> {
    let ciphers_copy = framed.codec().encryption.ciphers.clone();
    let secrets_copy = TrafficSecrets {
        client: framed.codec().encryption.traffic_secrets.client.clone(),
        server: framed.codec().encryption.traffic_secrets.server.clone(),
    };


    let ciphers = &ciphers_copy;
    let secrets = &secrets_copy;

    let input_psk: &[u8] = &vec_with_len(ciphers.hash_alg.byte_len());
    let new_prk = get_derived_prk(ciphers.hash_alg, prk, input_psk)?;

    let application_secrets = TrafficSecrets::derive_from(&ciphers, &conn.transcript, &new_prk, "ap")?;
    println!("KEY CLIENT_TRAFFIC_SECRET_0 = {}", BinaryData(&application_secrets.client.raw));
    println!("KEY SERVER_TRAFFIC_SECRET_0 = {}", BinaryData(&application_secrets.server.raw));


    // let mut bad_finished = Finished { verify_data: finished.verify_data.clone() };
    // bad_finished.verify_data.push(0);
    println!("Before verify_finished()");
    let (finished, finished_thash) = &sm.finished;
    verify_finished(ciphers.hash_alg, &secrets.server, finished_thash, finished)?;
    println!("After  verify_finished()");

    let first_cert_entry : &CertificateEntry = match &sm.certificate {
        Some(certificate) => {
            match certificate.certificate_list.get(0) {
                Some(v) => v,
                None => {
                    return Err(error!("Server sent an empty certificate list"));
                }
            }
        }
        None => {
            return Err(error!("Server did not send a Certificate message"));
        }
    };

    let server_cert_raw: &[u8] = &first_cert_entry.data;
    let server_cert: &x509::Certificate = &first_cert_entry.certificate;

    let ca_cert: &[u8] = match &conn.config.server_auth {
        ServerAuth::CertificateAuthority(v) => v,
        ServerAuth::None => {
            return Err(error!("No CA certificate available"));
        }
    };

    println!("Before verify_certificate()");
    verify_certificate(ca_cert, &server_cert_raw)?;
    println!("After  verify_certificate()");


    println!("Before verify_transcript()");

    match &sm.certificate_verify {
        Some((certificate_verify, certificate_verify_thash)) => {
            verify_transcript(
                certificate_verify,
                certificate_verify_thash,
                &server_cert.tbs_certificate.subject_public_key_info,
                Endpoint::Server
            )?;
        }
        None => {
            return Err(error!("Server did not send CertificateVerify message"));
        }
    }
    println!("After  verify_transcript()");

    // FIXME: Don't hard-code SignatureScheme
    match &conn.config.client_auth {
        ClientAuth::Certificate { cert, key } => {
            let client_cert = cert;
            let client_key = key;

            let rng = ring::rand::SystemRandom::new();
            println!("Before send_client_certificate()");
            send_client_certificate(
                ciphers.hash_alg, // hash_alg: HashAlgorithm,
                &mut conn.transcript, // transcript: &mut Vec<u8>,
                client_cert, // client_cert_data: &[u8],
                client_key, // client_key_data: &[u8],
                SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                &rng,
                framed,
            ).await?;

            println!("After  send_client_certificate()");
        }
        ClientAuth::None => {
        }
    }

    let new_thash: Vec<u8> = ciphers.hash_alg.hash(&conn.transcript); // TODO: use conn.new_thash?

    // let mut bad_new_thash = new_thash.clone();
    // bad_new_thash.push(0);
    println!("Before send_finished()");
    send_finished(
        ciphers.hash_alg,
        &new_thash,
        framed).await?;

    Ok(AEncryption {
        traffic_secrets: application_secrets,
        ciphers: ciphers.clone(),
    })
}

pub struct EstablishedConnection<T> where T : AsyncRead + AsyncWrite + Unpin {
    framed: Framed<T, RecordDecoder>,
}

struct UnencToSend<'a> {
    data: &'a [u8],
    content_type: ContentType,
}

struct EncryptedToSend<'a> {
    data: &'a [u8],
}

impl<T> EstablishedConnection<T> where T : AsyncRead + AsyncWrite + Unpin {
    pub async fn write_normal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.framed.send(&UnencToSend {
            data: data,
            content_type: ContentType::ApplicationData,
        }).await?;
        Ok(())
    }

    pub async fn read_normal(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            let message = receive_message_framed(&mut self.framed, None).await?;

            match message {
                Message::Handshake(Handshake::NewSessionTicket(ticket)) => {
                    println!("read_normal: got ticket (ignoring)");
                    // println!("ticket = {:#?}", ticket);
                }
                Message::ApplicationData(data) => {
                    return Ok(data);
                }
                Message::Alert(alert) => {
                    return Err(error!("PhaseThree: Received alert {:?}", alert));
                }
                _ => {
                    return Err(error!("PhaseThree: Received unexpected {}", message.name()));
                }
            }
        }
    }
}
