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
use super::super::super::result::GeneralError;
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

struct ClientConn {
    to_send: Vec<u8>,
}

impl ClientConn {
    fn new() -> Self {
        ClientConn {
            to_send: Vec::new(),
        }
    }

    fn append_encrypted(
        &mut self,
        mut data: Vec<u8>,
        content_type: ContentType,
        traffic_secret: &EncryptionKey,
        client_sequence_no: u64,
        transcript: Option<&mut Vec<u8>>,
    ) -> Result<(), TLSError> {
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
            fragment: data,
        };
        let output_record_bytes = output_record.to_vec();
        // match transcript {
        //     Some(transcript) => transcript.extend_from_slice(&output_record_bytes),
        //     None => (),
        // }
        self.to_send.extend_from_slice(&output_record_bytes);
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////

enum Endpoint {
    Client,
    Server,
}

fn send_finished(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    new_transcript_hash: &[u8],
    conn: &mut ClientConn,
    sequence_no: &mut u64,
) -> Result<(), Box<dyn Error>> {
    let finished_key = derive_secret(hash_alg, &encryption_key.raw, b"finished", &[])?;
    let verify_data = hash_alg.hmac_sign(&finished_key, &new_transcript_hash)?;
    let client_finished = Handshake::Finished(Finished { verify_data });
    send_handshake(encryption_key, conn, *sequence_no, &client_finished, None)?;
    *sequence_no += 1;
    Ok(())
}

fn send_client_certificate(
    hash_alg: HashAlgorithm,
    encryption_key: &EncryptionKey,
    conn: &mut ClientConn,
    sequence_no: &mut u64,
    transcript: &mut Vec<u8>,
    client_cert_data: &[u8],
    client_key_data: &[u8],
    signature_scheme: SignatureScheme,
    rng: &dyn ring::rand::SecureRandom,
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
    send_handshake(encryption_key, conn, *sequence_no, &handshake, Some(transcript))?;
    println!("new transcript len = {}", transcript.len());
    *sequence_no += 1;

    let thash: Vec<u8> = hash_alg.hash(transcript);

    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);

    let signature = rsa_sign(client_key_data, &verify_input, signature_scheme, rng)?;


    let handshake = Handshake::CertificateVerify(CertificateVerify {
        algorithm: signature_scheme,
        signature: signature,
    });
    send_handshake(encryption_key, conn, *sequence_no, &handshake, Some(transcript))?;
    *sequence_no += 1;

    Ok(())
}

fn send_handshake(
    encryption_key: &EncryptionKey,
    conn: &mut ClientConn,
    sequence_no: u64,
    handshake: &Handshake,
    transcript: Option<&mut Vec<u8>>,
) -> Result<(), Box<dyn Error>> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    conn.append_encrypted(
        finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &encryption_key,        // traffic_secret
        sequence_no,            // sequence_no
        transcript,
    )?;

    Ok(())
}

fn verify_certificate(ca_raw: &[u8], target_raw: &[u8]) -> Result<(), TLSError> {
    let ca_cert = x509::Certificate::from_bytes(&ca_raw).map_err(|_| TLSError::InvalidCertificate)?;

    let mut target_reader = BinaryReader::new(&target_raw);
    let target_item = asn1::reader::read_item(&mut target_reader).map_err(|_| TLSError::InvalidCertificate)?;
    let elements = target_item.as_exact_sequence(3).map_err(|_| TLSError::InvalidCertificate)?;

    let tbs_certificate = x509::TBSCertificate::from_asn1(&elements[0]).map_err(|_| TLSError::InvalidCertificate)?;
    let signature_algorithm = x509::AlgorithmIdentifier::from_asn1(&elements[1]).map_err(|_| TLSError::InvalidCertificate)?;
    let signature_value_bit_string = elements[2].as_bit_string().map_err(|_| TLSError::InvalidCertificate)?;
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

pub struct ReceiveRecord<'a, T : AsyncRead + Unpin> {
    conn: &'a mut PendingConnection,
    reader: &'a mut T,
    incoming_data: Vec<u8>,
}

impl<'a, T : AsyncRead + Unpin> ReceiveRecord<'a, T> {
    fn new(conn: &'a mut PendingConnection, reader: &'a mut T) -> ReceiveRecord<'a, T> {
        ReceiveRecord {
            conn: conn,
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

            println!("Reading fragment of len {}", length);

            if self.incoming_data.len() >= 5 + length {
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
                println!("ReceiveRecord::poll(): inner returned error");
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready(Ok(())) => {
                println!("ReceiveRecord::poll(): inner is ready");
                let new_filled = recv_buf.filled().len();
                println!("data = {}", &BinaryData(recv_buf.filled()));
                let extra = new_filled - old_filled;
                // TODO: if extra is 0, either we have unexpected end of data or the connection
                // has been closed. RecordReceiver should actually return Option<Record> so that
                // it can use None to indicate there are no more records.
                println!("# of bytes read = {}", extra);
                // self.ok_done()
                self.incoming_data.extend_from_slice(recv_buf.filled());

                println!("want = {}, have = {}", want, self.incoming_data.len());
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

pub struct PendingConnection {
    transcript: Vec<u8>,
    config: ClientConfig,
    client_sequence_no: u64,
    server_sequence_no: u64,
}

impl PendingConnection {
    pub fn new(
        config: ClientConfig,
    ) -> Self {
        PendingConnection {
            transcript: Vec::new(),
            config: config,
            client_sequence_no: 0,
            server_sequence_no: 0,
        }
    }

    fn receive_record<'a, T : AsyncRead + Unpin>(
        &'a mut self,
        reader: &'a mut T,
    ) -> ReceiveRecord<'a, T> {
        ReceiveRecord::new(self, reader)
    }

    async fn receive_record_ignore_cc(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<TLSOwnedPlaintext, Box<dyn Error>> {
        loop {
            let record = self.receive_record(reader).await?;
            if record.content_type != ContentType::ChangeCipherSpec {
                return Ok(record)
            }
        }
    }

    async fn receive_message(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        encryption: &AEncryption,
    ) -> Result<Message, Box<dyn Error>> {
        let plaintext = self.receive_record_ignore_cc(reader).await?;
        // TODO: Support records containing multiple handshake messages
        // TODO: Cater for alerts
        let (message, message_raw) = decrypt_message(
            self.server_sequence_no,
            &encryption.traffic_secrets.server,
            &plaintext.raw)?;
        self.server_sequence_no += 1;
        self.transcript.extend_from_slice(&message_raw);
        // Ok((message, message_raw))

        Ok(message)
    }

    async fn receive_plaintext_message(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin)
    ) -> Result<Message, Box<dyn Error>> {
        let plaintext = self.receive_record_ignore_cc(reader).await?;
        // TODO: Support records containing multiple handshake messages
        self.transcript.extend_from_slice(&plaintext.fragment);
        let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)?;
        Ok(message)
    }

    async fn receive_handshake(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
        encryption: &AEncryption,
    ) -> Result<Handshake, Box<dyn Error>> {
        let message = self.receive_message(reader, encryption).await?;
        match message {
            Message::Handshake(hs) => {
                Ok(hs)
            }
            _ => {
                Err(GeneralError::new(format!("Expected a handshake, got {:?}", message.content_type())))
            }
        }
    }

    async fn receive_plaintext_handshake(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin)
    ) -> Result<Handshake, Box<dyn Error>> {
        let message = self.receive_plaintext_message(reader).await?;
        match message {
            Message::Handshake(hs) => {
                Ok(hs)
            }
            _ => {
                Err(GeneralError::new(format!("Expected a handshake, got {:?}", message.content_type())))
            }
        }
    }

    async fn write_plaintext_handshake(
        &mut self,
        writer: &mut (impl AsyncWrite + Unpin),
        handshake: &Handshake,
    ) -> Result<(), Box<dyn Error>> {
        let record = handshake_to_record(handshake)?;
        self.transcript.extend_from_slice(&record.fragment);
        writer.write_all(&record.to_vec()).await?;
        Ok(())
    }

    async fn receive_server_hello(
        &mut self,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<ServerHello, Box<dyn Error>> {
        let handshake = self.receive_plaintext_handshake(reader).await?;
        match handshake {
            Handshake::ServerHello(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected ServerHello, got {}", handshake.name())))
        }
    }
}

pub async fn establish_connection<T>(
    mut conn: PendingConnection,
    mut stream: T,
    client_hello: &Handshake,
    private_key: EphemeralPrivateKey,
) -> Result<EstablishedConnection<T>, Box<dyn Error>>
    where T : AsyncRead + AsyncWrite + Unpin
{
    conn.write_plaintext_handshake(&mut stream, client_hello).await?;
    let server_hello = conn.receive_server_hello(&mut stream).await?;


    let henc = get_handshake_encryption(&conn.transcript, &server_hello, private_key)?;
    let prk = henc.prk;

    let encryption = AEncryption {
        traffic_secrets: henc.traffic_secrets,
        ciphers: henc.ciphers,
    };

    let sm = receive_server_messages(&mut conn, &mut stream, &encryption).await?;
    let mut output = ClientConn::new();
    let p2 = do_phase_two(&mut conn, &prk, &sm, &mut output, &encryption)?;


    stream.write_all(&output.to_send).await?;
    println!("After  send_finished()");

    conn.client_sequence_no = 0;
    conn.server_sequence_no = 0;

    Ok(EstablishedConnection {
        inner: conn,
        encryption: p2,
        stream: stream,
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
        .ok_or_else(|| GeneralError::new("Cannot get shared secret"))?;
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
    conn: &mut PendingConnection,
    reader: &mut (impl AsyncRead + Unpin),
    encryption: &AEncryption,
) -> Result<ServerMessages, Box<dyn Error>> {
    // TODO: Allow some of these to be absent depending on the config
    let handshake = conn.receive_handshake(reader, encryption).await?;
    let encrypted_extensions = match handshake {
        Handshake::EncryptedExtensions(v) => v,
        _ => return Err(GeneralError::new(format!("Expected EncryptedExtensions, got {}", handshake.name()))),
    };
    println!("Phase two: Got encrypted_extensions");

    let handshake = conn.receive_handshake(reader, encryption).await?;
    let certificate_request = match handshake {
        Handshake::CertificateRequest(v) => Some(v),
        _ => return Err(GeneralError::new(format!("Expected CertificateRequest, got {}", handshake.name()))),
    };
    println!("Phase two: Got certificate_request");

    let handshake = conn.receive_handshake(reader, encryption).await?;
    let certificate = match handshake {
        Handshake::Certificate(v) => Some(v),
        _ => return Err(GeneralError::new(format!("Expected Certificate, got {}", handshake.name()))),
    };

    println!("Phase two: Got certificate");
    let certificate_verify_thash = encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake(reader, encryption).await?;
    let certificate_verify = match handshake {
        Handshake::CertificateVerify(v) => Some((v, certificate_verify_thash)),
        _ => return Err(GeneralError::new(format!("Expected CertificateVerify, got {}", handshake.name()))),
    };

    println!("Phase two: Got certificate_verify");
    let finished_thash = encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake(reader, encryption).await?;
    let finished = match handshake {
        Handshake::Finished(v) => (v, finished_thash),
        _ => return Err(GeneralError::new(format!("Expected Finished, got {}", handshake.name()))),
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

fn do_phase_two(
    conn: &mut PendingConnection,
    prk: &[u8],
    sm: &ServerMessages,
    output: &mut ClientConn,
    encryption: &AEncryption,
) -> Result<AEncryption, Box<dyn Error>> {
    let ciphers = &encryption.ciphers;
    let secrets = &encryption.traffic_secrets;

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
                    return Err(GeneralError::new("Server sent an empty certificate list"));
                }
            }
        }
        None => {
            return Err(GeneralError::new("Server did not send a Certificate message"));
        }
    };

    let server_cert_raw: &[u8] = &first_cert_entry.data;
    let server_cert: &x509::Certificate = &first_cert_entry.certificate;

    let ca_cert: &[u8] = match &conn.config.server_auth {
        ServerAuth::CertificateAuthority(v) => v,
        ServerAuth::None => {
            return Err(GeneralError::new("No CA certificate available"));
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
            return Err(GeneralError::new("Server did not send CertificateVerify message"));
        }
    }
    println!("After  verify_transcript()");


    // let mut output = ClientConn::new();
    // FIXME: Don't hard-code SignatureScheme
    match &conn.config.client_auth {
        ClientAuth::Certificate { cert, key } => {
            let client_cert = cert;
            let client_key = key;

            let rng = ring::rand::SystemRandom::new();
            println!("Before send_client_certificate()");
            send_client_certificate(
                ciphers.hash_alg, // hash_alg: HashAlgorithm,
                &secrets.client, // encryption_key: &EncryptionKey,
                output, // conn: &mut ClientConn,
                &mut conn.client_sequence_no, // sequence_no: &mut u64,
                &mut conn.transcript, // transcript: &mut Vec<u8>,
                client_cert, // client_cert_data: &[u8],
                client_key, // client_key_data: &[u8],
                SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                &rng,
            )?;

            println!("After  send_client_certificate()");
        }
        ClientAuth::None => {
        }
    }

    let new_thash: Vec<u8> = ciphers.hash_alg.hash(&conn.transcript); // TODO: use conn.new_thash?

    // let mut bad_new_thash = new_thash.clone();
    // bad_new_thash.push(0);
    println!("Before send_finished()");
    send_finished(ciphers.hash_alg, &secrets.client, &new_thash, output, &mut conn.client_sequence_no)?;

    Ok(AEncryption {
        traffic_secrets: application_secrets,
        ciphers: ciphers.clone(),
    })
}

pub struct EstablishedConnection<T> where T : AsyncRead + AsyncWrite + Unpin {
    inner: PendingConnection,
    encryption: AEncryption,
    stream: T,
}

impl<T> EstablishedConnection<T> where T : AsyncRead + AsyncWrite + Unpin {
    pub async fn write_normal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut conn = ClientConn::new();
        conn.append_encrypted(
            data.to_vec(),
            ContentType::ApplicationData,
            &self.encryption.traffic_secrets.client,
            self.inner.client_sequence_no,
            None,
        )?;
        self.inner.client_sequence_no += 1;
        self.stream.write_all(&conn.to_send).await?;
        Ok(())
    }

    pub async fn read_normal(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            let message = self.inner.receive_message(&mut self.stream, &self.encryption).await?;

            match message {
                Message::Handshake(Handshake::NewSessionTicket(ticket)) => {
                    println!("read_normal: got ticket (ignoring)");
                    // println!("ticket = {:#?}", ticket);
                }
                Message::ApplicationData(data) => {
                    return Ok(data);
                }
                Message::Alert(alert) => {
                    return Err(GeneralError::new(
                        format!("PhaseThree: Received alert {:?}", alert)));
                }
                _ => {
                    return Err(GeneralError::new(
                        format!("PhaseThree: Received unexpected {}", message.name())));
                }
            }
        }
    }
}

fn handshake_to_record(handshake: &Handshake) -> Result<TLSOutputPlaintext, Box<dyn Error>> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;

    let output_record = TLSOutputPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: Vec::<u8>::from(writer),
    };
    Ok(output_record)
}
