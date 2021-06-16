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
use futures::stream::StreamExt;
use futures::sink::SinkExt;
use bytes::{BytesMut, Buf};
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::{SystemRandom, SecureRandom};
use super::stream::{
    Encryption,
    encrypt_record,
    PlaintextStream,
    EncryptedStream,
    AsyncReadWrite,
};
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
    ClientHello,
    CipherSuite,
};
use super::super::types::extension::{
    ECPointFormat,
    Extension,
    KeyShareEntry,
    NamedCurve,
    NamedGroup,
    ProtocolName,
    PskKeyExchangeMode,
    ServerName,
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
    SelfSigned,
}

pub enum ClientAuth {
    None,
    Certificate { cert: Vec<u8>, key: Vec<u8> },
}

pub struct ClientConfig {
    pub client_auth: ClientAuth,
    pub server_auth: ServerAuth,
    pub server_name: Option<String>,
}

pub fn make_client_hello(
    my_public_key_bytes: &[u8],
    server_name: Option<&String>,
) -> Result<ClientHello, TLSError> {
    let mut random: [u8; 32] = Default::default();
    let mut session_id: [u8; 32] = Default::default();
    SystemRandom::new().fill(&mut random).map_err(|_| TLSError::RandomFillFailed)?;
    SystemRandom::new().fill(&mut session_id).map_err(|_| TLSError::RandomFillFailed)?;

    let mut cipher_suites = Vec::<CipherSuite>::new();
    cipher_suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
    cipher_suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
    // cipher_suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    cipher_suites.push(CipherSuite::Unknown(0x00ff));

    let mut extensions = vec![
        Extension::ECPointFormats(vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedPrime,
            ECPointFormat::ANSIX962CompressedChar2]),
        Extension::SupportedGroups(vec![
            NamedCurve::X25519,
            NamedCurve::Secp256r1,
            NamedCurve::X448,
            NamedCurve::Secp521r1,
            NamedCurve::Secp384r1]),
        Extension::NextProtocolNegotiation(vec![]),
        Extension::ApplicationLayerProtocolNegotiation(vec![
            ProtocolName { data: Vec::from("h2".as_bytes()) },
            ProtocolName { data: Vec::from("http/1.1".as_bytes()) },
            ]),
        Extension::EncryptThenMac,
        Extension::ExtendedMasterSecret,
        Extension::PostHandshakeAuth,
        Extension::SignatureAlgorithms(vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::Ed25519,
            SignatureScheme::Ed448,
            SignatureScheme::RsaPssPssSha256,
            SignatureScheme::RsaPssPssSha384,
            SignatureScheme::RsaPssPssSha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512]),
        Extension::SupportedVersions(vec![2, 3, 4]),
        Extension::PskKeyExchangeModes(vec![PskKeyExchangeMode::PskDheKe]),
        Extension::KeyShareClientHello(vec![
            KeyShareEntry {
                group: NamedGroup::X25519,
                key_exchange: Vec::from(my_public_key_bytes),
            }])
    ];
    if let Some(server_name) = server_name {
        extensions.push(Extension::ServerName(vec![ServerName::HostName(String::from(server_name))]));
    }

    Ok(ClientHello {
        legacy_version: 0x0303,
        random: random,
        legacy_session_id: Vec::from(session_id),
        cipher_suites: cipher_suites,
        legacy_compression_methods: vec![0],
        extensions: extensions,
    })
}

////////////////////////////////////////////////////////////////////////////////////////////////////

enum Endpoint {
    Client,
    Server,
}

async fn send_finished(
    hash_alg: HashAlgorithm,
    new_transcript_hash: &[u8],
    stream: &mut EncryptedStream,
) -> Result<(), Box<dyn Error>> {
    let finished_key = derive_secret(
        hash_alg,
        &stream.encryption.traffic_secrets.client.raw,
        b"finished", &[])?;
    let verify_data = hash_alg.hmac_sign(&finished_key, &new_transcript_hash)?;
    let client_finished = Handshake::Finished(Finished { verify_data });
    send_handshake(&client_finished, None, stream).await?;
    Ok(())
}

async fn send_client_certificate(
    hash_alg: HashAlgorithm,
    transcript: &mut Vec<u8>,
    client_cert_data: &[u8],
    client_key_data: &[u8],
    signature_scheme: SignatureScheme,
    rng: &dyn ring::rand::SecureRandom,
    stream: &mut EncryptedStream,
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
    send_handshake(&handshake, Some(transcript), stream).await?;
    println!("new transcript len = {}", transcript.len());

    let thash: Vec<u8> = hash_alg.hash(transcript);

    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);

    let signature = rsa_sign(client_key_data, &verify_input, signature_scheme, rng)?;


    let handshake = Handshake::CertificateVerify(CertificateVerify {
        algorithm: signature_scheme,
        signature: signature,
    });
    send_handshake(&handshake, Some(transcript), stream).await?;

    Ok(())
}

async fn send_handshake(
    handshake: &Handshake,
    transcript: Option<&mut Vec<u8>>,
    stream: &mut EncryptedStream,
) -> Result<(), Box<dyn Error>> {
    let mut conn_to_send = BytesMut::new();


    let mut writer = BinaryWriter::new();
    writer.write_item(handshake)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    encrypt_record(
        &mut conn_to_send,
        &finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &stream.encryption.traffic_secrets.client,        // traffic_secret
        stream.client_sequence_no, // sequence_no
        transcript,
    )?;

    stream.client_sequence_no += 1;
    stream.send_direct(&conn_to_send).await?;

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

    let parameters: &'static dyn ring::signature::VerificationAlgorithm;
    if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_256_WITH_RSA_ENCRYPTION {
        parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA256;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_384_WITH_RSA_ENCRYPTION {
        parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA384;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_SHA_512_WITH_RSA_ENCRYPTION {
        parameters = &ring::signature::RSA_PKCS1_2048_8192_SHA512;
    }
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_ECDSA_WITH_SHA256 {
        parameters = &ring::signature::ECDSA_P256_SHA256_ASN1;
    }
    else {
        return Err(TLSError::UnsupportedCertificateSignatureAlgorithm);
    }

    let ca_public_key_info = &ca_cert.tbs_certificate.subject_public_key_info;
    let ca_public_key = ring::signature::UnparsedPublicKey::new(
        parameters,
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

    async fn receive_handshake_est(
        &mut self,
        stream: &mut EncryptedStream,
    ) -> Result<Handshake, Box<dyn Error>> {
        match stream.receive_message(Some(&mut self.transcript)).await? {
            Some(Message::Handshake(hs)) => Ok(hs),
            Some(message) => Err(error!("Expected a handshake, got {:?}", message.content_type())),
            None => Err(error!("Expected a handshake, got EOF")),
        }
    }

}

async fn receive_plaintext_handshake(
    stream: &mut PlaintextStream,
    transcript: &mut Vec<u8>,
) -> Result<Option<Handshake>, Box<dyn Error>> {
    match stream.receive_plaintext_message(transcript).await? {
        Some(Message::Handshake(hs)) => Ok(Some(hs)),
        Some(message) => Err(error!("Expected a handshake, got {:?}", message.content_type())),
        None => Err(error!("Expected a handshake, got EOF")),
    }
}

async fn receive_server_hello(
    stream: &mut PlaintextStream,
    transcript: &mut Vec<u8>,
) -> Result<ServerHello, Box<dyn Error>> {
    let handshake = receive_plaintext_handshake(stream, transcript).await?;
    match handshake {
        Some(Handshake::ServerHello(v)) => Ok(v),
        Some(handshake) => Err(error!("Expected ServerHello, got {}", handshake.name())),
        None => Err(error!("Expected ServerHello, got EOF")),
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

pub async fn establish_connection<T: 'static>(
    transport: T,
    config: ClientConfig,
) -> Result<EstablishedConnection, Box<dyn Error>>
    where T : AsyncRead + AsyncWrite + Unpin
{
    let transport = Box::new(transport);
    let private_key = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
    let public_key = private_key.compute_public_key()?;
    let client_hello = make_client_hello(public_key.as_ref(), config.server_name.as_ref())?;
    let client_hello_handshake = Handshake::ClientHello(client_hello);

    let mut initial_transcript: Vec<u8> = Vec::new();
    let mut plaintext_stream = PlaintextStream::new(transport, BytesMut::new());
    write_plaintext_handshake(
        &mut plaintext_stream.inner,
        &client_hello_handshake,
        &mut initial_transcript).await?;
    let server_hello = receive_server_hello(&mut plaintext_stream, &mut initial_transcript).await?;

    let henc = get_handshake_encryption(&initial_transcript, &server_hello, private_key)?;
    let prk = henc.prk;

    let encryption = Encryption {
        traffic_secrets: henc.traffic_secrets,
        ciphers: henc.ciphers,
    };

    let mut conn = EncryptedHandshake::new(config, initial_transcript);
    let mut enc_stream = EncryptedStream::new(plaintext_stream, encryption);
    let sm = receive_server_messages(&mut conn, &mut enc_stream).await?;
    let p2 = do_phase_two(&mut conn, &prk, &sm, &mut enc_stream).await?;

    enc_stream.client_sequence_no = 0;
    enc_stream.server_sequence_no = 0;
    enc_stream.encryption = p2;

    Ok(EstablishedConnection::new(enc_stream))
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
    stream: &mut EncryptedStream,
) -> Result<ServerMessages, Box<dyn Error>> {
    // TODO: Allow some of these to be absent depending on the config
    let handshake = conn.receive_handshake_est(stream).await?;
    let encrypted_extensions = match handshake {
        Handshake::EncryptedExtensions(v) => v,
        _ => return Err(error!("Expected EncryptedExtensions, got {}", handshake.name())),
    };
    println!("Phase two: Got encrypted_extensions");

    let handshake = conn.receive_handshake_est(stream).await?;
    let certificate_request = match handshake {
        Handshake::CertificateRequest(v) => Some(v),
        _ => return Err(error!("Expected CertificateRequest, got {}", handshake.name())),
    };
    println!("Phase two: Got certificate_request");

    let handshake = conn.receive_handshake_est(stream).await?;
    let certificate = match handshake {
        Handshake::Certificate(v) => Some(v),
        _ => return Err(error!("Expected Certificate, got {}", handshake.name())),
    };

    println!("Phase two: Got certificate");
    let certificate_verify_thash = stream.encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake_est(stream).await?;
    let certificate_verify = match handshake {
        Handshake::CertificateVerify(v) => Some((v, certificate_verify_thash)),
        _ => return Err(error!("Expected CertificateVerify, got {}", handshake.name())),
    };

    println!("Phase two: Got certificate_verify");
    let finished_thash = stream.encryption.ciphers.hash_alg.hash(&conn.transcript);

    let handshake = conn.receive_handshake_est(stream).await?;
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
    stream: &mut EncryptedStream,
) -> Result<Encryption, Box<dyn Error>> {
    let ciphers_copy = stream.encryption.ciphers.clone();
    let secrets_copy = TrafficSecrets {
        client: stream.encryption.traffic_secrets.client.clone(),
        server: stream.encryption.traffic_secrets.server.clone(),
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
        ServerAuth::None => return Err(error!("No CA certificate available")),
        ServerAuth::CertificateAuthority(v) => v,
        ServerAuth::SelfSigned => &server_cert_raw,
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

            let rng = SystemRandom::new();
            println!("Before send_client_certificate()");
            send_client_certificate(
                ciphers.hash_alg, // hash_alg: HashAlgorithm,
                &mut conn.transcript, // transcript: &mut Vec<u8>,
                client_cert, // client_cert_data: &[u8],
                client_key, // client_key_data: &[u8],
                SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                &rng,
                stream,
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
        stream).await?;

    Ok(Encryption {
        traffic_secrets: application_secrets,
        ciphers: ciphers.clone(),
    })
}

pub struct EstablishedConnection {
    stream: EncryptedStream,
    incoming_decrypted: BytesMut,
    read_closed: bool,
    write_closed: bool,
}

impl EstablishedConnection {
    pub fn new(stream: EncryptedStream) -> Self {
        EstablishedConnection {
            stream: stream,
            incoming_decrypted: BytesMut::new(),
            read_closed: false,
            write_closed: false,
        }
    }

    pub async fn write_normal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        self.stream.encrypt_and_send(data, ContentType::ApplicationData).await?;
        Ok(())
    }

    pub fn poll_fill_incoming(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>> {
        if self.incoming_decrypted.remaining() > 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.stream.poll_receive_encrypted_message(cx, None) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Some(Message::Handshake(Handshake::NewSessionTicket(ticket))))) => {
                    println!("poll_fill_incoming: got ticket (ignoring)");
                    // println!("ticket = {:#?}", ticket);
                }
                Poll::Ready(Ok(Some(Message::ApplicationData(data)))) => {
                    self.incoming_decrypted.extend_from_slice(&data);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(Message::Alert(alert)))) => {
                    self.read_closed = true;
                    return Poll::Ready(Err(error!("PhaseThree: Received alert {:?}", alert)));
                }
                Poll::Ready(Ok(Some(message))) => {
                    self.read_closed = true;
                    return Poll::Ready(Err(error!("PhaseThree: Received unexpected {}", message.name())));
                }
                Poll::Ready(Ok(None)) => {
                    self.read_closed = true;
                    return Poll::Ready(Err(error!("PhaseThree: Received unexpected EOF")));
                }
            }
        }
    }
}

impl AsyncRead for EstablishedConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>
    ) -> Poll<Result<(), std::io::Error>> {
        if self.read_closed {
            return Poll::Ready(
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    error!("Read end is closed"))));
        }
        let direct = Pin::into_inner(self);
        match direct.poll_fill_incoming(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                Poll::Ready(
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        error!("{}", e))))
            }
            Poll::Ready(Ok(())) => {
                let amt = std::cmp::min(direct.incoming_decrypted.remaining(), buf.remaining());
                buf.put_slice(&direct.incoming_decrypted[0..amt]);
                direct.incoming_decrypted.advance(amt);
                Poll::Ready(Ok(()))
            }
        }
    }
}
