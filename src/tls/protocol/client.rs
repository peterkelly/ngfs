use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use bytes::{BytesMut, Buf};
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::rand::{SystemRandom, SecureRandom};
use super::stream::{
    Encryption,
    encrypt_record,
    PlaintextStream,
    EncryptedStream,
};
use super::super::helpers::{
    Ciphers,
    TrafficSecrets,
    get_server_hello_x25519_shared_secret,
    get_derived_prk,
    get_zero_prk,
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
    TLSOutputPlaintext,
    MAX_PLAINTEXT_RECORD_SIZE,
};
use super::super::types::alert::{
    Alert,
    AlertLevel,
    AlertDescription,
};
use super::super::error::{
    TLSError,
};
use crate::util::util::vec_with_len;
use crate::crypto::crypt::HashAlgorithm;
use crate::util::binary::{BinaryReader, BinaryWriter};
use crate::formats::asn1;
use crate::crypto::x509;

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
    protocol_names: &[&str],
) -> Result<ClientHello, TLSError> {
    let mut random: [u8; 32] = Default::default();
    let mut session_id: [u8; 32] = Default::default();
    SystemRandom::new().fill(&mut random).map_err(|_| TLSError::RandomFillFailed)?;
    SystemRandom::new().fill(&mut session_id).map_err(|_| TLSError::RandomFillFailed)?;

    let cipher_suites = vec![
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        // CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::Unknown(0x00ff),
    ];

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
        Extension::ApplicationLayerProtocolNegotiation(
            protocol_names.iter()
                .map(|n| ProtocolName { data: Vec::from(n.as_bytes()) })
                .collect::<Vec<ProtocolName>>()),
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
        random,
        legacy_session_id: Vec::from(session_id),
        cipher_suites,
        legacy_compression_methods: vec![0],
        extensions,
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
) -> Result<(), TLSError> {
    let finished_key = derive_secret(
        hash_alg,
        &stream.encryption.traffic_secrets.client.raw,
        b"finished", &[])?;
    let verify_data = hash_alg.hmac_sign(&finished_key, new_transcript_hash)?;
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
) -> Result<(), TLSError> {
    let client_cert = x509::Certificate::from_bytes(client_cert_data)
        .map_err(|_| TLSError::InvalidCertificate)?;
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
    send_handshake(&handshake, Some(transcript), stream).await?;
    let thash: Vec<u8> = hash_alg.hash(transcript);
    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);
    let signature = rsa_sign(client_key_data, &verify_input, signature_scheme, rng)?;
    let handshake = Handshake::CertificateVerify(CertificateVerify {
        algorithm: signature_scheme,
        signature,
    });
    send_handshake(&handshake, Some(transcript), stream).await?;
    Ok(())
}

async fn send_handshake(
    handshake: &Handshake,
    transcript: Option<&mut Vec<u8>>,
    stream: &mut EncryptedStream,
) -> Result<(), TLSError> {
    let mut conn_to_send = BytesMut::new();


    let mut writer = BinaryWriter::new();
    writer.write_item(handshake).map_err(|_| TLSError::MessageEncodingFailed)?;
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
    stream.send_direct(&conn_to_send).await.map_err(|e| TLSError::IOError(e.kind()))?;

    Ok(())
}

fn verify_certificate(ca_raw: &[u8], target_raw: &[u8]) -> Result<(), TLSError> {
    let ca_cert = x509::Certificate::from_bytes(ca_raw)
        .map_err(|_| TLSError::InvalidCertificate)?;

    let mut target_reader = BinaryReader::new(target_raw);
    let target_item = asn1::reader::read_item(&mut target_reader)
        .map_err(|_| TLSError::InvalidCertificate)?;
    let elements = target_item.as_exact_sequence(3)
        .map_err(|_| TLSError::InvalidCertificate)?;

    /*let tbs_certificate = */x509::TBSCertificate::from_asn1(&elements[0])
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
    let mut verify_input: Vec<u8> = vec![0x20; 64];
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

struct HashAndHandshake {
    hash: Vec<u8>,
    handshake: Handshake,
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
            transcript,
            config,
        }
    }

    async fn receive_handshake(
        &mut self,
        stream: &mut EncryptedStream,
    ) -> Result<Handshake, TLSError> {
        match stream.receive_message(Some(&mut self.transcript)).await? {
            Some(Message::Handshake(hs)) => Ok(hs),
            Some(message) => Err(TLSError::UnexpectedMessage(message.name())),
            None => Err(TLSError::UnexpectedEOF),
        }
    }

    async fn receive_hash_and_handshake(
        &mut self,
        stream: &mut EncryptedStream,
    ) -> Result<HashAndHandshake, TLSError> {
        let hash = stream.encryption.ciphers.hash_alg.hash(&self.transcript);
        let handshake = self.receive_handshake(stream).await?;
        Ok(HashAndHandshake {
            hash,
            handshake,
        })
    }
}

async fn receive_plaintext_handshake(
    stream: &mut PlaintextStream,
    transcript: &mut Vec<u8>,
) -> Result<Option<Handshake>, TLSError> {
    match stream.receive_plaintext_message(transcript).await? {
        Some(Message::Handshake(hs)) => Ok(Some(hs)),
        Some(message) => Err(TLSError::UnexpectedMessage(message.name())),
        None => Err(TLSError::UnexpectedEOF),
    }
}

async fn receive_server_hello(
    stream: &mut PlaintextStream,
    transcript: &mut Vec<u8>,
) -> Result<ServerHello, TLSError> {
    let handshake = receive_plaintext_handshake(stream, transcript).await?;
    match handshake {
        Some(Handshake::ServerHello(v)) => Ok(v),
        Some(handshake) => Err(TLSError::UnexpectedMessage(handshake.name())),
        None => Err(TLSError::UnexpectedEOF),
    }
}

async fn write_plaintext_handshake(
    writer: &mut (impl AsyncWrite + Unpin),
    handshake: &Handshake,
    transcript: &mut Vec<u8>,
) -> Result<(), TLSError> {
    let mut bin_writer = BinaryWriter::new();
    bin_writer.write_item(handshake).map_err(|_| TLSError::MessageEncodingFailed)?;
    let fragment_vec = Vec::<u8>::from(bin_writer);

    let record = TLSOutputPlaintext {
        content_type: ContentType::Handshake,
        legacy_record_version: 0x0301,
        fragment: &fragment_vec,
    };

    transcript.extend_from_slice(record.fragment);
    let mut encoded = BytesMut::new();
    record.encode(&mut encoded);
    writer.write_all(&encoded).await.map_err(|e| TLSError::IOError(e.kind()))?;
    Ok(())
}

pub async fn establish_connection<T: 'static>(
    transport: Pin<Box<T>>,
    config: ClientConfig,
    protocol_names: &[&str],
) -> Result<EstablishedConnection, TLSError>
    where T : AsyncRead + AsyncWrite + Send
{
    let private_key = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
        .map_err(|_| TLSError::EphemeralPrivateKeyGenerationFailed)?;
    let public_key = private_key.compute_public_key()
        .map_err(|_| TLSError::ComputePublicKeyFailed)?;
    let client_hello = make_client_hello(public_key.as_ref(), config.server_name.as_ref(),
                                         protocol_names)?;
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
) -> Result<HandshakeEncryption, TLSError> {
    let ciphers = Ciphers::from_server_hello(server_hello)?;
    let secret = get_server_hello_x25519_shared_secret(private_key, server_hello)
        .ok_or(TLSError::GetSharedSecretFailed)?;
    let prk = get_derived_prk(ciphers.hash_alg, &get_zero_prk(ciphers.hash_alg), &secret)?;
    let traffic_secrets = TrafficSecrets::derive_from(&ciphers, transcript, &prk, "hs")?;
    Ok(HandshakeEncryption { traffic_secrets, ciphers, prk })
}

struct ServerMessages {
    #[allow(dead_code)]
    encrypted_extensions: EncryptedExtensions,
    #[allow(dead_code)]
    certificate_request: Option<CertificateRequest>,
    certificate: Option<Certificate>,
    certificate_verify: Option<(CertificateVerify, Vec<u8>)>,
    finished: (Finished, Vec<u8>),
}

async fn receive_server_messages(
    conn: &mut EncryptedHandshake,
    stream: &mut EncryptedStream,
) -> Result<ServerMessages, TLSError> {
    let mut hh: HashAndHandshake;

    hh = conn.receive_hash_and_handshake(stream).await?;
    let encrypted_extensions = match hh.handshake {
        Handshake::EncryptedExtensions(v) => v,
        _ => return Err(TLSError::UnexpectedMessage(hh.handshake.name())),
    };

    hh = conn.receive_hash_and_handshake(stream).await?;
    let certificate_request = match hh.handshake {
        Handshake::CertificateRequest(v) => {
            hh = conn.receive_hash_and_handshake(stream).await?;
            Some(v)
        }
        _ => {
            None
        }
    };

    let certificate = match hh.handshake {
        Handshake::Certificate(v) => {
            hh = conn.receive_hash_and_handshake(stream).await?;
            Some(v)
        }
        _ => {
            None
        }
    };

    let certificate_verify = match hh.handshake {
        Handshake::CertificateVerify(v) => {
            let r = Some((v, hh.hash));
            hh = conn.receive_hash_and_handshake(stream).await?;
            r
        }
        _ => {
            None
        }
    };

    let finished = match hh.handshake {
        Handshake::Finished(v) => (v, hh.hash),
        _ => return Err(TLSError::UnexpectedMessage(hh.handshake.name())),
    };

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
) -> Result<Encryption, TLSError> {
    let ciphers_copy = stream.encryption.ciphers.clone();
    let secrets_copy = TrafficSecrets {
        client: stream.encryption.traffic_secrets.client.clone(),
        server: stream.encryption.traffic_secrets.server.clone(),
    };


    let ciphers = &ciphers_copy;
    let secrets = &secrets_copy;

    let input_psk: &[u8] = &vec_with_len(ciphers.hash_alg.byte_len());
    let new_prk = get_derived_prk(ciphers.hash_alg, prk, input_psk)
        .map_err(TLSError::Internal)?;

    let application_secrets = TrafficSecrets::derive_from(ciphers, &conn.transcript, &new_prk, "ap")?;
    // let mut bad_finished = Finished { verify_data: finished.verify_data.clone() };
    // bad_finished.verify_data.push(0);
    let (finished, finished_thash) = &sm.finished;
    verify_finished(ciphers.hash_alg, &secrets.server, finished_thash, finished)?;

    let first_cert_entry : &CertificateEntry = match &sm.certificate {
        Some(certificate) => {
            match certificate.certificate_list.get(0) {
                Some(v) => v,
                None => {
                    return Err(TLSError::EmptyCertificatList);
                }
            }
        }
        None => {
            return Err(TLSError::MissingCertificateMessage);
        }
    };

    let server_cert_raw: &[u8] = &first_cert_entry.data;
    let server_cert: &x509::Certificate = &first_cert_entry.certificate;

    let ca_cert: &[u8] = match &conn.config.server_auth {
        ServerAuth::None => return Err(TLSError::CACertificateUnavailable),
        ServerAuth::CertificateAuthority(v) => v,
        ServerAuth::SelfSigned => server_cert_raw,
    };
    verify_certificate(ca_cert, server_cert_raw)?;

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
            return Err(TLSError::MissingCertificateVerifyMessage);
        }
    }

    // FIXME: Don't hard-code SignatureScheme
    match &conn.config.client_auth {
        ClientAuth::Certificate { cert, key } => {
            let client_cert = cert;
            let client_key = key;

            let rng = SystemRandom::new();
            send_client_certificate(
                ciphers.hash_alg, // hash_alg: HashAlgorithm,
                &mut conn.transcript, // transcript: &mut Vec<u8>,
                client_cert, // client_cert_data: &[u8],
                client_key, // client_key_data: &[u8],
                SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                &rng,
                stream,
            ).await?;
        }
        ClientAuth::None => {
        }
    }

    let new_thash: Vec<u8> = ciphers.hash_alg.hash(&conn.transcript); // TODO: use conn.new_thash?

    // let mut bad_new_thash = new_thash.clone();
    // bad_new_thash.push(0);
    send_finished(
        ciphers.hash_alg,
        &new_thash,
        stream).await?;

    Ok(Encryption {
        traffic_secrets: application_secrets,
        ciphers: ciphers.clone(),
    })
}

enum ReadState {
    Active,
    Eof,
    Error(TLSError),
}

enum WriteState {
    Active,
    InShutdown,
    Error(TLSError),
}

pub struct EstablishedConnection {
    stream: EncryptedStream,
    incoming_decrypted: BytesMut,
    outgoing_encrypted: BytesMut,
    read_state: ReadState,
    write_state: WriteState,
}

impl EstablishedConnection {
    fn new(stream: EncryptedStream) -> Self {
        EstablishedConnection {
            stream,
            incoming_decrypted: BytesMut::new(),
            outgoing_encrypted: BytesMut::new(),
            read_state: ReadState::Active,
            write_state: WriteState::Active,
        }
    }

    fn append_record(&mut self, data: &[u8], content_type: ContentType) -> Result<(), TLSError> {
        match encrypt_record(
            &mut self.outgoing_encrypted,
            data,
            content_type,
            &self.stream.encryption.traffic_secrets.client,
            self.stream.client_sequence_no,
            None,
        ) {
            Ok(()) => {
                self.stream.client_sequence_no += 1;
                Ok(())
            }
            Err(e) => {
                self.write_state = WriteState::Error(e.clone());
                Err(e)
            }
        }
    }

    fn append_application_data(&mut self, data: &[u8]) -> Result<(), TLSError> {
        self.append_record(data, ContentType::ApplicationData)
    }

    fn append_close_notify(&mut self) -> Result<(), TLSError> {
        let alert = Alert {
            level: AlertLevel::Warning,
            description: AlertDescription::CloseNotify,
        };

        let alert_data: &[u8] = &[
            alert.level.to_raw(),
            alert.description.to_raw(),
        ];

        self.append_record(alert_data, ContentType::Alert)
    }


    fn poll_drain_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TLSError>> {
        while !self.outgoing_encrypted.is_empty() {
            match AsyncWrite::poll_write(Pin::new(&mut self.stream.plaintext.inner), cx, &self.outgoing_encrypted) {
                Poll::Ready(Ok(w)) => {
                    self.outgoing_encrypted.advance(w);
                }
                Poll::Ready(Err(e)) => {
                    let tls_e: TLSError = TLSError::IOError(e.kind());
                    self.write_state = WriteState::Error(tls_e.clone());
                    return Poll::Ready(Err(tls_e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }

        match AsyncWrite::poll_flush(Pin::new(&mut self.stream.plaintext.inner), cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(TLSError::IOError(e.kind()))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_fill_incoming(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TLSError>> {
        if self.incoming_decrypted.remaining() > 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.stream.poll_receive_encrypted_message(cx, None) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(Some(Message::Handshake(Handshake::NewSessionTicket(_))))) => {
                    // ignore; repeat loop
                }
                Poll::Ready(Ok(Some(Message::ApplicationData(data)))) => {
                    self.incoming_decrypted.extend_from_slice(&data);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(Message::Alert(alert)))) => {
                    if alert.description == AlertDescription::CloseNotify {
                        self.read_state = ReadState::Eof;
                        return Poll::Ready(Ok(()));
                    }
                    let e = TLSError::UnexpectedAlert(alert);
                    self.read_state = ReadState::Error(e.clone());
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(Some(message))) => {
                    let e = TLSError::UnexpectedMessage(message.name());
                    self.read_state = ReadState::Error(e.clone());
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(None)) => {
                    let e = TLSError::UnexpectedEOF;
                    self.read_state = ReadState::Error(e.clone());
                    return Poll::Ready(Err(e));
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
    ) -> Poll<Result<(), io::Error>> {
        // Check for existing error condition
        match &self.read_state {
            ReadState::Eof => return Poll::Ready(Ok(())),
            ReadState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            ReadState::Active => (),
        }
        let direct = Pin::into_inner(self);
        match direct.poll_fill_incoming(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => {
                let amt = std::cmp::min(direct.incoming_decrypted.remaining(), buf.remaining());
                buf.put_slice(&direct.incoming_decrypted[0..amt]);
                direct.incoming_decrypted.advance(amt);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for EstablishedConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<Result<usize, io::Error>> {
        // Check for existing error condition
        match &self.write_state {
            WriteState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            WriteState::InShutdown => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            WriteState::Active => (), // ok, continue
        }


        let direct = Pin::into_inner(self);
        match direct.poll_drain_encrypted(cx) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => (),
        }

        let max_write: usize = MAX_PLAINTEXT_RECORD_SIZE;
        let amt = std::cmp::min(buf.len(), max_write);

        match direct.append_application_data(&buf[0..amt]) {
            Ok(()) => Poll::Ready(Ok(amt)),
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        // Check for existing error condition
        match &self.write_state {
            WriteState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            WriteState::InShutdown => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            WriteState::Active => (), // ok, continue
        }

        let direct = Pin::into_inner(self);
        match direct.poll_drain_encrypted(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>
    ) -> Poll<Result<(), io::Error>> {
        let mut direct = Pin::into_inner(self);

        // Check for existing error condition
        match &direct.write_state {
            WriteState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            WriteState::InShutdown => (), // ok, continue
            WriteState::Active => {
                match direct.append_close_notify() {
                    Err(e) => {
                        return Poll::Ready(Err(e.into()));
                    }
                    Ok(()) => {
                        // Record the fact that shutdown() has been requested. This will cause
                        // future calls to write() or flush() will fail.
                        direct.write_state = WriteState::InShutdown;
                    }
                }
            }
        }

        // Wait until any remaining data has been sent; we don't want to shut down the connection
        // until this has been sent.
        match direct.poll_drain_encrypted(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(())) => (),
        };

        // There is no remaining data to be sent. Perform the actual shutdown.
        match Pin::new(&mut direct.stream.plaintext.inner).poll_shutdown(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => (),
        }

        // Shutdown is now complete. Cause any future calls to shutdown() to fail. Note that
        // read() and write() will already fail since we transitioned to the InShutdown state.
        direct.write_state = WriteState::Error(TLSError::IOError(io::ErrorKind::BrokenPipe));
        Poll::Ready(Ok(()))
    }
}
