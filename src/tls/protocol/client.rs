use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use bytes::{BytesMut, Buf};
use ring::agreement::{EphemeralPrivateKey, PublicKey, X25519};
use ring::rand::{SystemRandom, SecureRandom};
use super::stream::{
    Encryption,
    encrypt_record,
    RecordReceiver,
    PlaintextStream,
    EncryptedStream,
};
use super::super::helpers::{
    Transcript,
    Ciphers,
    TrafficSecrets,
    get_server_hello_x25519_shared_secret,
    get_derived_prk,
    get_zero_prk,
    verify_finished,
    derive_secret,
    rsa_sign,
    ed25519_sign,
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
use super::client_state::ClientState;
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

#[derive(Clone)]
pub enum ClientKey {
    RSA(Vec<u8>),
    EC(Vec<u8>),
}

pub enum ClientAuth {
    None,
    Certificate { cert: Vec<u8>, key: ClientKey },
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

async fn send_certificate(
    transcript: &mut Transcript,
    client_cert_data: &[u8],
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
    Ok(())
}

async fn send_verify(
    transcript: &mut Transcript,
    client_key: &ClientKey,
    stream: &mut EncryptedStream,
) -> Result<(), TLSError> {
    let thash = transcript.get_hash();
    let verify_input = make_verify_transcript_input(Endpoint::Client, &thash);
    let certificate_verify = match client_key {
        ClientKey::RSA(client_key_data) => {
            let rng = SystemRandom::new();
            CertificateVerify {
                algorithm: SignatureScheme::RsaPssRsaeSha256,
                signature: rsa_sign(client_key_data, &verify_input, SignatureScheme::RsaPssRsaeSha256, &rng)?,
            }
        }
        ClientKey::EC(client_key_data) => {
            CertificateVerify {
                algorithm: SignatureScheme::Ed25519,
                signature: ed25519_sign(client_key_data, &verify_input)?,
            }
        }
    };
    let handshake = Handshake::CertificateVerify(certificate_verify);
    send_handshake(&handshake, Some(transcript), stream).await?;
    Ok(())
}

async fn send_handshake(
    handshake: &Handshake,
    transcript: Option<&mut Transcript>,
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
    else if signature_algorithm.algorithm.0 == x509::CRYPTO_ED25519 {
        parameters = &ring::signature::ED25519;
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
    let mut state = make_initial_state(transport, config, protocol_names)?;
    loop {
        println!("establish_connection: state = {}", state);
        match state {
            ECState::Done(s) => return Ok(s.conn),
            ECState::Error(e) => return Err(e),
            _ => state = state.step().await,
        }
    }
}

enum ECState {
    BeforeSendClientHello(BeforeSendClientHello),
    BeforeReceiveServerHello(BeforeReceiveServerHello),
    BeforeReceiveServerMessages(BeforeReceiveServerMessages),
    BeforeSendCertificateAndVerify(BeforeSendCertificateAndVerify),
    BeforeSendFinished(BeforeSendFinished),
    Done(ECStateDone),
    Error(TLSError),
}

impl fmt::Display for ECState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ECState::BeforeSendClientHello(_) => write!(f, "BeforeSendClientHello"),
            ECState::BeforeReceiveServerHello(_) => write!(f, "BeforeReceiveServerHello"),
            ECState::BeforeReceiveServerMessages(_) => write!(f, "BeforeReceiveServerMessages"),
            ECState::BeforeSendCertificateAndVerify(_) => write!(f, "BeforeSendCertificateAndVerify"),
            ECState::BeforeSendFinished(_) => write!(f, "BeforeSendFinished"),
            ECState::Done(_) => write!(f, "Done"),
            ECState::Error(_) => write!(f, "Error"),
        }
    }
}

impl ECState {
    async fn step(self) -> ECState {
        match self {
            ECState::BeforeSendClientHello(s) => {
                s.do_step().await
            }
            ECState::BeforeReceiveServerHello(s) => {
                s.do_step().await
            }
            ECState::BeforeReceiveServerMessages(s) => {
                s.do_step().await
            }
            ECState::BeforeSendCertificateAndVerify(s) => {
                s.do_step().await
            }
            ECState::BeforeSendFinished(s) => {
                s.do_step().await
            }
            ECState::Done(sdone) => {
                ECState::Done(sdone)
            }
            ECState::Error(e) => {
                ECState::Error(e)
            }
        }
    }
}

fn make_initial_state<T: 'static>(
    transport: Pin<Box<T>>,
    config: ClientConfig,
    protocol_names: &[&str],
) -> Result<ECState, TLSError>
    where T : AsyncRead + AsyncWrite + Send
{
    let private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())
        .map_err(|_| TLSError::EphemeralPrivateKeyGenerationFailed)?;
    let public_key: PublicKey = private_key.compute_public_key()
        .map_err(|_| TLSError::ComputePublicKeyFailed)?;
    let client_hello: ClientHello = make_client_hello(
        public_key.as_ref(),
        config.server_name.as_ref(),
        protocol_names,
    )?;
    let client_hello_handshake: Handshake = Handshake::ClientHello(client_hello);

    let initial_transcript: Vec<u8> = Vec::new();
    let plaintext_stream = PlaintextStream::new(transport, RecordReceiver::new());


    Ok(ECState::BeforeSendClientHello(BeforeSendClientHello {
        config: config,
        private_key: private_key,
        client_hello_handshake: client_hello_handshake,
        initial_transcript: initial_transcript,
        plaintext_stream: plaintext_stream,
    }))
}

struct BeforeSendClientHello {
    config: ClientConfig,
    private_key: EphemeralPrivateKey,
    client_hello_handshake: Handshake,
    initial_transcript: Vec<u8>,
    plaintext_stream: PlaintextStream,
}

impl BeforeSendClientHello {
    async fn do_step(mut self) -> ECState {
        match write_plaintext_handshake(
            &mut self.plaintext_stream.inner,
            &self.client_hello_handshake,
            &mut self.initial_transcript,
        ).await {
            Ok(()) => self.on_data_sent(),
            Err(e) => self.on_error(e),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_data_sent(self) -> ECState {
        ECState::BeforeReceiveServerHello(BeforeReceiveServerHello {
            config: self.config,
            private_key: self.private_key,
            initial_transcript: self.initial_transcript,
            plaintext_stream: self.plaintext_stream,
        })
    }
}

struct BeforeReceiveServerHello {
    config: ClientConfig,
    private_key: EphemeralPrivateKey,
    initial_transcript: Vec<u8>,
    plaintext_stream: PlaintextStream,
}

impl BeforeReceiveServerHello {
    async fn do_step(mut self) -> ECState {
        match self.plaintext_stream.receive_plaintext_message(
            &mut self.initial_transcript,
        ).await {
            Ok(opt_message) => self.on_opt_message(opt_message),
            Err(e) => self.on_error(e),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_opt_message(self, message: Option<Message>) -> ECState {
        let server_hello: ServerHello = match message {
            Some(Message::Handshake(Handshake::ServerHello(server_hello))) => server_hello,
            Some(message) => return ECState::Error(TLSError::UnexpectedMessage(message.name())),
            None => return ECState::Error(TLSError::UnexpectedEOF),
        };

        let ciphers: Ciphers = match Ciphers::from_server_hello(&server_hello) {
            Ok(r) => r,
            Err(e) => return ECState::Error(e),
        };
        let transcript: Transcript = Transcript::new(self.initial_transcript, ciphers.hash_alg);
        let henc: HandshakeEncryption = match get_handshake_encryption(
            &ciphers,
            &transcript,
            &server_hello,
            self.private_key,
        ) {
            Ok(r) => r,
            Err(e) => return ECState::Error(e),
        };
        let prk: Vec<u8> = henc.prk;


        let encryption: Encryption = Encryption {
            traffic_secrets: henc.traffic_secrets,
            ciphers,
        };

        let enc_stream: EncryptedStream = EncryptedStream::new(self.plaintext_stream, encryption);

        ECState::BeforeReceiveServerMessages(BeforeReceiveServerMessages {
            config: self.config,
            enc_stream,
            transcript,
            prk,
        })
    }
}

struct BeforeReceiveServerMessages {
    config: ClientConfig,
    enc_stream: EncryptedStream,
    transcript: Transcript,
    prk: Vec<u8>,
}

impl BeforeReceiveServerMessages {
    async fn do_step(mut self) -> ECState {
        match receive_server_messages(&mut self.transcript, &mut self.enc_stream).await {
            Ok(sm) => self.on_server_messages(sm),
            Err(e) => self.on_error(e),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_server_messages(self, sm: ServerMessages) -> ECState {
        // Compute the new traffic secrets for application data, but don't use them yet.
        let application_secrets: TrafficSecrets = match compute_application_secrets(
            &self.transcript, &self.config,
            &self.prk, &sm, &self.enc_stream.encryption) {
            Ok(r) => r,
            Err(e) => return ECState::Error(e),
        };

        // Send the client certificate and Finished messages, using the handshake traffic secrets
        if let ClientAuth::Certificate { cert, key } = self.config.client_auth {
            ECState::BeforeSendCertificateAndVerify(BeforeSendCertificateAndVerify {
                enc_stream: self.enc_stream,
                transcript: self.transcript,
                application_secrets: application_secrets,
                cert: cert,
                key: key,
            })
        }
        else {
            ECState::BeforeSendFinished(BeforeSendFinished {
                enc_stream: self.enc_stream,
                application_secrets: application_secrets,
                transcript: self.transcript,
            })
        }

    }
}

struct BeforeSendCertificateAndVerify {
    enc_stream: EncryptedStream,
    transcript: Transcript,
    application_secrets: TrafficSecrets,
    cert: Vec<u8>,
    key: ClientKey,
}

impl BeforeSendCertificateAndVerify {
    async fn do_step(mut self) -> ECState {
        match send_certificate(&mut self.transcript, &self.cert, &mut self.enc_stream).await {
            Ok(()) => (),
            Err(e) => return ECState::Error(e),
        };
        match send_verify(&mut self.transcript, &self.key, &mut self.enc_stream).await {
            Ok(()) => (),
            Err(e) => return ECState::Error(e),
        };
        ECState::BeforeSendFinished(BeforeSendFinished {
            enc_stream: self.enc_stream,
            application_secrets: self.application_secrets,
            transcript: self.transcript,
        })
    }
}

struct BeforeSendFinished {
    enc_stream: EncryptedStream,
    application_secrets: TrafficSecrets,
    transcript: Transcript,
}

impl BeforeSendFinished {
    async fn do_step(mut self) -> ECState {
        match send_finished(
            self.enc_stream.encryption.ciphers.hash_alg,
            &self.transcript.get_hash(),
            &mut self.enc_stream,
        ).await {
            Ok(()) => self.on_data_sent(),
            Err(e) => self.on_error(e),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_data_sent(mut self) -> ECState {
        // Reset the encryption state for the stream to use the new traffic secrets
        self.enc_stream.client_sequence_no = 0;
        self.enc_stream.server_sequence_no = 0;
        self.enc_stream.encryption.traffic_secrets = self.application_secrets;

        ECState::Done(ECStateDone { conn: EstablishedConnection::new(self.enc_stream) })
    }
}

struct ECStateDone {
    conn: EstablishedConnection,
}

struct HandshakeEncryption {
    prk: Vec<u8>,
    traffic_secrets: TrafficSecrets,
}

fn get_handshake_encryption(
    ciphers: &Ciphers,
    transcript: &Transcript,
    server_hello: &ServerHello,
    private_key: EphemeralPrivateKey,
) -> Result<HandshakeEncryption, TLSError> {
    let secret = get_server_hello_x25519_shared_secret(private_key, server_hello)
        .ok_or(TLSError::GetSharedSecretFailed)?;
    let prk = get_derived_prk(ciphers.hash_alg, &get_zero_prk(ciphers.hash_alg), &secret)?;
    let traffic_secrets = TrafficSecrets::derive_from(ciphers, transcript, &prk, "hs")?;
    Ok(HandshakeEncryption { traffic_secrets, prk })
}

pub struct ServerMessages {
    #[allow(dead_code)]
    pub encrypted_extensions: EncryptedExtensions,
    #[allow(dead_code)]
    pub certificate_request: Option<CertificateRequest>,
    pub certificate: Option<Certificate>,
    pub certificate_verify: Option<(CertificateVerify, Vec<u8>)>,
    pub finished: (Finished, Vec<u8>),
}

async fn receive_server_messages(
    transcript: &mut Transcript,
    stream: &mut EncryptedStream,
) -> Result<ServerMessages, TLSError> {
    let mut cstate = ClientState::ReceivedServerHello;

    loop {
        if let ClientState::ReceivedFinished {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
                finished,
        } = cstate {
            return Ok(ServerMessages {
                encrypted_extensions,
                certificate_request,
                certificate,
                certificate_verify,
                finished,
            })
        }

        let hash = transcript.get_hash();
        let message = stream.receive_message(Some(transcript)).await?;
        match message {
            Some(Message::Handshake(handshake)) => {
                cstate = cstate.on_hash_and_handshake(hash, handshake)?;
            }
            Some(message) => return Err(TLSError::UnexpectedMessage(message.name())),
            None => return Err(TLSError::UnexpectedEOF),
        }
    }
}

fn compute_application_secrets(
    transcript: &Transcript,
    config: &ClientConfig,
    prk: &[u8],
    sm: &ServerMessages,
    encryption: &Encryption,
) -> Result<TrafficSecrets, TLSError> {
    let ciphers = &encryption.ciphers;
    let secrets = &encryption.traffic_secrets;

    let input_psk: &[u8] = &vec_with_len(ciphers.hash_alg.byte_len());
    let new_prk = get_derived_prk(ciphers.hash_alg, prk, input_psk)
        .map_err(TLSError::Internal)?;

    let application_secrets = TrafficSecrets::derive_from(ciphers, transcript, &new_prk, "ap")?;
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

    let ca_cert: &[u8] = match &config.server_auth {
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

    Ok(application_secrets)
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
