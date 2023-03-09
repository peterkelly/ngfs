use std::io;
use std::pin::Pin;
use std::future::Future;
use std::task::{Context, Poll};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use bytes::{BytesMut, Buf};
use ring::agreement::{EphemeralPrivateKey, PublicKey, X25519};
use ring::rand::{SystemRandom, SecureRandom};
use super::stream::{
    Encryption,
    encrypt_record,
    RecordReceiver,
    PlaintextStream,
    EncryptedStream,
    ReadState,
    WriteState,
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
use super::client_state::{ClientState, ReceivedFinished};
use crate::util::util::vec_with_len;
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

fn send_finished_noflush(
    transcript: &Transcript,
    stream: &mut EncryptedStream,
) -> Result<(), TLSError> {
    let encryption = &stream.encryption;
    let finished_key = derive_secret(
        encryption.ciphers.hash_alg,
        &encryption.traffic_secrets.client.raw,
        b"finished", &[])?;
    let verify_data = encryption.ciphers.hash_alg.hmac_sign(&finished_key, &transcript.get_hash())?;
    let client_finished = Handshake::Finished(Finished { verify_data });
    append_handshake(&client_finished, None, stream)?;
    Ok(())
}

fn append_certificate(
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
    append_handshake(&handshake, Some(transcript), stream)?;
    Ok(())
}

fn append_verify(
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
    append_handshake(&handshake, Some(transcript), stream)?;
    Ok(())
}

fn append_handshake(
    handshake: &Handshake,
    transcript: Option<&mut Transcript>,
    stream: &mut EncryptedStream,
) -> Result<(), TLSError> {
    let mut writer = BinaryWriter::new();
    writer.write_item(handshake).map_err(|_| TLSError::MessageEncodingFailed)?;
    let finished_bytes: Vec<u8> = Vec::from(writer);
    encrypt_record(
        &mut stream.plaintext.outgoing,
        &finished_bytes,         // to_encrypt
        ContentType::Handshake, // content_type
        &stream.encryption.traffic_secrets.client,        // traffic_secret
        stream.client_sequence_no, // sequence_no
        transcript,
    )?;

    stream.client_sequence_no += 1;

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

fn append_plaintext_handshake(
    stream: &mut PlaintextStream,
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
    record.encode(&mut stream.outgoing);
    Ok(())
}

pub fn establish_connection<T: 'static>(
    transport: Pin<Box<T>>,
    config: ClientConfig,
    protocol_names: &[&str],
) -> EstablishConnection
    where T : AsyncRead + AsyncWrite + Send
{
    let state = match make_initial_state(transport, config, protocol_names) {
        Ok(r) => r,
        Err(e) => ECState::Error(e),
    };
    EstablishConnection {
        state: Some(state),
    }
}

pub struct EstablishConnection {
    state: Option<ECState>,
}

impl Future for EstablishConnection {
    type Output = Result<EstablishedConnection, TLSError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut xself = Pin::into_inner(self);
        loop {
            println!("EstablishConnection: state = {}", xself.state.as_ref().unwrap());
            match xself.state.take().unwrap() {
                ECState::Done(s) => return Poll::Ready(Ok(s.conn)),
                ECState::Error(e) => return Poll::Ready(Err(e)),
                mut s => {
                    if s.want_recv() {
                        match s.do_poll_recv(cx) {
                            Poll::Ready(Ok(())) => (),
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => (),
                        }
                    }

                    let (p, s) = s.poll_step(cx);
                    xself.state = Some(s);
                    match p {
                        Poll::Ready(()) => continue,
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }

    }
}

enum ECState {
    Begin(ECStateBegin),
    AfterSendClientHello(AfterSendClientHello),
    AfterReceiveServerHello(AfterReceiveServerHello),
    AfterReceiveServerMessages(AfterReceiveServerMessages),
    Done(ECStateDone),
    Error(TLSError),
}

impl fmt::Display for ECState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            ECState::Begin(_) => write!(f, "ECStateBegin"),
            ECState::AfterSendClientHello(_) => write!(f, "AfterSendClientHello"),
            ECState::AfterReceiveServerHello(s) => write!(f, "AfterReceiveServerHello {}",
                s.cstate.as_ref().unwrap()),
            ECState::AfterReceiveServerMessages(_) => write!(f, "AfterReceiveServerMessages"),
            ECState::Done(_) => write!(f, "Done"),
            ECState::Error(_) => write!(f, "Error"),
        }
    }
}

impl ECState {
    fn poll_step(self, cx: &mut Context<'_>) -> (Poll<()>, ECState) {
        match self {
            ECState::Begin(s) => {
                s.poll_step(cx)
            }
            ECState::AfterSendClientHello(s) => {
                s.poll_step()
            }
            ECState::AfterReceiveServerHello(s) => {
                s.poll_step()
            }
            ECState::AfterReceiveServerMessages(s) => {
                s.poll_step(cx)
            }
            ECState::Done(sdone) => {
                (Poll::Ready(()), ECState::Done(sdone))
            }
            ECState::Error(e) => {
                (Poll::Ready(()), ECState::Error(e))
            }
        }
    }

    fn want_recv(&self) -> bool {
        match self {
            ECState::Begin(_) => false,
            ECState::AfterSendClientHello(_) => true,
            ECState::AfterReceiveServerHello(_) => true,
            ECState::AfterReceiveServerMessages(_) => false,
            ECState::Done(_) => false,
            ECState::Error(_) => false,
        }
    }

    fn do_poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TLSError>> {
        match self {
            ECState::Begin(_) => {
                Poll::Ready(Err(TLSError::ReceiveInWrongPlace))
            }
            ECState::AfterSendClientHello(s) => {
                s.plaintext_stream.poll_recv(cx)
            }
            ECState::AfterReceiveServerHello(s) => {
                s.stream.plaintext.poll_recv(cx)
            }
            ECState::AfterReceiveServerMessages(_) => {
                Poll::Ready(Err(TLSError::ReceiveInWrongPlace))
            }
            ECState::Done(_) => {
                Poll::Ready(Err(TLSError::ReceiveInWrongPlace))
            }
            ECState::Error(_) => {
                Poll::Ready(Err(TLSError::ReceiveInWrongPlace))
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

    let mut initial_transcript: Vec<u8> = Vec::new();
    let mut plaintext_stream = PlaintextStream::new(transport, RecordReceiver::new());

    append_plaintext_handshake(
        &mut plaintext_stream,
        &client_hello_handshake,
        &mut initial_transcript,
    )?;

    Ok(ECState::Begin(ECStateBegin {
        config: config,
        private_key: private_key,
        initial_transcript: initial_transcript,
        plaintext_stream: plaintext_stream,
    }))
}

struct ECStateBegin {
    config: ClientConfig,
    private_key: EphemeralPrivateKey,
    initial_transcript: Vec<u8>,
    plaintext_stream: PlaintextStream,
}

impl ECStateBegin {
    fn poll_step(mut self, cx: &mut Context<'_>) -> (Poll<()>, ECState) {
        match self.plaintext_stream.poll_flush(cx) {
            Poll::Ready(Ok(())) => (Poll::Ready(()), self.on_data_sent()),
            Poll::Ready(Err(e)) => (Poll::Ready(()), self.on_error(e)),
            Poll::Pending => (Poll::Pending, ECState::Begin(self)),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_data_sent(self) -> ECState {
        ECState::AfterSendClientHello(AfterSendClientHello {
            config: self.config,
            private_key: self.private_key,
            initial_transcript: self.initial_transcript,
            plaintext_stream: self.plaintext_stream,
        })
    }
}

struct AfterSendClientHello {
    config: ClientConfig,
    private_key: EphemeralPrivateKey,
    initial_transcript: Vec<u8>,
    plaintext_stream: PlaintextStream,
}

impl AfterSendClientHello {
    fn poll_step(mut self) -> (Poll<()>, ECState) {
        match self.plaintext_stream.poll_receive_plaintext_message(&mut self.initial_transcript) {
            Poll::Ready(Ok(opt_message)) => (Poll::Ready(()), self.on_opt_message(opt_message)),
            Poll::Ready(Err(e)) => (Poll::Ready(()), self.on_error(e)),
            Poll::Pending => (Poll::Pending, ECState::AfterSendClientHello(self))
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

        ECState::AfterReceiveServerHello(AfterReceiveServerHello {
            config: self.config,
            stream: enc_stream,
            transcript: transcript,
            prk: prk,
            cstate: Some(ClientState::ReceivedServerHello),
        })
    }
}

struct AfterReceiveServerHello {
    config: ClientConfig,
    stream: EncryptedStream,
    transcript: Transcript,
    prk: Vec<u8>,
    cstate: Option<ClientState>,
}

impl AfterReceiveServerHello {
    fn poll_step(mut self) -> (Poll<()>, ECState) {
        let mut rsm = ReceiveServerMessages {
            transcript: &mut self.transcript,
            stream: &mut self.stream,
            cstate: Some(self.cstate.take().unwrap()),
        };
        match ReceiveServerMessages::poll(Pin::new(&mut rsm)) {
            Poll::Ready(Ok(sm)) => {
                (
                    Poll::Ready(()),
                    self.on_server_messages(sm),
                )
            }
            Poll::Ready(Err(e)) => {
                (
                    Poll::Ready(()),
                    self.on_error(e),
                )
            }
            Poll::Pending => {
                let cstate = Some(rsm.cstate.take().unwrap());
                (
                    Poll::Pending,
                    ECState::AfterReceiveServerHello(
                        AfterReceiveServerHello {
                            config: self.config,
                            stream: self.stream,
                            transcript: self.transcript,
                            prk: self.prk,
                            cstate: cstate,
                        }
                    ),
                )
            }
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_server_messages(mut self, sm: ServerMessages) -> ECState {
        // Compute the new traffic secrets for application data, but don't use them yet.
        let application_secrets: TrafficSecrets = match compute_application_secrets(
            &self.transcript, &self.config,
            &self.prk, &sm, &self.stream.encryption) {
            Ok(r) => r,
            Err(e) => return ECState::Error(e),
        };

        // Send the client certificate and Finished messages, using the handshake traffic secrets
        if let ClientAuth::Certificate { cert, key } = &self.config.client_auth {
            match append_certificate(&mut self.transcript, cert, &mut self.stream) {
                Ok(()) => (),
                Err(e) => return ECState::Error(e),
            };
            match append_verify(&mut self.transcript, key, &mut self.stream) {
                Ok(()) => (),
                Err(e) => return ECState::Error(e),
            };
        }

        match send_finished_noflush(&self.transcript, &mut self.stream) {
            Ok(()) => (),
            Err(e) => return self.on_error(e),
        };

        ECState::AfterReceiveServerMessages(AfterReceiveServerMessages {
            stream: self.stream,
            application_secrets: application_secrets,
        })
    }
}

struct AfterReceiveServerMessages {
    stream: EncryptedStream,
    application_secrets: TrafficSecrets,
}

impl AfterReceiveServerMessages {
    fn poll_step(mut self, cx: &mut Context<'_>) -> (Poll<()>, ECState) {
        match self.stream.plaintext.poll_flush(cx) {
            Poll::Ready(Ok(())) => (Poll::Ready(()), self.on_data_sent()),
            Poll::Ready(Err(e)) => (Poll::Ready(()), self.on_error(e)),
            Poll::Pending => (Poll::Pending, ECState::AfterReceiveServerMessages(self)),
        }
    }

    fn on_error(self, e: TLSError) -> ECState {
        ECState::Error(e)
    }

    fn on_data_sent(mut self) -> ECState {
        // Reset the encryption state for the stream to use the new traffic secrets
        self.stream.client_sequence_no = 0;
        self.stream.server_sequence_no = 0;
        self.stream.encryption.traffic_secrets = self.application_secrets;

        ECState::Done(ECStateDone { conn: EstablishedConnection::new(self.stream) })
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

struct ReceiveServerMessages<'a> {
    transcript: &'a mut Transcript,
    stream: &'a mut EncryptedStream,
    cstate: Option<ClientState>,
}

impl<'a> ReceiveServerMessages<'a> {
    fn poll(self: Pin<&mut Self>) -> Poll<Result<ServerMessages, TLSError>> {
        let mut xself = Pin::into_inner(self);

        loop {
            match xself.cstate.take().unwrap() {
                ClientState::ReceivedFinished(ReceivedFinished {
                        encrypted_extensions,
                        certificate_request,
                        certificate,
                        certificate_verify,
                        finished,
                }) => {
                    return Poll::Ready(Ok(ServerMessages {
                        encrypted_extensions,
                        certificate_request,
                        certificate,
                        certificate_verify,
                        finished,
                    }));
                }
                other => {
                    xself.cstate = Some(other);
                }
            }

            let hash = xself.transcript.get_hash();
            let message = match xself.stream.poll_receive_encrypted_message(Some(xself.transcript)) {
                Poll::Ready(Ok(r)) => r,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            match message {
                Some(Message::Handshake(handshake)) => {
                    xself.cstate = match xself.cstate.take().unwrap().on_hash_and_handshake(hash, handshake) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            // ClientState::ReceivedServerHello
                            return Poll::Ready(Err(e));
                        }
                    };
                }
                Some(message) => return Poll::Ready(Err(TLSError::UnexpectedMessage(message.name()))),
                None => return Poll::Ready(Err(TLSError::UnexpectedEOF)),
            }
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

pub struct EstablishedConnection {
    stream: EncryptedStream,
    incoming_decrypted: BytesMut,
    read_state: ReadState,
}

impl EstablishedConnection {
    fn new(stream: EncryptedStream) -> Self {
        EstablishedConnection {
            stream,
            incoming_decrypted: BytesMut::new(),
            read_state: ReadState::Active,
        }
    }

    fn append_record(&mut self, data: &[u8], content_type: ContentType) -> Result<(), TLSError> {
        match encrypt_record(
            &mut self.stream.plaintext.outgoing,
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
                self.stream.plaintext.write_state = WriteState::Error(e.clone());
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


    fn poll_flush_encrypted(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TLSError>> {
        self.stream.plaintext.poll_flush(cx)
    }

    fn poll_fill_incoming(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), TLSError>> {
        if self.incoming_decrypted.remaining() > 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.stream.plaintext.poll_recv(cx) {
                Poll::Ready(Ok(())) => (),
                Poll::Ready(Err(e)) => {
                    self.read_state = ReadState::Error(e.clone());
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    cx.waker().wake_by_ref(); // TODO: Is this needed?
                    return Poll::Pending;
                }
            }

            match self.stream.poll_receive_encrypted_message(None) {
                Poll::Pending => {
                    cx.waker().wake_by_ref(); // TODO: Is this needed?
                    return Poll::Pending;
                }
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
        match &self.stream.plaintext.write_state {
            WriteState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            WriteState::InShutdown => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            WriteState::Active => (), // ok, continue
        }


        let direct = Pin::into_inner(self);
        match direct.poll_flush_encrypted(cx) {
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
        match &self.stream.plaintext.write_state {
            WriteState::Error(e) => return Poll::Ready(Err(e.clone().into())),
            WriteState::InShutdown => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            WriteState::Active => (), // ok, continue
        }

        let direct = Pin::into_inner(self);
        match direct.poll_flush_encrypted(cx) {
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
        match &direct.stream.plaintext.write_state {
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
                        direct.stream.plaintext.write_state = WriteState::InShutdown;
                    }
                }
            }
        }

        // Wait until any remaining data has been sent; we don't want to shut down the connection
        // until this has been sent.
        match direct.poll_flush_encrypted(cx) {
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
        direct.stream.plaintext.write_state = WriteState::Error(TLSError::IOError(io::ErrorKind::BrokenPipe));
        Poll::Ready(Ok(()))
    }
}
