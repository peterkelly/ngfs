#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt};
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

fn verify_transcript_opt(
    certificate_verify: &Option<CertificateVerify>,
    certificate_verify_thash: &Option<Vec<u8>>,
    public_key: &x509::SubjectPublicKeyInfo,
    endpoint: Endpoint,
) -> Result<(), Box<dyn Error>> {
    let certificate_verify: &CertificateVerify = match certificate_verify {
        Some(v) => v,
        None => {
            return Err(GeneralError::new("Server did not send CertificateVerify"));
        }
    };
    let certificate_verify_thash: &[u8] = match certificate_verify_thash {
        Some(v) => v,
        None => {
            return Err(GeneralError::new("Server did not send CertificateVerify thash"));
        }
    };

    verify_transcript(certificate_verify, certificate_verify_thash, public_key, endpoint)?;
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

pub struct AEncryption {
    traffic_secrets: TrafficSecrets,
    ciphers: Ciphers,
}

pub struct AConnection {
    reader: Box<dyn AsyncRead + Unpin>,
    writer: Box<dyn AsyncWrite + Unpin>,
    transcript: Vec<u8>,
    my_private_key: Option<EphemeralPrivateKey>,
    config: ClientConfig,
    client_sequence_no: u64,
    server_sequence_no: u64,
    encryption: Option<AEncryption>,
    old_thash: Vec<u8>,
    new_thash: Vec<u8>,
}

impl AConnection {
    pub fn new(
        reader: Box<dyn AsyncRead + Unpin>,
        writer: Box<dyn AsyncWrite + Unpin>,
        my_private_key: EphemeralPrivateKey,
        config: ClientConfig,
    ) -> Self {
        AConnection {
            reader: reader,
            writer: writer,
            transcript: Vec::new(),
            my_private_key: Some(my_private_key),
            config: config,
            client_sequence_no: 0,
            server_sequence_no: 0,
            encryption: None,
            old_thash: Vec::new(),
            new_thash: Vec::new(),
        }
    }

    async fn receive_record(&mut self) -> Result<TLSOwnedPlaintext, Box<dyn Error>> {
        let mut header: [u8; 5] = Default::default();
        self.reader.read_exact(&mut header).await?;

        let content_type = ContentType::from_raw(header[0]);

        let mut legacy_record_version_bytes: [u8; 2] = Default::default();
        legacy_record_version_bytes.copy_from_slice(&header[1..3]);
        let legacy_record_version = u16::from_be_bytes(legacy_record_version_bytes);


        let mut length_bytes: [u8; 2] = Default::default();
        length_bytes.copy_from_slice(&header[3..5]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length > TLS_RECORD_SIZE {
            return Err(TLSPlaintextError::InvalidLength.into());
        }

        let mut fragment = vec_with_len(length);
        self.reader.read_exact(&mut fragment).await?;

        let mut raw: Vec<u8> = Vec::new();
        raw.extend_from_slice(&header);
        raw.extend_from_slice(&fragment);

        let record = TLSOwnedPlaintext {
            content_type,
            legacy_record_version,
            header: header,
            fragment: fragment,
            raw: raw,
        };
        Ok(record)
    }

    async fn receive_record_ignore_cc(&mut self) -> Result<TLSOwnedPlaintext, Box<dyn Error>> {
        loop {
            let record = self.receive_record().await?;
            if record.content_type != ContentType::ChangeCipherSpec {
                return Ok(record)
            }
        }
    }

    async fn receive_message(&mut self) -> Result<Message, Box<dyn Error>> {
        let plaintext = self.receive_record_ignore_cc().await?;
        match &self.encryption {
            Some(encryption) => {
                self.old_thash = encryption.ciphers.hash_alg.hash(&self.transcript);

                // TODO: Cater for alerts
                let (message, message_raw) = decrypt_message(
                    self.server_sequence_no,
                    &encryption.traffic_secrets.server,
                    &plaintext.raw)?;
                self.server_sequence_no += 1;
                self.transcript.extend_from_slice(&message_raw);
                // Ok((message, message_raw))

                self.new_thash = encryption.ciphers.hash_alg.hash(&self.transcript);
                Ok(message)
            }
            None => {
                // TODO: Support records containing multiple handshake messages
                self.transcript.extend_from_slice(&plaintext.fragment);
                let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)?;
                Ok(message)
            }
        }
    }

    async fn receive_handshake(&mut self) -> Result<Handshake, Box<dyn Error>> {
        let message = self.receive_message().await?;
        match message {
            Message::Handshake(hs) => {
                Ok(hs)
            }
            _ => {
                Err(GeneralError::new(format!("Expected a handshake, got {:?}", message.content_type())))
            }
        }
    }

    async fn write_plaintext_handshake(&mut self, handshake: &Handshake) -> Result<(), Box<dyn Error>> {
        let record = handshake_to_record(handshake)?;
        self.transcript.extend_from_slice(&record.fragment);
        self.writer.write_all(&record.to_vec()).await?;
        Ok(())
    }

    async fn receive_server_hello(&mut self) -> Result<ServerHello, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::ServerHello(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected ServerHello, got {}", handshake.name())))
        }
    }

    async fn receive_encrypted_extensions(&mut self) -> Result<EncryptedExtensions, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::EncryptedExtensions(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected EncryptedExtensions, got {}", handshake.name())))
        }
    }

    async fn receive_certificate_request(&mut self) -> Result<CertificateRequest, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::CertificateRequest(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected CertificateRequest, got {}", handshake.name())))
        }
    }

    async fn receive_certificate(&mut self) -> Result<Certificate, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::Certificate(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected Certificate, got {}", handshake.name())))
        }
    }

    async fn receive_certificate_verify(&mut self) -> Result<CertificateVerify, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::CertificateVerify(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected CertificateVerify, got {}", handshake.name())))
        }
    }

    async fn receive_finished(&mut self) -> Result<Finished, Box<dyn Error>> {
        let handshake = self.receive_handshake().await?;
        match handshake {
            Handshake::Finished(v) => Ok(v),
            _ => Err(GeneralError::new(format!("Expected Finished, got {}", handshake.name())))
        }
    }

    pub async fn do_phase_one(&mut self, client_hello: &Handshake) -> Result<PhaseOneResult, Box<dyn Error>> {
        self.write_plaintext_handshake(client_hello).await?;
        let server_hello = self.receive_server_hello().await?;

        println!("PhaseOne: Received ServerHello");
        println!("{:#?}", &Indent(&server_hello));
        let ciphers = Ciphers::from_server_hello(&server_hello)?;

        let my_private_key = self.my_private_key.take().unwrap();
        let secret = get_server_hello_x25519_shared_secret(my_private_key, &server_hello)
            .ok_or_else(|| GeneralError::new("Cannot get shared secret"))?;
        println!("Shared secret = {}", BinaryData(&secret));

        let prk = get_derived_prk(ciphers.hash_alg, &get_zero_prk(ciphers.hash_alg), &secret)?;

        let handshake_secrets = TrafficSecrets::derive_from(&ciphers, &self.transcript, &prk, "hs")?;
        println!("KEY CLIENT_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&handshake_secrets.client.raw));
        println!("KEY SERVER_HANDSHAKE_TRAFFIC_SECRET = {}", BinaryData(&handshake_secrets.server.raw));
        self.encryption = Some(AEncryption {
            traffic_secrets: handshake_secrets,
            ciphers: ciphers,
        });

        Ok(PhaseOneResult {
            prk,
        })
    }

    pub async fn do_phase_two(&mut self, p1: PhaseOneResult) -> Result<(), Box<dyn Error>> {
        let prk = p1.prk;

        // TODO: Allow some of these to be absent depending on the config
        let encrypted_extensions = self.receive_encrypted_extensions().await?;
        println!("Phase two: Got encrypted_extensions");
        let certificate_request = self.receive_certificate_request().await?;
        println!("Phase two: Got certificate_request");
        let certificate = self.receive_certificate().await?;
        println!("Phase two: Got certificate");
        let certificate_verify = self.receive_certificate_verify().await?;
        let certificate_verify_thash = self.old_thash.clone();
        println!("Phase two: Got certificate_verify");
        let finished = self.receive_finished().await?;
        println!("Phase two: Got finished");

        let encryption_copy = match &self.encryption {
            Some(encryption) => {
                AEncryption {
                    traffic_secrets: TrafficSecrets {
                        client: encryption.traffic_secrets.client.clone(),
                        server: encryption.traffic_secrets.server.clone(),
                    },
                    ciphers: Ciphers {
                        hash_alg: encryption.ciphers.hash_alg.clone(),
                        aead_alg: encryption.ciphers.aead_alg.clone(),
                    }
                }
            }
            None => {
                return Err(GeneralError::new("No encryption parameters available"));
            }
        };
        let ciphers = &encryption_copy.ciphers;
        let secrets = &encryption_copy.traffic_secrets;

        let input_psk: &[u8] = &vec_with_len(ciphers.hash_alg.byte_len());
        let new_prk = get_derived_prk(ciphers.hash_alg, &prk, input_psk)?;

        let application_secrets = TrafficSecrets::derive_from(&ciphers, &self.transcript, &new_prk, "ap")?;
        println!("KEY CLIENT_TRAFFIC_SECRET_0 = {}", BinaryData(&application_secrets.client.raw));
        println!("KEY SERVER_TRAFFIC_SECRET_0 = {}", BinaryData(&application_secrets.server.raw));


        // let mut bad_finished = Finished { verify_data: finished.verify_data.clone() };
        // bad_finished.verify_data.push(0);
        println!("Before verify_finished()");
        verify_finished(ciphers.hash_alg, &secrets.server, &self.old_thash, &finished)?;
        println!("After  verify_finished()");

        let first_cert_entry : &CertificateEntry = match certificate.certificate_list.get(0) {
            Some(v) => v,
            None => {
                return Err(GeneralError::new("Server sent an empty certificate list"));
            }
        };

        let server_cert_raw: &[u8] = &first_cert_entry.data;
        let server_cert: &x509::Certificate = &first_cert_entry.certificate;

        let ca_cert: &[u8] = match &self.config.server_auth {
            ServerAuth::CertificateAuthority(v) => v,
            ServerAuth::None => {
                return Err(GeneralError::new("No CA certificate available"));
            }
        };

        println!("Before verify_certificate()");
        verify_certificate(ca_cert, &server_cert_raw)?;
        println!("After  verify_certificate()");


        println!("Before verify_transcript_opt()");
        verify_transcript_opt(
            &Some(certificate_verify),
            &Some(certificate_verify_thash),
            &server_cert.tbs_certificate.subject_public_key_info,
            Endpoint::Server
        )?;
        println!("After  verify_transcript_opt()");

        // FIXME: Don't hard-code SignatureScheme
        match &self.config.client_auth {
            ClientAuth::Certificate { cert, key } => {
                let client_cert = cert;
                let client_key = key;

                let rng = ring::rand::SystemRandom::new();
                let mut conn = ClientConn::new();
                println!("Before send_client_certificate()");
                send_client_certificate(
                    ciphers.hash_alg, // hash_alg: HashAlgorithm,
                    &secrets.client, // encryption_key: &EncryptionKey,
                    &mut conn, // conn: &mut ClientConn,
                    &mut self.client_sequence_no, // sequence_no: &mut u64,
                    &mut self.transcript, // transcript: &mut Vec<u8>,
                    client_cert, // client_cert_data: &[u8],
                    client_key, // client_key_data: &[u8],
                    SignatureScheme::RsaPssRsaeSha256, // signature_scheme: SignatureScheme,
                    &rng,
                )?;

                self.writer.write_all(&conn.to_send).await?;

                println!("After  send_client_certificate()");
            }
            ClientAuth::None => {
            }
        }

        let new_thash: Vec<u8> = ciphers.hash_alg.hash(&self.transcript); // TODO: use self.new_thash?

        // let mut bad_new_thash = new_thash.clone();
        // bad_new_thash.push(0);
        println!("Before send_finished()");
        let mut conn = ClientConn::new();
        send_finished(ciphers.hash_alg, &secrets.client, &new_thash, &mut conn, &mut self.client_sequence_no)?;
        self.writer.write_all(&conn.to_send).await?;
        println!("After  send_finished()");

        self.client_sequence_no = 0;
        self.server_sequence_no = 0;
        self.encryption = Some(AEncryption {
            traffic_secrets: application_secrets,
            ciphers: encryption_copy.ciphers,
        });

        Ok(())
    }

    pub async fn write_normal(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut conn = ClientConn::new();
        match &self.encryption {
            Some(encryption) => {
                conn.append_encrypted(
                    data.to_vec(),
                    ContentType::ApplicationData,
                    &encryption.traffic_secrets.client,
                    self.client_sequence_no,
                    None,
                )?;
            }
            None => {
                return Err(GeneralError::new("No encryption keys"));
            }
        }
        self.client_sequence_no += 1;
        self.writer.write_all(&conn.to_send).await?;
        Ok(())
    }

    pub async fn read_normal(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        loop {
            let message = self.receive_message().await?;

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

pub struct PhaseOneResult {
    prk: Vec<u8>,
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
