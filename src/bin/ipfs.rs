#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]

// https://github.com/libp2p/specs/blob/master/connections/README.md#connection-upgrade

use ring::rand::SystemRandom;

use std::error::Error;
use tokio::net::{TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use ring::agreement::{EphemeralPrivateKey, X25519};
use ring::signature::{RsaKeyPair, KeyPair};
use torrent::p2p::{PublicKey, KeyType};
use torrent::util::{from_hex, escape_string, vec_with_len, BinaryData, DebugHexDump};
use torrent::error;
use torrent::protobuf::VarInt;
use torrent::tls::types::handshake::{
    CipherSuite,
    Handshake,
    ClientHello
};
use torrent::tls::protocol::client::{
    ServerAuth,
    ClientAuth,
    ClientConfig,
    establish_connection,
    EstablishedConnection,
};
use torrent::asn1::value::{Integer, ObjectIdentifier, BitString, Value, Item};
use torrent::asn1::writer::encode_item;
use torrent::x509;
use torrent::asn1;
use torrent::x509::{
    Certificate,
    TBSCertificate,
    Version,
    AlgorithmIdentifier,
    Name,
    Validity,
    SubjectPublicKeyInfo,
    Time,
    UTCTime,
    RelativeDistinguishedName,
    // Extension,
    populate_registry,
    print_certificate,
    CRYPTO_SHA_256_WITH_RSA_ENCRYPTION,
    CRYPTO_RSA_ENCRYPTION,
    X509_COUNTRY_NAME,
    X509_ORGANIZATION_NAME,
    X509_COMMON_NAME,
    X509_AUTHORITY_KEY_IDENTIFIER,
    X509_BASIC_CONSTRAINTS,
    X509_KEY_USAGE,
};
fn make_client_hello(my_public_key_bytes: &[u8]) -> ClientHello {
    use torrent::tls::types::extension::{
        ECPointFormat,
        NamedCurve,
        Extension,
        SignatureScheme,
        PskKeyExchangeMode,
        NamedGroup,
        ServerName,
        ProtocolName,
        KeyShareEntry,
    };

    // TODO: Actually make these random
    let random = from_hex("1a87a2e2f77536fcfa071500af3c7dffa5830e6c61214e2dee7623c2b925aed8").unwrap();
    let session_id = from_hex("7d954b019486e0dffaa7769a4b9d27d796eaee44b710f18d630f3292b6dc7560").unwrap();
    println!("random.len() = {}", random.len());
    println!("session_id.len() = {}", session_id.len());
    assert!(random.len() == 32);
    assert!(session_id.len() == 32);

    let mut random_fixed: [u8; 32] = Default::default();
    random_fixed.copy_from_slice(&random);

    let mut cipher_suites = Vec::<CipherSuite>::new();
    cipher_suites.push(CipherSuite::TLS_AES_128_GCM_SHA256);
    cipher_suites.push(CipherSuite::TLS_AES_256_GCM_SHA384);
    // cipher_suites.push(CipherSuite::TLS_CHACHA20_POLY1305_SHA256);
    cipher_suites.push(CipherSuite::Unknown(0x00ff));

    let extensions = vec![
        Extension::ServerName(vec![ServerName::HostName(String::from("localhost"))]),
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

    ClientHello {
        legacy_version: 0x0303,
        random: random_fixed,
        legacy_session_id: session_id,
        cipher_suites: cipher_suites,
        legacy_compression_methods: vec![0],
        extensions: extensions,
    }
}

async fn read_multistream_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<usize, Box<dyn Error>> {
    let mut buf: [u8; 1] = [0; 1];
    let mut value: usize = 0;
    loop {
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(error!("Unexpected end of input")),
            Ok(_) => {
                let b = buf[0];
                value = (value << 7) | ((b & 0x7f) as usize);
                if b & 0x80 == 0 {
                    break;
                }
            }
        };
    }
    Ok(value)
}

async fn read_multistream_data(reader: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>, Box<dyn Error>> {
    let expected_len = read_multistream_varint(reader).await?;
    // println!("expected_len = {}", expected_len);
    let mut incoming_data: Vec<u8> = Vec::new();

    let mut got_len: usize = 0;
    while got_len < expected_len {
        let mut buf: [u8; 1] = [0; 1];
        match reader.read(&mut buf).await {
            Err(e) => return Err(e.into()),
            Ok(0) => return Err(error!("Unexpected end of input")),
            Ok(_) => {
                incoming_data.push(buf[0]);
                got_len += 1;
            }
        };
    }
    Ok(incoming_data)
}

async fn write_multistream_data(writer: &mut (impl AsyncWrite + Unpin), data: &[u8]) -> Result<(), Box<dyn Error>> {
    let len_bytes = VarInt::encode_usize(data.len());
    writer.write_all(&len_bytes).await?;
    writer.write_all(&data).await?;
    writer.flush().await?;
    Ok(())
}

async fn write_multistream_data_client(
    conn: &mut EstablishedConnection,
    data: &[u8],
) -> Result<(), Box<dyn Error>>
{
    let len_bytes = VarInt::encode_usize(data.len());
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&len_bytes);
    buf.extend_from_slice(&data);
    // writer.flush().await?;
    conn.write_normal(&buf).await?;
    Ok(())
}






fn generate_certificate(
    key_pair: &RsaKeyPair,
    libp2p_ext_public_key: &[u8],
    libp2p_ext_signature: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {

    let mut libp2p_ext_items: Vec<Item> = Vec::new();


    // libp2p_ext_items.push(Item::from(Value::BitString(BitString {
    //     bytes: Vec::from(libp2p_ext_public_key),
    //     unused_bits: 0,
    // })));
    // libp2p_ext_items.push(Item::from(Value::BitString(BitString {
    //     bytes: Vec::from(libp2p_ext_signature),
    //     unused_bits: 0,
    // })));

    libp2p_ext_items.push(Item::from(Value::OctetString(Vec::from(libp2p_ext_public_key))));
    libp2p_ext_items.push(Item::from(Value::OctetString(Vec::from(libp2p_ext_signature))));






    let mut libp2p_ext_item = Item::from(Value::Sequence(libp2p_ext_items));
    let mut libp2p_ext_bytes: Vec<u8> = Vec::new();
    encode_item(&libp2p_ext_item, &mut libp2p_ext_bytes)?;


    // pub serial_number: Integer,
    let serial_number = from_hex("00fece0a9eaa3eddc3")
        .ok_or_else(|| error!("Invalid hex string: serial_number"))?;

    let authority_key_identifier = from_hex(
        &format!("{}{}",
        "3050a143a441303f310b300906035504061302555331173015060355040a0c0e4d7920506572736f6e",
        "616c2043413117301506035504030c0e6d792e706572736f6e616c2e6361820900d7c3d885fa68751d"))
        .ok_or_else(|| error!("Invalid hex string: authority_key_identifier"))?;
    let basic_constraints = from_hex("3000")
        .ok_or_else(|| error!("Invalid hex string: basic_constraints"))?;
    let key_usage = from_hex("030204f0")
        .ok_or_else(|| error!("Invalid hex string: key_usage"))?;


    // let subject_key_pair = std::fs::read(&subcmd.subject_private_key)
    //     .map_err(|e| error!("{}: {}", subcmd.subject_private_key, e))?;
    // println!("Got subject_key_pair");
    // let subject_key_pair = RsaKeyPair::from_der(&subject_key_pair)?;
    // println!("Got subject_key_pair");
    let subject_public_key: Vec<u8> = Vec::from(key_pair.public_key().as_ref());



    // let signer_key_pair_bytes = std::fs::read(&subcmd.signer_private_key)
    //     .map_err(|e| error!("{}: {}", subcmd.signer_private_key, e))?;
    // println!("Got signer_key_pair");
    // let signer_key_pair = RsaKeyPair::from_der(&signer_key_pair_bytes)?;



    // println!("generate: subject_key = {:?}", subcmd.subject_key);
    // println!("generate: signing_key = {:?}", subcmd.signing_key);
    // println!("generate: output = {:?}", subcmd.output);
    let tbs_certificate = TBSCertificate {
        version: Version::V3,
        serial_number: Integer(serial_number.clone()),
        signature: AlgorithmIdentifier {
            algorithm: ObjectIdentifier(Vec::from(CRYPTO_SHA_256_WITH_RSA_ENCRYPTION)),
            parameters: Some(Item::from(Value::Null)),
        },
        issuer: Name { parts: vec![
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COUNTRY_NAME)),
                value: Item::from(Value::PrintableString(String::from("US"))),
            },
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_ORGANIZATION_NAME)),
                value: Item::from(Value::UTF8String(String::from("My Personal CA"))),
            },
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COMMON_NAME)),
                value: Item::from(Value::UTF8String(String::from("my.personal.ca"))),
            } ] },
        validity: Validity {
            not_before: Time::UTCTime(UTCTime { data: String::from("210515162539Z") }),
            not_after: Time::UTCTime(UTCTime {  data: String::from("220312162539Z") }),
        },
        subject: Name { parts: vec![
            RelativeDistinguishedName {
                id: ObjectIdentifier(Vec::from(X509_COMMON_NAME)),
                value: Item::from(Value::UTF8String(String::from("client"))),
            } ] },
        subject_public_key_info: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier {
                algorithm: ObjectIdentifier(Vec::from(CRYPTO_RSA_ENCRYPTION)),
                parameters: Some(Item::from(Value::Null)),
            },
            subject_public_key: BitString {
                unused_bits: 0,
                bytes: subject_public_key,
            },
        },
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: vec![
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_AUTHORITY_KEY_IDENTIFIER)),
                critical: false,
                data: authority_key_identifier,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_BASIC_CONSTRAINTS)),
                critical: false,
                data: basic_constraints,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from(X509_KEY_USAGE)),
                critical: false,
                data: key_usage,
            },
            x509::Extension {
                id: ObjectIdentifier(Vec::from([1, 3, 6, 1, 4, 1, 53594, 1, 1])),
                critical: true,
                data: libp2p_ext_bytes,
            }
        ],
    };

    let output_data = sign_tbs_certificate(&tbs_certificate, &key_pair)?;
    // std::fs::write(&subcmd.output, &output_data).map_err(|e| error!("{}: {}", subcmd.output, e))?;
    // println!("Wrote {}", subcmd.output);

    Ok(output_data)
}

fn sign_tbs_certificate(
    tbs_certificate: &x509::TBSCertificate,
    signer_key_pair: &ring::signature::RsaKeyPair) -> Result<Vec<u8>, Box<dyn Error>> {


    let mut encoded_tbs_certificate: Vec<u8> = Vec::new();
    encode_item(&tbs_certificate.to_asn1(), &mut encoded_tbs_certificate)?;

    let mut signature = vec![0; signer_key_pair.public_modulus_len()];
    let rng = ring::rand::SystemRandom::new();

    let encoding = &ring::signature::RSA_PKCS1_SHA256;
    // let encoding = &ring::signature::RSA_PSS_SHA256; // bad
    signer_key_pair.sign(encoding, &rng, &encoded_tbs_certificate, &mut signature)
        .map_err(|e| error!("Signing failed: {}", e))?;


    let signature_algorithm = AlgorithmIdentifier {
        algorithm: ObjectIdentifier(Vec::from(CRYPTO_SHA_256_WITH_RSA_ENCRYPTION)),
        parameters: Some(Item::from(Value::Null)),
    };
    let signature_value = BitString {
        unused_bits: 0,
        bytes: signature,
    };

    wrap_signature(tbs_certificate, &signature_algorithm, &signature_value)
}

fn wrap_signature(
    tbs_certificate: &TBSCertificate,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &BitString) -> Result<Vec<u8>, Box<dyn Error>> {

    let mut items: Vec<Item> = Vec::new();
    items.push(tbs_certificate.to_asn1());
    items.push(signature_algorithm.to_asn1());
    items.push(Item::from(Value::BitString(signature_value.clone())));
    let item = Item::from(Value::Sequence(items));

    let mut output_data: Vec<u8> = Vec::new();
    encode_item(&item, &mut output_data)?;
    Ok(output_data)
}





































#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // println!("Start");

    // let rng = ring::rand::SystemRandom::new();
    // let mut bytes: [u8; 32] = [0; 32];
    // ring::rand::SecureRandom::fill(&rng, &mut bytes)?;
    // println!("Filled {} bytes from ring's SystemRandom", bytes.len());



    use ed25519_dalek::{Keypair, Signature, Signer};
    // use rand_chacha::rand_core::SeedableRng;
    // use ed25519_dalek::*;

    // let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
    let mut rng = rand::rngs::OsRng {};
    let dalek_keypair: Keypair = Keypair::generate(&mut rng);


    use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};

    let public_key = &dalek_keypair.public;

    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.to_bytes();     // 32
    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = dalek_keypair.secret.to_bytes(); // 32
    let keypair_bytes:    [u8; KEYPAIR_LENGTH]    = dalek_keypair.to_bytes();        // 64
    // let signature_bytes:  [u8; SIGNATURE_LENGTH]  = signature.to_bytes();


    println!("public_key_bytes.len() = {}", public_key_bytes.len());
    println!("secret_key_bytes.len() = {}", secret_key_bytes.len());
    println!("keypair_bytes.len()    = {}", keypair_bytes.len());


    let libp2p_public_key = PublicKey {
        key_type: KeyType::Ed25519,
        data: Vec::from(public_key_bytes),
    };
    let libp2p_public_key_bytes = libp2p_public_key.to_pb();


    // use rand::{RngCore, thread_rng};
    // use rand::SeedableRng;
    // use rsa::PrivateKeyEncoding;
    // // let mut rng = rand::rngs::OsRng;


    // println!("Here 0");
    // let mut key = [0u8; 16];
    // OsRng.fill_bytes(&mut key);
    // let random_u64 = OsRng.next_u64();
    // println!("random_u64 = {}", random_u64);

    // println!("Here 1");
    // let new_private_key = rsa::RSAPrivateKey::new(&mut rng, 2048)?;
    // println!("Here 2");
    // let new_private_key_pkcs8: Vec<u8> = new_private_key.to_pkcs1()?;
    // println!("Here 3");
    // let key_pair = ring::signature::RsaKeyPair::from_der(&new_private_key_pkcs8)?;
    // println!("Generated key pair");
    // let certificate = generate_certificate(&key_pair)?;
    // println!("Generated certificate");

    println!("Before openssl key generation");
    let local_rsa_private_key = openssl::rsa::Rsa::generate(2048)?;
    let client_key = local_rsa_private_key.private_key_to_der()?;
    println!("After openssl key generation");

    // let client_cert = std::fs::read("nginx/conf/client.crt.der")?;
    // let client_key = std::fs::read("nginx/conf/client.key.der")?;

    let key_pair = ring::signature::RsaKeyPair::from_der(&client_key)?;
    println!("Generated key pair");



    let p2p_subject_public_key_info = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: ObjectIdentifier(Vec::from(CRYPTO_RSA_ENCRYPTION)),
            parameters: Some(Item::from(Value::Null)),
        },
        subject_public_key: BitString {
            unused_bits: 0,
            bytes: Vec::from(key_pair.public_key().as_ref()),
        },
    };
    let p2p_subject_public_key_info_item = p2p_subject_public_key_info.to_asn1();
    let mut p2p_subject_public_key_info_bytes: Vec<u8> = Vec::new();
    encode_item(&p2p_subject_public_key_info_item, &mut p2p_subject_public_key_info_bytes)?;











    let mut signature_input: Vec<u8> = Vec::new();
    signature_input.extend_from_slice(b"libp2p-tls-handshake:");
    // signature_input.extend_from_slice(key_pair.public_key().as_ref());
    signature_input.extend_from_slice(&p2p_subject_public_key_info_bytes);
    let signature: Signature = dalek_keypair.sign(&signature_input);

    let certificate: Vec<u8> = generate_certificate(
        &key_pair,
        &libp2p_public_key_bytes,
        &signature.to_bytes())?;
    println!("Generated certificate");

    let config = ClientConfig {
        client_auth: ClientAuth::Certificate {
            cert: certificate,
            key: client_key,
        },
        server_auth: ServerAuth::SelfSigned,
    };









    let mut socket = TcpStream::connect("localhost:4001").await?;


    write_multistream_data(&mut socket, b"/multistream/1.0.0\n").await?;
    write_multistream_data(&mut socket, b"/tls/1.0.0\n").await?;

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    let data = read_multistream_data(&mut socket).await?;
    println!("{:#?}", &DebugHexDump(&data));
    println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));







    let rng = SystemRandom::new();
    let private_key = EphemeralPrivateKey::generate(&X25519, &rng)?;
    let public_key = private_key.compute_public_key()?;
    println!("public_key_bytes    = {}", BinaryData(public_key.as_ref()));

    let client_hello = make_client_hello(public_key.as_ref());
    let handshake = Handshake::ClientHello(client_hello);

    println!("Before establish_connection()");
    let mut conn = establish_connection(config, Box::new(socket), &handshake, private_key).await?;
    println!("After establish_connection()");

    let mut buf = vec_with_len(65536);
    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    write_multistream_data_client(&mut conn, b"/multistream/1.0.0\n").await?;
    // write_multistream_data_client(&mut conn, b"ls\n").await?;

    write_multistream_data_client(&mut conn, b"/mplex/6.7.0\n").await?;

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    let r = conn.read(&mut buf).await?;
    println!("Read {} bytes", r);
    println!("data =\n{:#?}", DebugHexDump(&buf[0..r]));

    // let data = read_multistream_data(&mut socket).await?;
    // println!("{:#?}", &DebugHexDump(&data));
    // println!("Got {}", escape_string(&String::from_utf8_lossy(&data)));

    Ok(())
}
