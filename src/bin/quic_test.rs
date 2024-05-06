#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_mut)]
#![allow(unused_assignments)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(non_upper_case_globals)]

use std::error::Error;
use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::collections::BTreeMap;
use clap::Parser;
use ring::rand::{SystemRandom, SecureRandom};
use ring::agreement::{EphemeralPrivateKey, PublicKey, X25519};
use quinn::Endpoint;
use tokio::net::UdpSocket;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use ngfs::ipfs::types::multibase::{
    DecodeError,
    Base,
    encode,
    encode_noprefix,
    decode,
    decode_noprefix,
};
use ngfs::crypto::aead::AeadAlgorithm;
use ngfs::crypto::crypt::{HashAlgorithm, Hasher};
use ngfs::crypto::error::CryptError;
use ngfs::quic::encryption::{
    add_header_protection,
    remove_header_protection,
    encrypt_payload,
    decrypt_payload,
};
use ngfs::quic::spec::{
    Frame,
    CryptoFrame,
    ConnectionCloseFrame,
    Packet,
    PacketType,
    ConnectionId,
    EndpointType,
};
use ngfs::quic::wire::{ConnectionSecrets, EndpointSecrets};
use ngfs::quic::parameters::TransportParameter;
use ngfs::tls::helpers::hkdf_expand_label2;
use ngfs::tls::types::handshake::{Handshake, CipherSuite, ClientHello};
use ngfs::tls::types::extension::{
    Extension,
    TransportParameters,
    ECPointFormat,
    NamedCurve,
    SignatureScheme,
    KeyShareEntry,
    NamedGroup,
    PskKeyExchangeMode,
    ProtocolName,
};
use ngfs::util::binary::{BinaryReader, BinaryWriter, ToBinary, BinaryError};
use ngfs::util::util::{BinaryData, DebugHexDump, Indent};

const raw_crypto_frame_str: &str = "
060040f1010000ed0303ebf8fa56f129 39b9584a3896472ec40bb863cfd3e868
04fe3a47f06a2b69484c000004130113 02010000c000000010000e00000b6578
616d706c652e636f6dff01000100000a 00080006001d00170018001000070005
04616c706e0005000501000000000033 00260024001d00209370b2c9caa47fba
baf4559fedba753de171fa71f50f1ce1 5d43e994ec74d748002b000302030400
0d0010000e0403050306030203080408 050806002d00020101001c0002400100
3900320408ffffffffffffffff050480 00ffff07048000ffff08011001048000
75300901100f088394c8f03e51570806 048000ffff";

const raw_initial_packet_str: &str = "
c000000001088394c8f03e5157080000 449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c 0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a12 82a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba1 7c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89 eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae81215 4682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf3 62c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e 610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5 eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d8 2df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7 961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4 faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d874 3eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7 fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a 33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a22 9a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf 330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f0 5796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576 f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff2 8f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f 6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37 252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accd d5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4 dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c 4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a07 1b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b4381303 68cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e5 66d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499d bd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433 bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885 c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723 c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd8 04a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356f bf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905dd f3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be 0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b 8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
";

const quinn_initial_packet_str: &str = "
c2 00 00 00 01 14 47 e5  7e 88 45 27 cf cd 85 dc
73 7c 1d 21 35 ed 9f ba  96 54 08 d0 c2 67 58 f7
d6 e4 5d 00 44 8a b4 1b  f4 f9 77 4c e0 94 1a 1f
af de a4 ce ca bf 29 f1  d6 c0 f9 cc a0 9e 09 78
5d f1 32 7d 90 d8 13 3d  57 25 e0 c0 99 9f 4d 50
8e 20 4e d3 5a cc 78 41  1e f8 62 a8 a9 db ff 1f
54 41 2b 7b 20 ff 51 a6  ed 16 4e de 23 f4 4b 36
32 d6 f2 fa 05 7a fd 59  f5 8b 35 b3 22 e6 07 72
d0 e7 0c a9 6a e3 e9 aa  7e d5 29 92 6e 21 f5 40
6f 52 ce 1d 3f 08 9c 31  19 be 52 54 4f fa 1e 30
90 bb 0e 82 fa 94 46 92  8d e4 c9 67 ea 9e 8d 1b
78 84 25 59 a0 9b 61 f6  98 ea 48 fd 9d 97 3d a4
43 d1 bd 3b f9 c1 a6 2e  b4 c6 12 df f1 10 16 df
ae 4d e5 a1 11 97 ef ca  a2 73 38 2f 6a 26 d1 a5
a1 2e d6 e2 0a 09 a1 d4  b3 11 5a e2 77 e2 e8 1b
d2 e9 21 d8 ac 69 ca 13  32 b4 e1 bf de 4d 04 39
8a 4a 9c 1b d2 12 2e 51  27 d2 3b 66 0b 63 a0 e6
bc bf f2 07 00 4d cd a9  bb 5e e5 4c f3 c1 f1 4f
56 04 d1 8b c0 c4 93 7d  59 60 95 9e 10 80 41 1a
9c ba 3d 05 3c 07 38 b2  95 ef ba 9e 06 64 1e 29
ca 24 33 12 80 cb 1c ed  37 1a b2 d0 70 30 7f d0
f9 8a ec 60 1d 5c f3 4d  6b 61 43 4f b9 e6 56 f5
0d 02 f9 fd ef ab e5 e6  7a 3b f5 4f 97 bc 2f ff
52 da 75 60 8e 51 3c 7a  dc 34 25 eb a6 f4 ff 76
bd e9 89 bd 4b 98 d7 4c  d1 cc 7f 46 60 29 54 5f
d0 8f 2f 57 23 f9 c2 8c  99 7f d0 b4 9a 3b 36 fa
61 be 92 82 2f 6f 93 0a  66 3b d2 35 ed f0 bd 48
61 1a 89 23 17 9c c7 a2  75 28 ee 82 d0 e2 da 3d
5a 51 14 9f 73 0a 9d 02  c6 8c ab 19 87 10 b2 48
ab d4 39 8a 87 7d 73 76  a7 d2 f6 b9 29 90 14 c2
c9 5d f9 8f 6b fd 5b 1f  2d 62 6a b9 13 13 b0 d4
0d 0b 16 96 30 59 7a 1f  e2 e6 62 0b 7c 0f fa f2
da 48 3c 0e 4b 05 f6 36  33 d1 dc c5 9b 6c 37 6e
f6 ae a9 b5 4e 66 f9 eb  f6 79 4e a1 fd 14 3f bf
07 d4 71 27 31 1b 81 98  78 6d 46 fc a2 74 2e 68
ed 3a 62 ce 25 96 e1 78  ac a1 ca 8c a5 53 73 32
65 11 42 b1 13 d4 16 de  a1 2a 9a 41 33 a8 5c 9d
32 1f f0 c6 57 94 ac b1  23 31 7b 6e 26 22 1b 5d
c5 e7 17 1b 58 0b 2f d4  46 a5 42 64 a6 c0 89 b2
48 89 48 7b 40 ba 68 a8  65 f6 02 a1 45 9f b0 5a
76 f6 be 3d d6 9f 19 39  ca 38 d6 ed 49 d0 95 06
d8 12 2d 7a 36 57 8e 86  f0 f5 19 7a f5 c6 64 ee
69 2d 51 29 72 fc 81 df  02 68 4c 60 22 db 0a e8
e2 3a d5 99 75 81 23 3f  a7 f5 8f 9c b6 dd cb de
8d 09 65 ef 5e 8b ac 8b  26 0d b3 10 89 35 bc 62
c1 38 9f e7 48 61 3f b1  51 0b 1d e5 c3 fe 49 66
89 b6 fd 82 5c d2 18 58  05 75 b9 ed 93 6c b7 cd
74 5e fa ea 2b ff e5 96  c2 13 6e 50 c2 6a d8 d4
ef 43 41 09 ba ad b6 04  fc f5 fd 7d 39 ba ef a2
0c 27 b5 4c 0e bf 33 d0  e0 bc 0f 9a bc a0 e4 0a
e3 58 9c f0 bf 6a 58 39  8e 89 f2 d4 d2 97 ef a9
5c 76 a7 df b3 b4 e7 d7  3c c3 51 b3 b6 4a 31 4a
4b c6 77 be 4c 56 d0 fa  13 27 02 21 0a 7b 22 06
24 59 e9 be 85 4b fd 3c  16 15 4b 52 f8 6b cf cd
59 fa 9f cc 60 0b b0 f8  ca 58 0e f0 45 64 0a 03
e9 33 25 7e 18 f3 32 9a  d7 ed 7f df d9 17 23 1e
41 59 45 64 c6 75 49 f7  72 1e 48 4d 58 10 53 df
1c 38 e9 17 43 57 12 bf  09 0d 2b 4c 45 01 62 33
5c 57 ff de 0b cd ed 34  9b 57 97 fe 0b 4e 44 c2
9f b8 21 c7 e4 6c 42 80  42 89 e9 0e 72 35 48 04
3a 64 72 79 46 46 6f 77  fa ac 0f 13 1d e3 18 30
ec bc 6e a4 ba 01 13 a0  c4 a2 00 9a c6 64 da f3
7a 0a ed e7 50 30 bd 56  e3 47 5d 0e 5c 76 1d ed
0f 95 5a 3f 7a 49 ad 88  89 c0 21 5c 83 06 61 65
d9 fb 74 8d b7 9c a4 a7  2a 85 bb ee 0b a9 05 2b
b0 a6 f3 e0 fd 6b 9e 0a  81 9c 35 81 f4 61 fa 2d
19 03 4a 53 88 c1 33 d6  30 df 05 4b f9 43 da 54
cf 3e 24 bb 09 a6 71 12  e6 ab b5 08 4d 4a 2f 16
13 ca 67 00 72 7b af 50  43 7c b6 38 97 b6 d8 30
99 eb d8 fc 5b 9f b3 81  d2 61 87 fa 01 09 50 5a
df 4f 28 45 c6 ce ab 8d  99 37 4b b1 73 ac ab 30
65 07 f3 22 c1 6f 7a 8e  e3 7b 32 a3 de 7c 95 d2
18 29 57 30 42 73 df dd  41 09 54 f0 79 31 57 b9
d1 dd 70 83 8c 91 92 d8  ea be e3 ee 92 6d 0d a3
45 c5 b7 59 ff 36 e5 12  67 b3 75 ce 98 7a 41 37
";

fn bytes_from_str(s: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut plain_string = String::new();
    for c in s.chars() {
        match c {
            '0'..='9' |
            'a'..='f' => plain_string.push(c),
            ' ' |
            '\n' => (),
            _ => return Err(format!("Unexpected character: {}", c).into()),
        }
    }
    Ok(decode_noprefix(&plain_string, Base::Base16)?)
}

struct Callbacks {
}

impl Callbacks {
    fn log_dropped_packet(&mut self, reason: &str) {
        println!("Dropped packet: {}", reason);
    }
}

struct ClientSentClientHello {
    server_addr: SocketAddr,
    private_key: EphemeralPrivateKey,
    public_key: PublicKey,
    random: [u8; 32],
}

struct ServerReceivedClientHello {
}

enum ConnectionState {
    ClientSentClientHello(ClientSentClientHello),
    ServerReceivedClientHello(ServerReceivedClientHello),
    Other,
}

struct ConnectionImpl {
    our_connection_id: ConnectionId,
    their_connection_id: ConnectionId,
    secrets: ConnectionSecrets,
    state: ConnectionState,
    endpoint_type: EndpointType,
}

impl ConnectionImpl {
    fn handle_packet(&mut self, packet: Packet, token: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut level = EncryptionLevel::new();
        for frame in packet.frames.iter() {
            match frame {
                Frame::Crypto(f) => {
                    println!("Frame CRYPTO (offset {}, len {})", f.start_offset, f.data.len());
                    println!("{:#?}", Indent(&DebugHexDump(&f.data)));
                    level.crypto_received.extend_from_slice(&f.data);

                    // let message = Message::from_raw(&plaintext.fragment, plaintext.content_type)
                    //     .map_err(|_| TLSError::InvalidMessageRecord)?;

                    // let mut reader = BinaryReader::new(&f.data);
                    // let handshake = reader.read_item::<Handshake>()?;
                    // println!("Handshake: {:#?}", handshake);
                }
                _ => {
                    println!("Frame {:?}", frame);
                }
            }
        }
        Self::process_initial_handshakes(&mut level, &packet, token)?;
        Ok(())
    }

    fn process_initial_handshakes(
        level: &mut EncryptionLevel,
        packet: &Packet,
        token: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let mut first = true;

        while let Some(handshake) = level.try_pop_handshake()? {
            // println!("Handshake: {:#?}", handshake);

            println!("Received {}", handshake.name());
            if let Handshake::ClientHello(client_hello) = &handshake {
                println!("{:#?}", handshake);
                let mut decoded_params: Vec<TransportParameter> = Vec::new();
                for extension in client_hello.extensions.iter() {
                    if let Extension::TransportParameters(tp) = extension {
                        decoded_params = TransportParameter::decode_list(&tp.0)?;
                        assert!(TransportParameter::encode_list(&decoded_params) == tp.0);
                    }
                }
                println!("decoded_params =");
                println!("{:#?}", decoded_params);
            }
            else {
                println!("{:#?}", handshake);
            }

            if first {
                // if let Some(cb_recv_initial) = &handler.cb_recv_initial {
                    let hash_alg = HashAlgorithm::SHA256;
                    let secrets = ConnectionSecrets::from_connection_id(hash_alg, &packet.dst_connection_id)?;
                    // cb_recv_initial(
                    //     &packet.dst_connection_id,
                    //     &packet.src_connection_id,
                    //     token,
                    //     &handshake,
                    //     &secrets.client,
                    // );

                // }

                // make_initial(
                //     &packet.dst_connection_id,
                //     &packet.src_connection_id,
                //     token,
                //     &handshake,
                // );


                first = false;
            }
        }
        Ok(())
    }
}

struct Handler {
    cb: Callbacks,
    connections: BTreeMap<ConnectionId, ConnectionImpl>,
}

fn parse_frames(data: &[u8]) -> Result<Vec<Frame>, Box<dyn Error>> {
    let mut reader = BinaryReader::new(data);
    let mut frames: Vec<Frame> = Vec::new();
    let mut padding_len = 0;

    while reader.remaining() > 0 {
        let frame_type = reader.read_u8()?;
        match frame_type {
            0x00 => {
                // Padding; ignore
                // frames.push(Frame::Padding);
                padding_len += 1;
            }
            0x02 => {
                frames.push(Frame::Ping);
            }
            0x06 => {
                let offset = reader.read_quic_varint()?;
                let length = reader.read_quic_varint()?;
                // println!("CRYPTO frame: offset {}, length {}", offset, length);
                // todo!()
                let data = Vec::from(reader.read_fixed(length as usize)?);
                frames.push(Frame::Crypto(CryptoFrame {
                    start_offset: offset,
                    data: data,
                }))
            }
            0x1c => {
                let error_code = reader.read_quic_varint()?;
                let frame_type = reader.read_quic_varint()?;
                let reason_len = reader.read_quic_varint()?;
                let reason = String::from_utf8_lossy(reader.read_fixed(reason_len as usize)?).to_string();
                println!("CONNECTION_CLOSE");
                println!("error_code = {}", error_code);
                println!("frame_type = {}", frame_type);
                println!("reason = {:?}", reason);
                frames.push(Frame::ConnectionClose(ConnectionCloseFrame {
                    error_code,
                    frame_type: Some(frame_type),
                    reason,
                }));
            }
            _ => {
                return Err(format!("Unknown frame type 0x{:02x}", frame_type).into());
            }
        }
    }
    println!("parse_frames: padding_len = {}", padding_len);

    // reader.expect_eof()?;
    Ok(frames)
}

fn make_initial(
    dst_connection_id: &ConnectionId,
    src_connection_id: &ConnectionId,
    token: &[u8],
    handshake: &Handshake,
    secrets: &EndpointSecrets,
) {
    match make_initial1(dst_connection_id, src_connection_id, token, handshake, secrets) {
        Ok(_) => println!("make_initial: ok"),
        Err(e) => println!("make_initial: error: {}", e),
    }
}

fn make_initial1(
    dst_connection_id: &ConnectionId,
    src_connection_id: &ConnectionId,
    token: &[u8],
    handshake: &Handshake,
    secrets: &EndpointSecrets,
) -> Result<(), Box<dyn Error>> {
    println!("make_initial: handshake = {:#?}", handshake);
    let packet = make_initial2(dst_connection_id, src_connection_id, token, handshake, secrets)?;
    let expected_filename = "packet-expected.bin";
    let expected = bytes_from_str(raw_initial_packet_str)?;
    std::fs::write(expected_filename, &expected)?;
    println!("Wrote {}", expected_filename);

    let actual_filename = "packet-actual.bin";
    std::fs::write(actual_filename, &packet)?;
    println!("Wrote {}", actual_filename);
    println!("expected == actual ? {}", expected == packet);
    Ok(())
}


fn make_initial2(
    dst_connection_id: &ConnectionId,
    src_connection_id: &ConnectionId,
    token: &[u8],
    handshake: &Handshake,
    secrets: &EndpointSecrets,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut handshake_writer = BinaryWriter::new();
    handshake.to_binary(&mut handshake_writer)?;
    let handshake_data = Vec::from(handshake_writer);

    let mut payload = BinaryWriter::new();
    payload.write_u8(0x06); // CRYPTO frame
    payload.write_quic_varint(0); // offset
    payload.write_quic_varint(handshake_data.len() as u64); // len
    payload.write_raw(&handshake_data);

    encode_initial_packet(
        dst_connection_id,
        src_connection_id,
        0,
        token,
        payload.as_ref(),
        secrets,
    )
}

fn encode_initial_packet(
    dst_connection_id: &ConnectionId,
    src_connection_id: &ConnectionId,
    packet_no: u64,
    token: &[u8],
    payload: &[u8],
    secrets: &EndpointSecrets,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let min_packet_len = 1200;
    let hash_alg = HashAlgorithm::SHA256;
    let aead_alg = AeadAlgorithm::AES_128_GCM_SHA256;

    let packet_number_length = 4;

    let mut header = BinaryWriter::new();
    let byte0: u8 = 0xc3;
    header.write_u8(byte0);
    header.write_raw(&[0x00, 0x00, 0x00, 0x01]); // version
    header.write_u8(dst_connection_id.0.len() as u8);
    header.write_raw(&dst_connection_id.0);
    header.write_u8(src_connection_id.0.len() as u8);
    header.write_raw(&src_connection_id.0);
    header.write_quic_varint(token.len() as u64);
    header.write_raw(token);
    let length_offset = header.len();
    header.write_u16(0); // fill in later
    let pn_offset = header.len();
    header.write_u32(packet_no as u32);
    let mut header = Vec::from(header);

    let mut payload = Vec::from(payload);

    let size_without_padding = header.len() + payload.len() + aead_alg.tag_len();
    let mut length = packet_number_length + (payload.len() as u64) + (aead_alg.tag_len() as u64);
    for _ in size_without_padding..min_packet_len {
        payload.push(0);
        length += 1;
    }

    header[length_offset] = ((length >> 8) as u8) | 0x40;
    header[length_offset + 1] = length as u8;

    Ok(encrypt_payload(
        packet_no,
        header.as_ref(),
        pn_offset,
        Vec::from(payload),
        (length - 4) as usize,
        &secrets,
        aead_alg,
    )?)
}

impl Handler {
    fn new() -> Self {
        Handler {
            cb: Callbacks {},
            // cb_recv_initial: None,
            connections: BTreeMap::new(),
        }
    }

    fn log_dropped_packet(&mut self, reason: &str) {
    }

    fn on_recv_packet(&mut self, packet: &mut [u8], addr: SocketAddr) {
        match self.parse_packet(packet, addr) {
            Ok(()) => (),
            Err(e) => {
                println!("Error parsing received packet: {}", e);
            }
        }
    }

    fn parse_packet(&mut self, packet: &mut [u8], addr: SocketAddr) -> Result<(), Box<dyn Error>> {
        let Some(byte0) = packet.get(0) else {
            return Err("Packet is empty".into());
        };

        if byte0 & 0x40 == 0x00 {
            return Err("Fixed bit is zero".into());
        }

        if byte0 & 0x80 == 0x80 {
            self.parse_long_header_packet(packet, addr)
        }
        else {
            self.parse_short_header_packet(packet, addr)
        }
    }

    fn parse_long_header_packet(
        &mut self,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        let mut reader = BinaryReader::new(packet);
        let byte0 = reader.read_u8()?;
        println!("long header packet: byte0 = 0x{:02x} {:08b}", byte0, byte0);
        let version = reader.read_u32()?;
        println!("long header packet: version = {}", version);
        if version != 1 {
            return Err("Unsupported version".into());
        }
        let dcid_len = reader.read_u8()?;
        if dcid_len > 20 {
            return Err("Invalid dst_connection_id length".into());
        }
        let dcid = ConnectionId(Vec::from(reader.read_fixed(dcid_len as usize)?));

        let scid_len = reader.read_u8()?;
        if scid_len > 20 {
            return Err("Invalid src_connection_id length".into());
        }
        let scid = ConnectionId(Vec::from(reader.read_fixed(scid_len as usize)?));
        let offset = reader.abs_offset();

        println!("long header packet: dst_connection_id = {}", dcid);
        println!("long header packet: src_connection_id = {}", scid);

        let long_packet_type = (byte0 & 0x30) >> 4;
        match long_packet_type {
            0x00 => self.parse_initial(byte0, dcid, scid, offset, packet, addr),
            0x01 => self.parse_0rtt(byte0, dcid, scid, offset, packet, addr),
            0x02 => self.parse_handshake(byte0, dcid, scid, offset, packet, addr),
            _    => self.parse_retry(byte0, dcid, scid, offset, packet, addr),
        }
    }

    fn parse_short_header_packet(
        &mut self,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        todo!()
    }

    fn parse_initial(
        &mut self,
        byte0: u8,
        dst_connection_id: ConnectionId,
        src_connection_id: ConnectionId,
        offset: usize,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        let mut reader = BinaryReader::new_at(packet, offset);
        let header_form = (byte0 & 0x80) >> 7;
        let fixed_bit = (byte0 & 0x40) >> 6;
        let long_packet_type = (byte0 & 0x30) >> 4;

        let token_len = reader.read_quic_varint()?;
        let token = Vec::from(reader.read_fixed(token_len as usize)?);
        let length = reader.read_quic_varint()? as usize;

        println!("parse_initial: token_len = {}", token_len);
        println!("parse_initial: length = {}", length);

        let pn_offset = reader.abs_offset();

        let hash_alg = HashAlgorithm::SHA256;
        let aead_alg = AeadAlgorithm::AES_128_GCM_SHA256;

        match self.connections.get_mut(&dst_connection_id) {
            Some(connection_info) => {
                println!("parse_initial: dst_connection_id = {} (existing)", dst_connection_id);
                let secrets = &connection_info.secrets;
                let their_secrets = &secrets.server;

                let (packet_no, payload) = decrypt_payload(packet, pn_offset, length, their_secrets, aead_alg)?;
                let frames = parse_frames(&payload)?;
                connection_info.handle_packet(
                    Packet {
                        frames: frames,
                        src_connection_id,
                        dst_connection_id,
                        packet_no: packet_no,
                        packet_type: PacketType::Initial,
                    },
                    &token)?;
                Ok(())
            }
            None => {
                println!("parse_initial: dst_connection_id = {} (new)", dst_connection_id);
                let secrets = ConnectionSecrets::from_connection_id(hash_alg, &dst_connection_id)?;
                let their_secrets = &secrets.client;


                let mut connection_info = ConnectionImpl {
                    our_connection_id: src_connection_id.clone(),
                    their_connection_id: dst_connection_id.clone(),
                    secrets: secrets.clone(),
                    state: ConnectionState::ServerReceivedClientHello(ServerReceivedClientHello {
                    }),
                    endpoint_type: EndpointType::Server,
                };

                let (packet_no, payload) = decrypt_payload(packet, pn_offset, length, their_secrets, aead_alg)?;
                let frames = parse_frames(&payload)?;
                connection_info.handle_packet(
                    Packet {
                        frames: frames,
                        src_connection_id: src_connection_id.clone(),
                        dst_connection_id,
                        packet_no: packet_no,
                        packet_type: PacketType::Initial,
                    },
                    &token)?;

                self.connections.insert(src_connection_id, connection_info);
                Ok(())
            }
        }
    }

    fn parse_0rtt(
        &mut self,
        byte0: u8,
        dst_connection_id: ConnectionId,
        src_connection_id: ConnectionId,
        offset: usize,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        return Err("TODO: 0-RTT packets".into());
    }

    fn parse_handshake(
        &mut self,
        byte0: u8,
        dst_connection_id: ConnectionId,
        src_connection_id: ConnectionId,
        offset: usize,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        return Err("TODO: Handshake packets".into());
    }

    fn parse_retry(
        &mut self,
        byte0: u8,
        dst_connection_id: ConnectionId,
        src_connection_id: ConnectionId,
        offset: usize,
        packet: &mut [u8],
        addr: SocketAddr,
    ) -> Result<(), Box<dyn Error>> {
        return Err("TODO: Retry packets".into());
    }
}

async fn udp_receiver(handler: Handler, opt: Options) {
    match udp_receiver_inner(handler, opt).await {
        Ok(()) => (),
        Err(e) => println!("Error: {}", e),
    }
}

fn make_client_hello(
    protocol_names: &[&str],
    public_key: &PublicKey,
    transport_parameters: &[TransportParameter],
    random: [u8; 32],
) -> ClientHello {
    let cipher_suites = vec![
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384,
        // CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::Unknown(0x00ff),
    ];

    // let mut extensions = make_extensions(protocol_names, &public_key, transport_parameters);
    let extensions = vec![
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
                key_exchange: Vec::from(public_key.as_ref()),
            }]),
        Extension::TransportParameters(TransportParameters(
            TransportParameter::encode_list(transport_parameters)

            )),
    ];
    ClientHello {
        legacy_version: 0x0303,
        random,
        legacy_session_id: vec![],
        cipher_suites,
        legacy_compression_methods: vec![0],
        extensions,
    }
}


async fn udp_receiver_inner(mut handler: Handler, opt: Options) -> Result<(), Box<dyn Error>> {
    let sock = UdpSocket::bind("0.0.0.0:8080").await?;

    match &opt.subcmd {
        SubCommand::Client(client) => {
            let dst_connection_id = ConnectionId(vec![0x12, 0x34, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]); // random
            let src_connection_id = ConnectionId(vec![0x56, 0x78]); // ours
            let hash_alg = HashAlgorithm::SHA256;
            let secrets = ConnectionSecrets::from_connection_id(hash_alg, &dst_connection_id)?;

            let token: Vec<u8> = vec![];
            let mut random: [u8; 32] = Default::default();
            SystemRandom::new().fill(&mut random)?;


            let private_key: EphemeralPrivateKey = EphemeralPrivateKey::generate(&X25519, &SystemRandom::new())?;
            let public_key: PublicKey = private_key.compute_public_key()?;

            let transport_parameters = &[
                TransportParameter::InitialSourceConnectionId(src_connection_id.clone()),
            ];

            let protocol_names = &["hq-29"];

            let client_hello: ClientHello = make_client_hello(
                protocol_names,
                &public_key,
                transport_parameters,
                random,
            );
            let handshake: Handshake = Handshake::ClientHello(client_hello);

            let initial: Vec<u8> = make_initial2(
                &dst_connection_id,
                &src_connection_id,
                &token,
                &handshake,
                &secrets.client,
            )?;
            let remote_addr = client.addr;
            sock.send_to(&initial, remote_addr).await?;


            let connection_info = ConnectionImpl {
                our_connection_id: src_connection_id.clone(),
                their_connection_id: dst_connection_id.clone(),
                secrets: secrets.clone(),
                state: ConnectionState::ClientSentClientHello(ClientSentClientHello {
                    server_addr: client.addr,
                    private_key: private_key,
                    public_key: public_key,
                    random: random,
                }),
                endpoint_type: EndpointType::Client,
            };
            handler.connections.insert(src_connection_id.clone(), connection_info);
        }
        SubCommand::Server => {
        }
        SubCommand::ParseInitial => {
        }
        // EndpointType::Server => {
        // }
    }


    let mut buf = [0; 4096];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        println!("{:?} bytes received from {:?}", len, addr);
        // println!("{:#?}", Indent(&DebugHexDump(&buf[0..len])));
        handler.on_recv_packet(&mut buf[0..len], addr);
        return Ok(());

        // let len = sock.send_to(&buf[..len], addr).await?;
        // println!("{:?} bytes sent", len);
    }
}

fn test_varint(bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut reader = BinaryReader::new(bytes);
    let varint = reader.read_quic_varint()?;
    println!("varint = {}", varint);
    Ok(())
}

// varint = 151,288,809,941,952,652
// varint = 494,878,333
// varint = 15,293
// varint = 37

pub struct EncryptionLevel {
    pub crypto_received: Vec<u8>,
}

impl EncryptionLevel {
    pub fn new() -> Self {
        EncryptionLevel {
            crypto_received: Vec::new(),
        }
    }

    pub fn try_pop_handshake(&mut self) -> Result<Option<Handshake>, Box<dyn Error>> {
        let mut reader = BinaryReader::new(&self.crypto_received);
        if reader.remaining() < 4 {
            return Ok(None);
        }
        let handshake_type = reader.read_u8()?;
        let length = reader.read_u24()? as usize;
        if reader.remaining() < length {
            return Ok(None);
        }

        let mut reader = BinaryReader::new(&self.crypto_received);
        let handshake = reader.read_item::<Handshake>()?;

        let mut writer = BinaryWriter::new();
        writer.write_item(&handshake)?;
        let mut handshake_data = Vec::from(writer);
        assert!(self.crypto_received == handshake_data);
        // if self.crypto_received == handshake_data {
        //     println!("Handshake round-trip: OK");
        // }
        // else {
        //     println!("Handshake round-trip: MISMATCH");
        // }

        self.crypto_received = self.crypto_received.split_off(reader.abs_offset());
        Ok(Some(handshake))
    }
}

#[derive(Parser)]
#[command(name="quic_test")]
struct Options {
    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Parser)]
enum SubCommand {
    Client(Client),
    Server,
    ParseInitial,
}

#[derive(Parser)]
struct Client {
    #[arg()]
    addr: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // torrent::quic::spec::test()

    // let raw_crypto_frame = bytes_from_str(raw_crypto_frame_str)?;
    // println!("raw_crypto_frame = {:?}    ", raw_crypto_frame);
    // println!("raw_crypto_frame.len() = {}", raw_crypto_frame.len());
    // println!("{:#?}", Indent(&DebugHexDump(&raw_crypto_frame)));

    // test_varint(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c])?;
    // test_varint(&[0x9d, 0x7f, 0x3e, 0x7d])?;
    // test_varint(&[0x7b, 0xbd])?;
    // test_varint(&[0x25])?;




    let opt = Options::parse();

    match &opt.subcmd {
        SubCommand::Client(client) => {
            let mut handler = Handler::new();
            let receiver = tokio::spawn(udp_receiver(handler, opt));
            receiver.await?;
        }
        SubCommand::Server => {
            let mut handler = Handler::new();
            let receiver = tokio::spawn(udp_receiver(handler, opt));
            receiver.await?;
        }
        SubCommand::ParseInitial => {
            let mut handler = Handler::new();
            // handler.cb_recv_initial = Some(Box::new(make_initial));
            // handler.on_recv_packet(&mut bytes_from_str(raw_initial_packet_str)?);
            let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
            handler.on_recv_packet(&mut bytes_from_str(quinn_initial_packet_str)?, addr);
        }
    }

    Ok(())
}
