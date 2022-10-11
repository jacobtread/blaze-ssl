use crate::msg::codec::{decode_vec_u16, decode_vec_u8, encode_vec_u24, u24, Codec, Reader};
use crate::msg::constants::{PROTOCOL_SSL3, TLS_RSA_WITH_RC4_128_SHA};
use crate::msg::types::Certificate;
use crate::msg::types::SSLRandom;
use crate::msg::{Message, MessageType};

#[derive(Debug)]
pub enum HandshakePayload {
    ClientHello(u16, SSLRandom),
    ServerHello(SSLRandom),
    Certificate(Certificate),
    ServerHelloDone,
    ClientKeyExchange(Vec<u8>),
    Finished {
        md5_hash: [u8; 16],
        sha_hash: [u8; 20],
    },
    Unknown,
}

impl HandshakePayload {
    const CLIENT_HELLO: u8 = 1;
    const SERVER_HELLO: u8 = 2;
    const CERTIFICATE: u8 = 11;
    const SERVER_HELLO_DONE: u8 = 14;
    const CLIENT_KEY_EXCHANGE: u8 = 16;
    const FINISHED: u8 = 20;

    fn value(&self) -> u8 {
        match self {
            HandshakePayload::ClientHello(_, _) => Self::CLIENT_HELLO,
            HandshakePayload::ServerHello(_) => Self::SERVER_HELLO,
            HandshakePayload::Certificate(_) => Self::CERTIFICATE,
            HandshakePayload::ServerHelloDone => Self::SERVER_HELLO_DONE,
            HandshakePayload::ClientKeyExchange(_) => Self::CLIENT_KEY_EXCHANGE,
            HandshakePayload::Finished { .. } => Self::FINISHED,
            HandshakePayload::Unknown => 0,
        }
    }

    pub fn as_message(&self) -> Message {
        let payload = self.encode();
        Message {
            ty: MessageType::Handshake,
            payload,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        match self {
            HandshakePayload::ServerHello(random) => {
                PROTOCOL_SSL3.encode(&mut content);
                random.encode(&mut content);

                // NO-OP Session ID
                content.push(0);

                TLS_RSA_WITH_RC4_128_SHA.encode(&mut content);

                // Null Compression hard coded
                content.push(0);
            }
            HandshakePayload::Certificate(certificate) => {
                encode_vec_u24(&mut content, &mut vec![certificate.clone()]);
            }
            HandshakePayload::Finished { md5_hash, sha_hash } => {
                content.extend_from_slice(md5_hash);
                content.extend_from_slice(sha_hash);
            }
            _ => {}
        }
        let mut output = Vec::with_capacity(content.len() + 4);
        let content_length = u24(content.len() as u32);
        output.push(self.value());
        content_length.encode(&mut output);
        output.append(&mut content);
        output
    }

    pub fn decode(input: &mut Reader) -> Option<Self> {
        let ty = input.take_byte()?;
        println!("Hit type {ty}");
        let length = u24::decode(input)?.0 as usize;
        let mut contents = input.slice(length)?;
        Some(match ty {
            HandshakePayload::CLIENT_HELLO => {
                let client_version = u16::decode(&mut contents)?;
                let client_random = SSLRandom::decode(&mut contents)?;
                let _session = decode_vec_u8::<u8>(&mut contents)?;
                let _cipher_suites = decode_vec_u16::<u16>(&mut contents)?;
                let _compression_methods = decode_vec_u8::<u8>(&mut contents)?;
                HandshakePayload::ClientHello(client_version, client_random)
            }
            HandshakePayload::CLIENT_KEY_EXCHANGE => {
                HandshakePayload::ClientKeyExchange(contents.remaining().to_vec())
            }
            HandshakePayload::FINISHED => {
                let mut md5_hash = [0; 16];
                let mut sha_hash = [0; 20];
                let bytes = contents.take(16)?;
                md5_hash.clone_from_slice(bytes);
                let bytes = contents.take(20)?;
                sha_hash.clone_from_slice(bytes);
                HandshakePayload::Finished { md5_hash, sha_hash }
            }
            _ => HandshakePayload::Unknown,
        })
    }
}