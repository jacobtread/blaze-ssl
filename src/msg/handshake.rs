use crate::msg::types::ProtocolVersion;

use super::{CipherSuite, Codec, Reader, SSLRandom};

pub enum HandshakePayload {
    ClientHello(ClientHello),
}

#[derive(Debug)]
pub struct ClientHello {
    pub protocol_version: ProtocolVersion,
    pub random: SSLRandom,
    pub cipher_suites: Vec<CipherSuite>,
}

impl Codec for ClientHello {
    fn encode(&self, output: &mut Vec<u8>) {
        self.protocol_version.encode(output);


    }

    fn decode(input: &mut Reader) -> Option<Self> {}
}
