use crate::msg::codec::{decode_u32, Codec, Reader};
use lazy_static::lazy_static;
use ring::rand;
use ring::rand::{SecureRandom, SystemRandom};

lazy_static! {
    pub static ref SSL_V3: &'static ProtocolVersion = &ProtocolVersion(0x0300);
}

/// Structure representing an encoded protocol version.
#[derive(Debug, PartialEq, Eq)]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    pub fn is_valid(&self) -> bool {
        self.0 == 0x0300
    }
}

impl Codec for ProtocolVersion {
    fn encode(&self, output: &mut Vec<u8>) {
        self.0.encode(output);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        Some(ProtocolVersion(u16::decode(input)?))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SSLRandom(pub [u8; 32]);

#[derive(Debug)]
pub struct GetRandomFailed;

impl SSLRandom {
    pub fn new() -> Result<Self, GetRandomFailed> {
        let mut data = [0u8; 32];
        SystemRandom::new()
            .fill(&mut data)
            .map_err(|_| GetRandomFailed)?;
        Ok(Self(data))
    }
}

/// Fill the whole slice with random material.
pub(crate) fn fill_random(bytes: &mut [u8]) -> Result<(), GetRandomFailed> {
    SystemRandom::new().fill(bytes).map_err(|_| GetRandomFailed)
}

/// Return a uniformly random u32.
pub(crate) fn random_u32() -> Result<u32, GetRandomFailed> {
    let mut buf = [0u8; 4];
    fill_random(&mut buf)?;
    decode_u32(&buf).ok_or(GetRandomFailed)
}

impl Codec for SSLRandom {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let bytes = input.take(32)?;
        let mut opaque = [0; 32];
        opaque.clone_from_slice(bytes);
        Some(Self(opaque))
    }
}
