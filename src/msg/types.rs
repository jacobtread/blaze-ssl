use crate::msg::codec::{Codec, Reader};
use ring::rand::{SecureRandom, SystemRandom};

/// The certificate must be DER-encoded X.509.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct Certificate(pub Vec<u8>);

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
