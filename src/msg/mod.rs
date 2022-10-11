use crate::msg::codec::{Codec, Reader};
use crate::msg::enums::ContentType;
use crate::msg::payload::{Payload, PayloadU16};
use crate::msg::types::{ProtocolVersion, SSL_V3};
use crate::ssl_enum;
use std::fs::read;

pub mod codec;
pub mod data;
pub mod deframer;
pub mod enc;
pub mod enums;
pub mod handshake;
pub mod joiner;
pub mod macros;
pub mod payload;
pub mod types;

/// Raw implementation of a SSL message contains the
/// content type, protocol version and the content
/// bytes
#[derive(Debug)]
pub struct RawMessage {
    pub content_type: ContentType,
    pub payload: Vec<u8>,
}

/// Message where the payload is borrowed from a slice of another message
#[derive(Debug)]
pub struct BorrowedMessage<'a> {
    content_type: ContentType,
    payload: &'a [u8],
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalProtocolVersion,
}

impl RawMessage {
    fn encode(&self) -> Vec<u8> {
        let length = self.payload.len();
        let mut output = Vec::with_capacity(5 + length);
        self.content_type.encode(&mut output);
        SSL_V3.encode(&mut output);
        (length as u16).encode(&mut output);
        output.extend_from_slice(&self.payload);
        output
    }

    fn decode(input: &mut Reader) -> Result<Self, MessageError> {
        let content_type = ContentType::decode(input).ok_or(MessageError::TooShortForHeader)?;
        let protocol_version =
            ProtocolVersion::decode(input).ok_or(MessageError::TooShortForHeader)?;

        let length = u16::decode(input).ok_or(MessageError::TooShortForHeader)?;

        if !protocol_version.is_valid() {
            return Err(MessageError::IllegalProtocolVersion);
        }

        let mut payload = input
            .slice(length as usize)
            .ok_or(MessageError::TooShortForLength)?;
        let payload = payload.remaining().to_vec();

        Ok(Self {
            content_type,
            payload,
        })
    }
}

impl<'a> BorrowedMessage<'a> {
    pub fn encode(&self) -> Vec<u8> {
        let length = self.payload.len();
        let mut output = Vec::with_capacity(5 + length);
        self.content_type.encode(&mut output);
        SSL_V3.encode(&mut output);
        (length as u16).encode(&mut output);
        output.extend_from_slice(&self.payload);
        output
    }
}

impl RawMessage {
    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;
    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;
    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}
