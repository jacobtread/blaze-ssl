use crate::msg::codec::{Codec, Reader};

pub mod codec;
pub mod constants;
pub mod deframer;
pub mod enc;
pub mod handshake;
pub mod joiner;
pub mod types;

pub const SSL_V3: u16 = 0x0300;

/// Raw implementation of a SSL message contains the
/// content type, protocol version and the content
/// bytes
#[derive(Debug)]
pub struct OpaqueMessage {
    pub ty: MessageType,
    pub payload: Vec<u8>,
}

impl Into<OpaqueMessage> for Message {
    fn into(self) -> OpaqueMessage {
        OpaqueMessage {
            ty: self.ty,
            payload: self.payload,
        }
    }
}

/// Represents a SSL message that is in plain text
#[derive(Debug)]
pub struct Message {
    pub ty: MessageType,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MessageType {
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
    Unknown(u8),
}

impl Codec for MessageType {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(match self {
            Self::ChangeCipherSpec => 0x14,
            Self::Alert => 0x15,
            Self::Handshake => 0x16,
            Self::ApplicationData => 0x17,
            Self::Unknown(value) => *value,
        })
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        Some(match input.take_byte()? {
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert,
            0x16 => Self::Handshake,
            0x17 => Self::ApplicationData,
            value => Self::Unknown(value),
        })
    }
}

/// Message where the payload is borrowed from a slice of another message
#[derive(Debug)]
pub struct BorrowedMessage<'a> {
    pub content_type: MessageType,
    pub payload: &'a [u8],
}

#[derive(Debug)]
pub enum MessageError {
    TooShortForHeader,
    TooShortForLength,
    IllegalProtocolVersion,
}

impl OpaqueMessage {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let length = self.payload.len();
        let mut output = Vec::with_capacity(5 + length);
        self.ty.encode(&mut output);
        SSL_V3.encode(&mut output);
        (length as u16).encode(&mut output);
        output.extend_from_slice(&self.payload);
        output
    }

    fn decode(input: &mut Reader) -> Result<Self, MessageError> {
        let content_type = MessageType::decode(input).ok_or(MessageError::TooShortForHeader)?;
        let protocol_version = u16::decode(input).ok_or(MessageError::TooShortForHeader)?;

        let length = u16::decode(input).ok_or(MessageError::TooShortForHeader)?;

        if protocol_version != SSL_V3 {
            return Err(MessageError::IllegalProtocolVersion);
        }

        let mut payload = input
            .slice(length as usize)
            .ok_or(MessageError::TooShortForLength)?;
        let payload = payload.remaining().to_vec();

        Ok(Self {
            ty: content_type,
            payload,
        })
    }
}

impl OpaqueMessage {
    /// This is the maximum on-the-wire size of a TLSCiphertext.
    /// That's 2^14 payload bytes, a header, and a 2KB allowance
    /// for ciphertext overheads.
    const MAX_PAYLOAD: u16 = 16384 + 2048;
    /// Content type, version and size.
    const HEADER_SIZE: u16 = 1 + 2 + 2;
    /// Maximum on-wire message size.
    pub const MAX_WIRE_SIZE: usize = (Self::MAX_PAYLOAD + Self::HEADER_SIZE) as usize;
}
