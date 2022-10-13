pub mod handshake;
#[macro_use]
pub mod macros;

mod types;
mod codec;

mod deframer;
mod joiner;

// Re-exports for structures used throught application
pub use deframer::MessageDeframer;
pub use joiner::HandshakeJoiner;
pub use codec::*;
pub use types::*;

/// Structure representing a SSLMessage that has had its header
/// decoded so we know the type of message but we don't know if
/// the payload of the message is SSLPlaintext or SSLCiphertext
/// so it must be converted to a `Message` through the processor
#[derive(Debug)]
pub struct OpaqueMessage {
    /// The type of message this message is
    pub message_type: MessageType,
    /// The opaque payload bytes
    pub payload: Vec<u8>,
}

/// Error types for handling different kinds of issues when
/// decoding Opaque messages.
#[derive(Debug)]
enum MessageError {
    TooShort,
    IllegalVersion,
}

impl OpaqueMessage {
    /// Maximum allowed fragment payload size
    const MAX_PAYLOAD_SIZE: u16 = 16384 + 2048;

    /// Size of Message Type + Version + Length
    const HEADER_SIZE: u16 = 1 + 2 + 2;

    /// Maximum allowed on-wire message size
    const MAX_WIRE_SIZE: usize = (Self::HEADER_SIZE + Self::MAX_PAYLOAD_SIZE) as usize;

    /// Encodes the Opaque message to a Vec of bytes which contains
    /// the SSLMessage header and the payload. Always encodes the
    /// ProtocolVersion as SSLv3
    pub(crate) fn encode(&self) -> Vec<u8> {
        let length = self.payload.len() as u16;
        let mut output = Vec::with_capacity((Self::HEADER_SIZE + length) as usize);
        self.message_type.encode(&mut output);
        ProtocolVersion::SSLv3.encode(&mut output);
        length.encode(&mut output);
        output.extend_from_slice(&self.payload);
        output
    }

    /// Attempts to decode an Opaque message from the provided input
    /// reader. Will return both the message and the message Protocol
    /// Version if the decoding was successful
    pub(crate) fn decode(input: &mut Reader) -> Result<Self, MessageError> {
        let message_type = MessageType::decode(input).ok_or(MessageError::TooShort)?;
        let protocol_version = ProtocolVersion::decode(input).ok_or(MessageError::TooShort)?;
        if protocol_version != ProtocolVersion::SSLv3 {
            // We only accept decoding of SSLv3 protocol packets
            return Err(MessageError::IllegalVersion);
        }
        let length = u16::decode(input).ok_or(MessageError::TooShort)?;
        let mut payload_reader = input
                .slice(length as usize)
                .ok_or(MessageError::TooShort)?;
        let payload = payload_reader.remaining().to_vec();
        Ok(Self {
            message_type,
            payload
        })
    }
}

/// Structure representing a message where the payload is a slice
/// of another larger message. Used for message fragmentation
#[derive(Debug)]
pub struct BorrowedMessage<'a> {
    pub message_type: MessageType,
    pub payload: &'a [u8],
}

/// Structure representing a SSLMessage where the contents are
/// SSLPlaintext and are able to be decoded to the known message
/// type stored along-side the payload
#[derive(Debug)]
pub struct Message {
    /// The type of message this message is
    pub message_type: MessageType,
    /// The plain-text payload bytes
    pub payload: Vec<u8>,
}

impl Message {
    /// Maximum length each fragment can be
    const MAX_FRAGMENT_LENGTH: usize = 16384;

    /// Fragments the provided `message` into an iterator of borrowed
    /// messages which are chunks of the message payload that are no
    /// greater than MAX_FRAGMENT_LENGTH
    pub fn fragment<'a>(message: &'a Message) -> impl Iterator<Item = BorrowedMessage<'a>> + 'a {
        message
            .payload
            .chunks(Self::MAX_FRAGMENT_LENGTH)
            .map(move |c| BorrowedMessage {
                message_type: message.message_type.clone(),
                payload: c,
            })
    }
}