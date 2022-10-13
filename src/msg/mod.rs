pub mod codec;
pub mod handshake;
#[macro_use]
pub mod macros;
pub mod enums;
pub mod types;

// Re-exporting Codec & Reader for `codec_enum` macro
pub use codec::{Codec, Reader, Certificate};

pub use enums::MessageType;

/// Structure representing a SSLMessage that has had its header
/// decoded so we know the type of message but we don't know if
/// the payload of the message is SSLPlaintext or SSLCiphertext
/// so it must be converted to a `Message` through the processor
#[derive(Debug)]
pub struct OpaqueMessage {
    /// The type of message this message is
    pub message_type: MessageType,
    /// The opaque payload bytes
    pub payload: Vec<u8>
}

/// Structure representing a SSLMessage where the contents are
/// SSLPlaintext and are able to be decoded to the known message
/// type stored along-side the payload
#[derive(Debug)]
pub struct Message {
    /// The type of message this message is
    pub message_type: MessageType,
    /// The plain-text payload bytes
    pub payload: Vec<u8>
}

