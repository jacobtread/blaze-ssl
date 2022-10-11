use crate::msg::{BorrowedMessage, Message, OpaqueMessage};
use derive_more::From;
use rc4::cipher::{BlockDecryptMut, StreamCipherError};
use rc4::consts::U16;
use rc4::{KeyInit, Rc4, StreamCipher};
use std::error::Error;
use std::rc::Rc;

#[derive(Debug, From)]
pub enum CryptError {
    StreamCipherError(StreamCipherError),
}

/// Structure representing known types for encoding and decoding messages
pub enum MessageProcessor {
    None,
    RC4 {
        read_key: Rc4<U16>,
        write_key: Rc4<U16>,
    },
}

impl MessageProcessor {
    pub fn encrypt(&mut self, message: BorrowedMessage) -> OpaqueMessage {
        match self {
            MessageProcessor::None => OpaqueMessage {
                content_type: message.content_type,
                payload: message.payload.to_vec(),
            },
            MessageProcessor::RC4 { write_key, .. } => {
                let mut payload = message.payload.to_vec();
                write_key.apply_keystream(&mut payload);

                // TODO: Write mac

                OpaqueMessage {
                    content_type: message.content_type,
                    payload,
                }
            }
        }
    }

    pub fn decrypt(&mut self, message: OpaqueMessage) -> Message {
        match self {
            MessageProcessor::None => Message {
                content_type: message.content_type,
                payload: message.payload,
            },
            MessageProcessor::RC4 { read_key, .. } => {
                let mut payload = message.payload.to_vec();
                read_key.apply_keystream(&mut payload);

                // TODO: Remove mac

                Message {
                    content_type: message.content_type,
                    payload,
                }
            }
        }
    }
}
