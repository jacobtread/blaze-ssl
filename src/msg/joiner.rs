use crate::msg::codec::{u24, Codec, Reader};
use crate::msg::enums::ContentType;
use crate::msg::handshake::HandshakePayload;
use crate::msg::payload::Payload;
use crate::msg::types::ProtocolVersion;
use crate::msg::RawMessage;
use std::collections::VecDeque;

const HEADER_SIZE: usize = 1 + 3;

/// TLS allows for handshake messages of up to 16MB.  We
/// restrict that to 64KB to limit potential for denial-of-
/// service.
const MAX_HANDSHAKE_SIZE: u32 = 0xffff;

/// This works to reconstruct TLS handshake messages
/// from individual TLS messages.  It's guaranteed that
/// TLS messages output from this layer contain precisely
/// one handshake payload.
pub struct HandshakeJoiner {
    /// Completed handshake frames for output.
    pub frames: VecDeque<HandshakePayload>,

    /// The message payload we're currently accumulating.
    buf: Vec<u8>,
}

impl Default for HandshakeJoiner {
    fn default() -> Self {
        Self::new()
    }
}

enum BufferState {
    /// Buffer contains a header that introduces a message that is too long.
    MessageTooLarge,

    /// Buffer contains a full header and body.
    OneMessage,

    /// We need more data to see a header and complete body.
    NeedsMoreData,
}

impl HandshakeJoiner {
    /// Make a new HandshakeJoiner.
    pub fn new() -> Self {
        Self {
            frames: VecDeque::new(),
            buf: Vec::new(),
        }
    }

    /// Do we have any buffered data?
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Take the message, and join/split it as needed.
    /// Return the number of new messages added to the
    /// output deque as a result of this message.
    ///
    /// Returns None if msg or a preceding message was corrupt.
    /// You cannot recover from this situation.  Otherwise returns
    /// a count of how many messages we queued.
    pub fn take_message(&mut self, msg: RawMessage) -> Option<usize> {
        // The vast majority of the time `self.buf` will be empty since most
        // handshake messages arrive in a single fragment. Avoid allocating and
        // copying in that common case.
        if self.buf.is_empty() {
            self.buf = msg.payload;
        } else {
            self.buf.extend_from_slice(&msg.payload[..]);
        }

        let mut count = 0;
        loop {
            match self.buf_contains_message() {
                BufferState::MessageTooLarge => {
                    println!("Message too large");
                    return None;
                }
                BufferState::NeedsMoreData => {
                    println!("Needs more data");
                    break;
                }
                BufferState::OneMessage => {
                    println!("Contains message");
                    if !self.deframe_one() {
                        return None;
                    }

                    count += 1;
                }
            }
        }

        Some(count)
    }

    /// Does our `buf` contain a full handshake payload?  It does if it is big
    /// enough to contain a header, and that header has a length which falls
    /// within `buf`.
    fn buf_contains_message(&self) -> BufferState {
        if self.buf.len() < HEADER_SIZE {
            return BufferState::NeedsMoreData;
        }

        let (header, rest) = self.buf.split_at(HEADER_SIZE);
        match u24::from_bytes(&header[1..]) {
            Some(len) if len.0 > MAX_HANDSHAKE_SIZE => BufferState::MessageTooLarge,
            Some(len) if rest.get(..len.into()).is_some() => BufferState::OneMessage,
            _ => BufferState::NeedsMoreData,
        }
    }

    /// Take a TLS handshake payload off the front of `buf`, and put it onto
    /// the back of our `frames` deque inside a normal `Message`.
    ///
    /// Returns false if the stream is desynchronised beyond repair.
    fn deframe_one(&mut self) -> bool {
        let used = {
            let mut rd = Reader::new(&self.buf);
            let parsed = match HandshakePayload::decode(&mut rd) {
                Some(p) => p,
                None => return false,
            };

            self.frames.push_back(parsed);
            rd.cursor()
        };
        self.buf = self.buf.split_off(used);
        true
    }
}
