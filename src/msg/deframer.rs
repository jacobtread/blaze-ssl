use crate::msg::codec::{Codec, Reader};
use crate::msg::{BorrowedMessage, MessageError, RawMessage};
use std::collections::VecDeque;
use std::io;
use std::io::Read;

pub const MAX_FRAGMENT_LEN: usize = 16384;

/// Fragments the provided message into an iterator
/// of borrowed messages that fit the same chunks
pub fn fragment_message<'a>(
    message: &'a RawMessage,
) -> impl Iterator<Item = BorrowedMessage<'a>> + 'a {
    message
        .payload
        .chunks(MAX_FRAGMENT_LEN)
        .map(move |c| BorrowedMessage {
            content_type: message.content_type.clone(),
            payload: c,
        })
}

/// Structure for taking chunks of bytes and turning them
/// into messages when they are ready
pub struct MessageDeframer {
    /// Queue of messages that were parsed.
    pub messages: VecDeque<RawMessage>,
    /// Set to true if the received messages seem to not be TLS
    /// or are broken in some unrepairable way. Connection
    /// should be terminated
    pub invalid: bool,
    /// Buffer containing the currently accumulated message bytes
    buffer: Box<[u8; RawMessage::MAX_WIRE_SIZE]>,
    /// The amount of the buffer that has been used.
    used: usize,
}

#[derive(Debug)]
enum BufferAction {
    // Buffer contains an invalid message
    Invalid,
    // Might contain a message if more data is read
    Partial,
    // Contains a valid frame
    Valid,
}

impl MessageDeframer {
    /// Creates a new message deframer
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            invalid: false,
            buffer: Box::new([0u8; RawMessage::MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Returns whether there is messages currently in the queue
    pub fn has_message(&self) -> bool {
        !self.messages.is_empty()
    }

    /// Read some bytes from the provided `read` and add them to the internal
    /// buffer. Attempts to decode messages from the internal buffer returning
    /// the number of bytes read.
    pub fn read(&mut self, read: &mut dyn Read) -> io::Result<usize> {
        let read_count = read.read(&mut self.buffer[self.used..])?;
        self.used += read_count;
        loop {
            match self.try_deframe() {
                BufferAction::Invalid => {
                    self.invalid = true;
                    break;
                }
                BufferAction::Valid => continue,
                BufferAction::Partial => break,
            }
        }
        Ok(read_count)
    }

    fn try_deframe(&mut self) -> BufferAction {
        let mut reader = Reader::new(&self.buffer[..self.used]);
        match RawMessage::decode(&mut reader) {
            Ok(message) => {
                let used = reader.cursor();
                self.messages.push_back(message);
                self.buf_consume(used);
                BufferAction::Valid
            }
            Err(MessageError::TooShortForHeader) | Err(MessageError::TooShortForLength) => {
                BufferAction::Partial
            }
            Err(_) => BufferAction::Invalid,
        }
    }

    fn buf_consume(&mut self, taken: usize) {
        if taken < self.used {
            self.buffer.copy_within(taken..self.used, 0);
            self.used -= taken;
        } else if taken == self.used {
            self.used = 0;
        }
    }
}
