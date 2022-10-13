use crate::codec::{u24, Codec, Reader};
use crate::handshake::{HandshakeMessage, HandshakePayload};
use std::collections::VecDeque;
use std::io;
use std::io::Read;

pub const SSL_V3: u16 = 0x0300;

/// Raw implementation of a SSL message contains the
/// content type, protocol version and the content
/// bytes
#[derive(Debug)]
pub struct OpaqueMessage {
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Into<OpaqueMessage> for Message {
    fn into(self) -> OpaqueMessage {
        OpaqueMessage {
            message_type: self.message_type,
            payload: self.payload,
        }
    }
}

/// Represents a SSL message that is in plain text
#[derive(Debug)]
pub struct Message {
    pub message_type: MessageType,
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

impl MessageType {
    pub fn value(&self) -> u8 {
        match self {
            MessageType::ChangeCipherSpec => 20,
            MessageType::Alert => 21,
            MessageType::Handshake => 22,
            MessageType::ApplicationData => 23,
            MessageType::Unknown(value) => *value,
        }
    }

    pub fn from_value(value: u8) -> MessageType {
        match value {
            0x14 => Self::ChangeCipherSpec,
            0x15 => Self::Alert,
            0x16 => Self::Handshake,
            0x17 => Self::ApplicationData,
            value => Self::Unknown(value),
        }
    }
}

impl Codec for MessageType {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(self.value())
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        Some(MessageType::from_value(input.take_byte()?))
    }
}

#[derive(Debug)]
pub enum FatalAlert {
    UnexpectedMessage,
    BadRecordMac,
    DecompressionFailure,
    IllegalParameter,
    Unknown
}

impl Codec for FatalAlert {
    fn encode(&self, output: &mut Vec<u8>) {
        output.push(2);
        output.push( match self {
            Self::UnexpectedMessage => 0xA,
            Self::BadRecordMac => 0x14,
            Self::DecompressionFailure => 0x1E,
            Self::IllegalParameter => 0x2F,
            Self::Unknown => 0x0
        });
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let _level = input.take_byte()?;
        let value = input.take_byte()?;
        Some(match value {
            0xA => Self::UnexpectedMessage,
            0x14 => Self::BadRecordMac,
            0x1E => Self::DecompressionFailure,
            0x2F => Self::IllegalParameter,
            _ => return None
        })
    }
}

/// Message where the payload is borrowed from a slice of another message
#[derive(Debug)]
pub struct BorrowedMessage<'a> {
    pub message_type: MessageType,
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
        self.message_type.encode(&mut output);
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
            message_type: content_type,
            payload,
        })
    }
}

/// Structure for taking chunks of bytes and turning them
/// into messages when they are ready
pub struct MessageDeframer {
    /// Queue of messages that were parsed.
    pub messages: VecDeque<OpaqueMessage>,
    /// Set to true if the received messages seem to not be TLS
    /// or are broken in some unrepairable way. Connection
    /// should be terminated
    pub invalid: bool,
    /// Buffer containing the currently accumulated message bytes
    buffer: Box<[u8; OpaqueMessage::MAX_WIRE_SIZE]>,
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
            buffer: Box::new([0u8; OpaqueMessage::MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Attempts to take the next complete message from the
    /// messages queue if there are any
    pub fn next(&mut self) -> Option<OpaqueMessage> {
        self.messages.pop_front()
    }

    /// Read some bytes from the provided `read` and add them to the internal
    /// buffer. Attempts to decode messages from the internal buffer returning
    /// the number of bytes read.
    pub fn read(&mut self, read: &mut dyn Read) -> io::Result<bool> {
        self.used += read.read(&mut self.buffer[self.used..])?;
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
        Ok(!self.invalid)
    }

    fn try_deframe(&mut self) -> BufferAction {
        let mut reader = Reader::new(&self.buffer[..self.used]);
        match OpaqueMessage::decode(&mut reader) {
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
    pub payloads: VecDeque<HandshakeMessage>,

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
            payloads: VecDeque::new(),
            buf: Vec::new(),
        }
    }

    /// Attempts to take the next handshake payload if there
    /// are any available
    pub fn next(&mut self) -> Option<HandshakeMessage> {
        self.payloads.pop_front()
    }

    /// Take the message, and join/split it as needed.
    /// Return the number of new messages added to the
    /// output deque as a result of this message.
    ///
    /// Returns None if msg or a preceding message was corrupt.
    /// You cannot recover from this situation.  Otherwise returns
    /// a count of how many messages we queued.
    pub fn consume_message(&mut self, msg: Message) -> Option<usize> {
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
                BufferState::MessageTooLarge => return None,
                BufferState::NeedsMoreData => break,
                BufferState::OneMessage => {
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
    /// Returns false if the stream is de-synchronised beyond repair.
    fn deframe_one(&mut self) -> bool {
        let used = {
            let mut rd = Reader::new(&self.buf);
            let payload = match HandshakePayload::decode(&mut rd) {
                Some(p) => p,
                None => return false,
            };

            let length = rd.cursor();
            let raw = self.buf[0..length].to_vec();
            self.payloads.push_back(HandshakeMessage { payload, raw });
            length
        };
        self.buf = self.buf.split_off(used);
        true
    }
}