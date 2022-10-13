use super::Message;

/// Structure for keeping a record of all the message payloads that have
/// be sent and recieved. Used for computing Finished hashes. `finish` is
/// called to copy the current bytes over to `last` this allows keeping
/// a seperate buffer for computing the hashes of the other side for
/// comparing
#[derive(Debug)]
pub struct MessageTranscript {
    pub current: Vec<u8>,
    pub last: Vec<u8>,
}

impl MessageTranscript {
    /// Creates a new message transcript
    pub fn new() -> Self {
        Self {
            current: Vec::new(),
            last: Vec::new(),
        }
    }

    /// Appends a raw section of bytes to the transcript
    pub fn push_raw(&mut self, message: &[u8]) {
        self.current.extend_from_slice(message);
    }

    /// Appends a section of bytes from the message payload to
    /// the transcript
    pub fn push_message(&mut self, message: &Message) {
        self.current.extend_from_slice(&message.payload)
    }

    /// Clears the `last` transcript and copies the current into it
    pub fn finish(&mut self) {
        self.last.clear();
        self.last.extend_from_slice(&self.current);
    }
}
