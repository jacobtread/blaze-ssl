use std::cmp;
use crate::codec::{Certificate, Codec, Reader, SSLRandom};
use crate::constants::PROTOCOL_SSL3;
use crate::handshake::{Transcript, HandshakePayload};
use crate::hash::{generate_key_block, FinishedSender, compute_finished_md5, compute_finished_sha, compute_mac};
use crate::msgs::{fragment_message, BorrowedMessage, HandshakeJoiner, MessageDeframer, OpaqueMessage, Alert, FatalAlert};
use crate::msgs::{Message, MessageType};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use rsa::{PaddingScheme, RsaPrivateKey};
use std::io::{self, ErrorKind, Read, Write};
use lazy_static::lazy_static;

lazy_static! {
    /// RSA private key used by the server
    pub static ref SERVER_KEY: RsaPrivateKey = {
        let key_der = include_bytes!("key.der");
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::RsaPrivateKey;

        RsaPrivateKey::from_pkcs8_der(key_der)
            .expect("Failed to load redirector private key")
    };

    /// Certificate used by the server
    pub static ref SERVER_CERTIFICATE: Certificate = {
        let cert_der = include_bytes!("cert.der");
        Certificate(cert_der.to_vec())
    };
}

/// Wrapping structure for wrapping Read + Write streams with a SSLv3
/// protocol wrapping.
pub struct BlazeStream<S> {
    /// Underlying stream target
    stream: S,

    /// Write sequence counter (Reset on cipher change)
    write_seq: u64,
    /// Read sequence counter (Reset on cipher change)
    read_seq: u64,

    /// Message deframer for de-framing messages from the read stream
    deframer: MessageDeframer,

    /// Processor for pre-processing messages that have been read
    read_processor: ReadProcessor,
    /// Process for pre-processing messages that are being sent
    write_processor: WriteProcessor,

    /// Buffer for input that is read from the application layer
    read_buffer: Vec<u8>,
    /// Buffer for output written to the application layer
    /// (Written to stream when connection is flushed)
    write_buffer: Vec<u8>,

    /// State determining whether the stream is stopped
    stopped: bool,
}

#[derive(Debug)]
pub enum BlazeError {
    IO(io::Error),
    FatalAlert(FatalAlert),
    Stopped,
    Unsupported,
}


impl From<io::Error> for BlazeError {
    fn from(err: io::Error) -> Self {
        BlazeError::IO(err)
    }
}

pub type BlazeResult<T> = Result<T, BlazeError>;

impl<S> BlazeStream<S>
    where
        S: Read + Write,
{
    pub fn new(value: S) -> BlazeResult<Self> {
        let stream = Self {
            stream: value,
            write_seq: 0,
            read_seq: 0,
            deframer: MessageDeframer::new(),
            read_processor: ReadProcessor::None,
            write_processor: WriteProcessor::None,
            write_buffer: Vec::new(),
            read_buffer: Vec::new(),
            stopped: false,
        };
        let handshaking = HandshakingStream {
            stream,
            joiner: HandshakeJoiner::new(),
            transcript: Transcript::new(),
        };
        handshaking.handshake()
    }

    /// Attempts to take the next message form the deframer or read a new
    /// message from the underlying stream if there is no parsable messages
    pub fn next_message(&mut self) -> BlazeResult<Message> {
        loop {
            if self.stopped {
                return Err(BlazeError::Stopped)
            }

            if let Some(message) = self.deframer.next() {
                let message = self.read_processor.process(message, self.read_seq)
                    .map_err(|err| match err {
                        DecryptError::InvalidMac => self.alert_fatal(FatalAlert::BadRecordMac)
                    })?;
                self.read_seq += 1;

                if message.message_type == MessageType::Alert {
                    let mut reader = Reader::new(&message.payload);
                    if let Some(alert) = Alert::decode(&mut reader) {
                        self.handle_alert(alert);
                    } else {
                        reader.reset();
                        let fatal = FatalAlert::decode(&mut reader)
                            .unwrap_or(FatalAlert::Unknown);
                        return Err(self.handle_fatal(fatal));
                    }
                }

                return Ok(message);
            }
            if !self.deframer.read(&mut self.stream)? {
                return Err(self.alert_fatal(FatalAlert::IllegalParameter));
            }
        }
    }

    /// Triggers a shutdown by sending a CloseNotify alert
    pub fn shutdown(&mut self) -> BlazeResult<()>{
        self.alert(Alert::CloseNotify)
    }


    /// Handle the alert message provided
    pub fn handle_alert(&mut self, alert: Alert) {
        match alert {
            Alert::CloseNotify => {
                // We are closing flush and set stopped
                let _ = self.flush();
                self.stopped = true;
            }
            Alert::HandshakeFailure => {}
            Alert::NoCertificate => {}
            Alert::BadCertificate => {}
            Alert::UnsupportedCertificate => {}
            Alert::CertificateRevoked => {}
            Alert::CertificateExpired => {}
            Alert::CertificateUnknown => {}
        }
    }

    /// Handle a fatal alert (Stop the connection and don't attempt more reads/writes)
    pub fn handle_fatal(&mut self, alert: FatalAlert) -> BlazeError {
        self.stopped = true;
        return BlazeError::FatalAlert(alert);
    }


    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
    pub fn write_message(&mut self, message: Message) -> io::Result<()> {
        for msg in fragment_message(&message) {
            let msg = self.write_processor.process(msg, self.write_seq);
            let bytes = msg.encode();
            self.stream.write(&bytes)?;
            self.write_seq += 1;
        }
        Ok(())
    }

    /// Writes an alert message and calls `handle_alert` with the alert
    pub fn alert(&mut self, alert: Alert) -> BlazeResult<()> {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        // Internally handle the alert being sent
        self.handle_alert(alert);
        self.write_message(message)?;
        Ok(())
    }

    pub fn alert_fatal(&mut self, alert: FatalAlert) -> BlazeError {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        let _ = self.write_message(message);
        // Internally handle the alert being sent
        self.handle_fatal(alert)
    }

    /// Fills the application data buffer if the buffer is empty by reading
    /// a message from the application layer
    pub fn fill_app_data(&mut self) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed())
        }
        let buffer_len = self.read_buffer.len();
        let count = if buffer_len == 0 {
            let message = self.next_message()
                .map_err(|_| io::Error::new(ErrorKind::ConnectionAborted, "Ssl Failure"))?;

            if message.message_type != MessageType::ApplicationData {
                // Alert unexpected message
                self.alert_fatal(FatalAlert::UnexpectedMessage);
                return Ok(0)
            }

            let payload = message.payload;
            self.read_buffer.extend_from_slice(&payload);
            payload.len()
        } else {
            buffer_len
        };
        Ok(count)
    }
}

/// Creates an error indicating that the stream is closed
fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::Other, "Stream already closed")
}

impl<S> Write for BlazeStream<S>
    where
        S: Read + Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed())
        }
        self.write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.stopped {
            return Err(io_closed())
        }
        let message = Message {
            message_type: MessageType::ApplicationData,
            payload: self.write_buffer.split_off(0),
        };
        self.write_message(message)?;
        self.stream.flush()
    }
}

impl<S> Read for BlazeStream<S>
    where
        S: Read + Write,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.fill_app_data()?;
        if self.stopped {
            return Err(io_closed())
        }
        let read = cmp::min(buf.len(), count);
        if read > 0 {
            let new_buffer = self.read_buffer.split_off(read);
            buf[..read].copy_from_slice(&self.read_buffer);
            self.read_buffer = new_buffer;
        }
        Ok(read)
    }
}

/// Stream wrapper where the client and server are in the
/// handshaking process. Provides additional structures for
/// reading handshake messages from the stream
pub struct HandshakingStream<S> {
    stream: BlazeStream<S>,
    joiner: HandshakeJoiner,
    transcript: Transcript,
}

/// Structure for storing the random values from
/// the client and server responses
#[derive(Debug)]
pub struct HelloData {
    client_random: SSLRandom,
    server_random: SSLRandom,
}

/// Structure for storing cryptographic keys and
/// state that may be required
pub struct CryptographicState {
    master_key: [u8; 48],
    client_write_secret: [u8; 16],
    server_write_secret: [u8; 16],
    client_write_key: [u8; 16],
    server_write_key: [u8; 16],
}

impl<S> HandshakingStream<S>
    where
        S: Read + Write,
{
    /// Takes the next received handshake packet returning an error
    /// if one could not be formed or another message type was received
    fn next_handshake(&mut self) -> BlazeResult<HandshakePayload> {
        loop {
            if let Some(message) = self.joiner.next() {
                let payload = message.payload;

                if matches!(&payload, HandshakePayload::Finished(_, _)) {
                    // Finish the client transcription
                    self.transcript.finish_client();
                }
                self.transcript.push_raw(&message.raw);
                return Ok(payload);
            } else {
                let message = self.stream.next_message()?;
                if message.message_type != MessageType::Handshake {
                    return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage));
                }
                self.joiner.consume_message(message);
            }
        }
    }

    /// Handles handshaking returning the underlying stream for use
    /// once handshaking is complete
    pub fn handshake(mut self) -> Result<BlazeStream<S>, BlazeError> {
        let hello_data = self.accept_hello()?;
        let state = self.accept_exchange(hello_data)?;
        self.accept_cipher_change(&state)?;
        self.accept_finished(&state)?;
        Ok(self.stream)
    }

    /// Handles the hello portion of the handshaking processes returns
    /// a struct containing the client and server randoms
    fn accept_hello(&mut self) -> BlazeResult<HelloData> {
        let client_random = match self.next_handshake()? {
            HandshakePayload::ClientHello(protocol, random) => {
                if protocol != PROTOCOL_SSL3 {
                    return Err(BlazeError::Unsupported);
                }
                random
            }
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        let server_random = SSLRandom::new()
            .map_err(|_| self.stream.alert_fatal(FatalAlert::IllegalParameter))?;

        // Send server hello, certificate, and server done
        self.emit_server_hello(server_random.clone())?;
        self.emit_server_certificate()?;
        self.emit_server_hello_done()?;

        Ok(HelloData {
            client_random,
            server_random,
        })
    }

    /// Emits the server hello message
    fn emit_server_hello(&mut self, server_random: SSLRandom) -> BlazeResult<()> {
        let message = HandshakePayload::ServerHello(server_random)
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Emit the server certificate message with a copy of the
    /// server certificate
    fn emit_server_certificate(&mut self) -> BlazeResult<()> {
        let message = HandshakePayload::Certificate(&SERVER_CERTIFICATE)
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Emits the server hello done handshake payload
    fn emit_server_hello_done(&mut self) -> BlazeResult<()> {
        let message = HandshakePayload::ServerHelloDone
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Handles accepting the client key exchange and generating the master
    /// key from the provided encrypted pre-master key
    fn accept_exchange(&mut self, hello: HelloData) -> BlazeResult<CryptographicState> {
        let encrypted_pm_key = match self.next_handshake()? {
            HandshakePayload::ClientKeyExchange(payload) => payload,
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        let pm_key = SERVER_KEY
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &encrypted_pm_key)
            .map_err(|_| self.stream.alert_fatal(FatalAlert::IllegalParameter))?;


        let client_random = &hello.client_random.0;
        let server_random = &hello.server_random.0;

        let mut master_key = [0u8; 48];
        generate_key_block(&mut master_key, &pm_key, client_random, server_random);

        // Generate key block 80 bytes long (20x2 for write secrets + 16x2 for write keys) only 72 bytes used
        let mut key_block = [0u8; 64];
        generate_key_block(&mut key_block, &master_key, server_random, client_random);

        let mut client_write_secret = [0u8; 16];
        client_write_secret.copy_from_slice(&key_block[0..16]);
        let mut server_write_secret = [0u8; 16];
        server_write_secret.copy_from_slice(&key_block[16..32]);

        let mut client_write_key = [0u8; 16];
        client_write_key.copy_from_slice(&key_block[32..48]);
        let mut server_write_key = [0u8; 16];
        server_write_key.copy_from_slice(&key_block[48..64]);

        Ok(CryptographicState {
            master_key,
            client_write_secret,
            server_write_secret,
            client_write_key,
            server_write_key,
        })
    }

    /// Handles changing over ciphers when the ChangeCipherSpec message is
    /// received
    fn accept_cipher_change(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        // Expect the client to change cipher spec
        match self.stream.next_message()?.message_type {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        }
        // Reset reads
        self.stream.read_seq = 0;

        // Switch read processor to RC4 with new key
        let key = Rc4::new(&state.client_write_key);
        let mut mac_secret = [0u8; 16];
        mac_secret.copy_from_slice(&state.client_write_secret);
        self.stream.read_processor = ReadProcessor::RC4 {
            mac_secret,
            key,
        };
        Ok(())
    }

    /// Accepts the finishing message from the client switching the clients
    /// CipherSpec and writing back the finished message
    fn accept_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        match self.next_handshake()? {
            HandshakePayload::Finished(md5_hash, sha_hash) => {
                if !self.check_client_hashes(&state.master_key, md5_hash, sha_hash) {
                    return Err(self.stream.alert_fatal(FatalAlert::IllegalParameter));
                }
            }
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        self.emit_cipher_change_spec(state)?;
        self.emit_finished(state)?;
        Ok(())
    }

    /// Emits the ChangeCipherSpec message to the client telling it to change
    /// cipher spec and switches the stream write processor to the RC4
    /// encrypting processor
    fn emit_cipher_change_spec(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let message = Message {
            message_type: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };
        self.stream.write_message(message)?;
        // Reset the writes
        self.stream.write_seq = 0;

        // Switch read processor to RC4 with new key
        let key = Rc4::new(&state.server_write_key);
        let mut mac_secret = [0u8; 16];
        mac_secret.copy_from_slice(&state.server_write_secret);
        self.stream.write_processor = WriteProcessor::RC4 {
            mac_secret,
            key,
        };
        Ok(())
    }

    /// Computes and compares the client hashes for the handshaking process returning
    /// whether they are matching hashes
    fn check_client_hashes(&mut self, master_key: &[u8; 48], md5_hash: [u8; 16], sha_hash: [u8; 20]) -> bool {
        let exp_md5_hash = compute_finished_md5(master_key, FinishedSender::Client, &self.transcript.client);
        let exp_sha_hash = compute_finished_sha(master_key, FinishedSender::Client, &self.transcript.client);
        exp_md5_hash == md5_hash && exp_sha_hash == sha_hash
    }

    /// Calculates the hashes for this handshake and emits the Finished handshake message
    /// indicating to the client that Handshaking is complete.
    fn emit_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let master_key = &state.master_key;

        let server_md5_hash = compute_finished_md5(master_key, FinishedSender::Server, &self.transcript.full);
        let server_sha_hash = compute_finished_sha(master_key, FinishedSender::Server, &self.transcript.full);

        let message = HandshakePayload::Finished(server_md5_hash, server_sha_hash)
            .as_message();
        self.stream.write_message(message)?;
        Ok(())
    }
}


/// Handler for processing messages that need to be written
/// converts them to writing messages
pub enum WriteProcessor {
    /// NO-OP Write processor which directly converts the message to OpaqueMessage
    None,
    /// RC4 Encryption processor which encrypts the message before converting
    RC4 {
        key: Rc4,
        mac_secret: [u8; 16],
    },
}

impl WriteProcessor {
    /// Processes the provided message using the underlying method and creates an
    /// Opaque message that can be written from it.
    ///
    /// `message` The message to process for writing
    /// `seq` The current sequence number for this message
    pub fn process(&mut self, message: BorrowedMessage, seq: u64) -> OpaqueMessage {
        match self {
            // NO-OP directly convert message into output
            WriteProcessor::None => OpaqueMessage {
                message_type: message.message_type,
                payload: message.payload.to_vec(),
            },
            // RC4 Encryption
            WriteProcessor::RC4 { key, mac_secret } => {
                let mut payload = message.payload.to_vec();
                let mac = compute_mac(mac_secret, message.message_type.value(), &payload, seq);
                payload.extend_from_slice(&mac);

                let mut payload_enc = vec![0u8; payload.len()];
                key.process(&payload, &mut payload_enc);
                OpaqueMessage {
                    message_type: message.message_type,
                    payload: payload_enc,
                }
            }
        }
    }
}

/// Handler for processing messages that have been read
/// and turning them into their actual messages
pub enum ReadProcessor {
    /// NO-OP Write processor which directly converts the message to Message
    None,
    /// RC4 Decryption processor which decrypts the message before converting
    RC4 {
        key: Rc4,
        mac_secret: [u8; 16],
    },
}

#[derive(Debug)]
pub enum DecryptError {
    /// The mac address of the decrypted payload didn't match the
    /// computed value
    InvalidMac,
}

type DecryptResult<T> = Result<T, DecryptError>;

impl ReadProcessor {
    pub fn process(&mut self, message: OpaqueMessage, seq: u64) -> DecryptResult<Message> {
        Ok(match self {
            // NO-OP directly convert message into output
            ReadProcessor::None => Message {
                message_type: message.message_type,
                payload: message.payload,
            },
            // RC4 Decryption
            ReadProcessor::RC4 { key, mac_secret } => {
                let mut payload_and_mac = vec![0u8; message.payload.len()];
                key.process(&message.payload, &mut payload_and_mac);

                let mac_start = payload_and_mac.len() - 16;
                let payload = &payload_and_mac[..mac_start];

                let mac = &payload_and_mac[mac_start..];
                let expected_mac = compute_mac(mac_secret, message.message_type.value(), &payload, seq);

                if !expected_mac.eq(mac) {
                    return Err(DecryptError::InvalidMac);
                }

                Message {
                    message_type: message.message_type,
                    payload: payload.to_vec(),
                }
            }
        })
    }
}