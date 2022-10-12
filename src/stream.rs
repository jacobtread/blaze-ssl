use crate::codec::{Certificate, SSLRandom};
use crate::constants::PROTOCOL_SSL3;
use crate::handshake::{HandshakeHashBuffer, HandshakePayload};
use crate::hash::{generate_key_block, FinishedSender, compute_finished_md5, compute_finished_sha};
use crate::msgs::{
    fragment_message, BorrowedMessage, HandshakeJoiner, MessageDeframer, OpaqueMessage,
};
use crate::msgs::{Message, MessageType};
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use rsa::{PaddingScheme, RsaPrivateKey};
use std::io::{self, Read, Write};

pub struct SslStream<S> {
    stream: S,
    write_seq: u64,
    read_seq: u64,
    certificate: Certificate,
    private_key: RsaPrivateKey,
    deframer: MessageDeframer,
    processor: MessageProcessor,
}

impl<S> SslStream<S> {
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }
}

#[derive(Debug)]
pub enum SslError {
    IO(io::Error),
    InvalidMessages,
    UnexpectedMessage,
    Failure,
    Unsupported,
}

impl From<io::Error> for SslError {
    fn from(err: io::Error) -> Self {
        SslError::IO(err)
    }
}

pub type SslResult<T> = Result<T, SslError>;

impl<S> SslStream<S>
    where
        S: Read + Write,
{
    pub fn new(value: S, cert: Certificate, private: RsaPrivateKey) -> SslResult<Self> {
        let stream = Self {
            stream: value,
            write_seq: 0,
            read_seq: 0,
            certificate: cert,
            private_key: private,
            deframer: MessageDeframer::new(),
            processor: MessageProcessor::None,
        };
        let handshaking = HandshakingStream {
            stream,
            joiner: HandshakeJoiner::new(),
            transcript: HandshakeHashBuffer(Vec::new()),
        };
        handshaking.handshake()
    }

    /// Attempts to take the next message form the deframer or read a new
    /// message from the underlying stream if there is no parsable messages
    pub fn next_message(&mut self) -> SslResult<Message> {
        loop {
            if let Some(message) = self.deframer.next() {
                let message = self.processor.decrypt(message, self.read_seq);
                if message.ty == MessageType::ChangeCipherSpec {
                    self.read_seq = 0;
                } else {
                    self.read_seq += 1;
                }
                return Ok(message);
            }
            if !self.deframer.read(&mut self.stream)? {
                return Err(SslError::InvalidMessages);
            }
        }
    }

    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
    pub fn write_message(&mut self, message: Message) -> io::Result<()> {
        for msg in fragment_message(&message) {
            let msg = self.processor.encrypt(msg, self.write_seq);
            let bytes = msg.encode();
            self.stream.write(&bytes)?;
            if message.ty == MessageType::ChangeCipherSpec {
                self.write_seq = 0;
            } else {
                self.write_seq += 1;
            }
        }
        Ok(())
    }
}

impl<S> Write for SslStream<S>
    where
        S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: Convert application data to messages
        self.stream.write(&buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<S> Read for SslStream<S>
    where
        S: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // TODO: Read from application data messages
        self.stream.read(buf)
    }
}

/// Stream wrapper where the client and server are in the
/// handshaking process. Provides additional structures for
/// reading handshake messages from the stream
pub struct HandshakingStream<S> {
    stream: SslStream<S>,
    joiner: HandshakeJoiner,
    transcript: HandshakeHashBuffer,
}

impl<S> HandshakingStream<S> {
    pub fn get_ref(&self) -> &S {
        self.stream.get_ref()
    }

    pub fn get_mut(&mut self) -> &mut S {
        self.stream.get_mut()
    }
}

/// Type of pre master key
pub type PreMasterKey = [u8; 48];
/// Type of master key
pub type MasterKey = [u8; 48];
/// Type of slice from two combined randoms
pub type CombinedRandom = [u8; 64];

/// Structure for storing the random values from
/// the client and server responses
#[derive(Debug)]
pub struct HelloData {
    client_random: SSLRandom,
    server_random: SSLRandom,
}

/// Structure for storing the master key and combined
/// randoms values from the ClientKeyExchange
pub struct ExchangeData {
    master_key: [u8; 48],
    client_write_secret: [u8; 16],
    server_write_secret: [u8; 16],
    client_write_key: Rc4,
    server_write_key: Rc4,
}

/// Structure for data used in the finished message
pub struct FinishedData {
    master_key: [u8; 48],
}

impl<S> HandshakingStream<S>
    where
        S: Read + Write,
{
    /// Takes the next received handshake packet returning an error
    /// if one could not be formed or another message type was received
    fn next_handshake(&mut self) -> SslResult<HandshakePayload> {
        loop {
            if let Some(message) = self.joiner.next() {
                let payload = message.payload;

                if !matches!(&payload, HandshakePayload::Finished(_, _)) {
                    self.transcript.push_raw(&message.raw);
                }

                return Ok(payload);
            } else {
                let message = self.stream.next_message()?;
                if message.ty != MessageType::Handshake {
                    return Err(SslError::UnexpectedMessage);
                }
                self.joiner.consume_message(message);
            }
        }
    }

    /// Handles handshaking returning the underlying stream for use
    /// once handshaking is complete
    pub fn handshake(mut self) -> Result<SslStream<S>, SslError> {
        let hello_data = self.accept_hello()?;
        let exchange_data = self.accept_exchange(hello_data)?;
        let finished_data = self.accept_cipher_change(exchange_data)?;
        self.accept_finished(finished_data)?;

        println!("Handshake completed success");

        Ok(self.stream)
    }

    /// Handles the hello portion of the handshaking processes returns
    /// a struct containing the client and server randoms
    fn accept_hello(&mut self) -> SslResult<HelloData> {
        let client_random = match self.next_handshake()? {
            HandshakePayload::ClientHello(protocol, random) => {
                if protocol != PROTOCOL_SSL3 {
                    return Err(SslError::Unsupported);
                }
                random
            }
            _ => return Err(SslError::UnexpectedMessage),
        };

        let server_random = SSLRandom::new().map_err(|_| SslError::Failure)?;

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
    fn emit_server_hello(&mut self, server_random: SSLRandom) -> SslResult<()> {
        let message = HandshakePayload::ServerHello(server_random)
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Emit the server certificate message with a copy of the
    /// server certificate
    fn emit_server_certificate(&mut self) -> SslResult<()> {
        let message = HandshakePayload::Certificate(self.stream.certificate.clone())
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Emits the server hello done handshake payload
    fn emit_server_hello_done(&mut self) -> SslResult<()> {
        let message = HandshakePayload::ServerHelloDone
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    /// Handles accepting the client key exchange and generating the master
    /// key from the provided encrypted pre-master key
    fn accept_exchange(&mut self, hello: HelloData) -> SslResult<ExchangeData> {
        let encrypted_pm_key = match self.next_handshake()? {
            HandshakePayload::ClientKeyExchange(payload) => payload,
            _ => return Err(SslError::UnexpectedMessage),
        };

        let pm_key = self
            .stream
            .private_key
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &encrypted_pm_key)
            .map_err(|_| SslError::Failure)?;

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

        let client_write_key = Rc4::new(&client_write_key);
        let server_write_key = Rc4::new(&server_write_key);

        Ok(ExchangeData {
            master_key,
            client_write_secret,
            server_write_secret,
            client_write_key,
            server_write_key,
        })
    }

    /// Handles changing over ciphers when the ChangeCipherSpec message is
    /// received
    fn accept_cipher_change(&mut self, exchange_data: ExchangeData) -> SslResult<FinishedData> {
        // Expect the client to change cipher spec
        match self.stream.next_message()?.ty {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(SslError::UnexpectedMessage),
        }

        self.stream.processor = MessageProcessor::RC4 {
            client_mac_secret: exchange_data.client_write_secret,
            server_mac_secret: exchange_data.server_write_secret,
            read_key: exchange_data.client_write_key,
            write_key: exchange_data.server_write_key,
        };

        Ok(FinishedData {
            master_key: exchange_data.master_key,
        })
    }

    /// Accepts the finishing message from the client switching the clients
    /// CipherSpec and writing back the finished message
    fn accept_finished(&mut self, finished_data: FinishedData) -> SslResult<()> {
        let master_key = &finished_data.master_key;

        match self.next_handshake()? {
            HandshakePayload::Finished(md5_hash, sha_hash) => {
                // Compute expected client hashes and check them against the provided ones
                let exp_sha_hash = compute_finished_sha(master_key, FinishedSender::Client, &self.transcript);
                let exp_md5_hash = compute_finished_md5(master_key, FinishedSender::Client, &self.transcript);
                if exp_sha_hash != sha_hash || exp_md5_hash != md5_hash {
                    return Err(SslError::Failure);
                }
            },
            _ => return Err(SslError::UnexpectedMessage),
        };

        let server_md5_hash = compute_finished_md5(master_key, FinishedSender::Server, &self.transcript);
        let server_sha_hash = compute_finished_sha(master_key, FinishedSender::Server, &self.transcript);

        let cipher_spec_msg = Message {
            ty: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };

        self.stream.write_message(cipher_spec_msg)?;

        let message = HandshakePayload::Finished(server_md5_hash, server_sha_hash)
            .as_message();
        self.stream.write_message(message)?;
        Ok(())
    }
}

/// Structure representing known types for encoding and decoding messages
pub enum MessageProcessor {
    None,
    RC4 {
        server_mac_secret: [u8; 16],
        client_mac_secret: [u8; 16],

        read_key: Rc4,
        write_key: Rc4,
    },
}

impl MessageProcessor {
    pub fn compute_mac(write_secret: &[u8], ty: u8, message: &[u8], seq: u64) -> [u8; 16] {
        let mut digest = Md5::new();
        let mut out = [0u8; 16];
        let pad1 = [0x36; 48];
        let pad2 = [0x5c; 48];
        // A = hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment)
        digest.input(write_secret);
        digest.input(&pad1);
        digest.input(&seq.to_be_bytes());
        digest.input(&[ty]);
        digest.input(&message.len().to_be_bytes());
        digest.input(message);
        digest.result(&mut out);
        digest.reset();

        // hash(MAC_write_secret + pad_2 + A);
        digest.input(write_secret);
        digest.input(&pad2);
        digest.input(&out);
        digest.result(&mut out);
        out
    }

    pub fn encrypt(&mut self, message: BorrowedMessage, seq: u64) -> OpaqueMessage {
        match self {
            MessageProcessor::None => OpaqueMessage {
                ty: message.content_type,
                payload: message.payload.to_vec(),
            },
            MessageProcessor::RC4 {
                write_key,
                server_mac_secret,
                ..
            } => {
                let mut payload_in = message.payload.to_vec();
                let mac = Self::compute_mac(
                    server_mac_secret,
                    message.content_type.value(),
                    &payload_in,
                    seq,
                );
                payload_in.extend_from_slice(&mac);
                let mut payload_out = vec![0u8; payload_in.len()];
                write_key.process(&payload_in, &mut payload_out);
                OpaqueMessage {
                    ty: message.content_type,
                    payload: payload_out,
                }
            }
        }
    }

    pub fn decrypt(&mut self, message: OpaqueMessage, seq: u64) -> Message {
        match self {
            MessageProcessor::None => Message {
                ty: message.ty,
                payload: message.payload,
            },
            MessageProcessor::RC4 {
                read_key,
                client_mac_secret,
                server_mac_secret,
                ..
            } => {
                let mut payload = vec![0u8; message.payload.len()];
                read_key.process(&message.payload, &mut payload);
                let mac_cutoff = payload.len() - 16;

                let mac = &payload[mac_cutoff..];
                let payload = &payload[..mac_cutoff];

                let expected_mac_a =
                    Self::compute_mac(client_mac_secret, message.ty.value(), &payload, seq);

                let expected_mac_b =
                    Self::compute_mac(server_mac_secret, message.ty.value(), &payload, seq);

                // TODO: Check mac
                println!("Decrypted message: \nREAL: {mac:?}\nCLIE: {expected_mac_a:?}\nSERV: {expected_mac_b:?}");

                Message {
                    ty: message.ty,
                    payload: payload.to_vec(),
                }
            }
        }
    }
}
