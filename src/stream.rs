use crate::codec::{Certificate, SSLRandom};
use crate::handshake::HandshakePayload;
use crate::hash::{compute_final_key, create_master_secret};
use crate::msgs::{
    fragment_message, BorrowedMessage, HandshakeJoiner, MessageDeframer, OpaqueMessage,
};
use crate::msgs::{Message, MessageType};
use rc4::consts::U16;
use rc4::{KeyInit, Rc4, StreamCipher};
use rsa::{PaddingScheme, RsaPrivateKey};
use sha1_smol::Sha1;
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
        };
        handshaking.handshake()
    }

    /// Attempts to take the next message form the deframer or read a new
    /// message from the underlying stream if there is no parsable messages
    pub fn next_message(&mut self) -> SslResult<Message> {
        loop {
            if let Some(message) = self.deframer.next() {
                println!("Raw Message: {message:?}");
                let message = self.processor.decrypt(message, self.read_seq);
                if !matches!(self.processor, MessageProcessor::None) {
                    self.read_seq += 1;
                    println!("Decrypted Message: {message:?}");
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
            if !matches!(self.processor, MessageProcessor::None) {
                self.write_seq += 1;
            }
            let bytes = msg.encode();
            self.stream.write(&bytes)?;
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
#[derive(Debug)]
pub struct ExchangeData {
    master_key: MasterKey,
    _randoms: CombinedRandom,
}

impl<S> HandshakingStream<S>
where
    S: Read + Write,
{
    /// Takes the next received handshake packet returning an error
    /// if one could not be formed or another message type was received
    fn next_handshake(&mut self) -> SslResult<HandshakePayload> {
        loop {
            if let Some(payload) = self.joiner.next() {
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

    /// Converts the provided handshake too a message and writes it
    fn write_handshake(&mut self, handshake: HandshakePayload) -> io::Result<()> {
        let message = handshake.as_message();
        self.stream.write_message(message)
    }

    /// Handles handshaking returning the underlying stream for use
    /// once handshaking is complete
    pub fn handshake(mut self) -> Result<SslStream<S>, SslError> {
        let hello_data = self.accept_hello()?;
        let exchange_data = self.accept_exchange(&hello_data)?;
        self.accept_cipher_change(exchange_data, &hello_data)?;
        self.accept_finished()?;

        println!("Handshake completed success");

        Ok(self.stream)
    }

    /// Handles the hello portion of the handshaking processes returns
    /// a struct containing the client and server randoms
    fn accept_hello(&mut self) -> SslResult<HelloData> {
        println!("State = Accept Hello");
        let (protocol, client_random) = match self.next_handshake()? {
            HandshakePayload::ClientHello(a, b) => (a, b),
            _ => return Err(SslError::UnexpectedMessage),
        };
        println!("Got Client Hello (Version: {protocol:?}, Random: {client_random:?})");

        let server_random = SSLRandom::new().map_err(|_| SslError::Failure)?;
        let certificate = self.stream.certificate.clone();
        // Send server hello, certificate, and server done
        self.write_handshake(HandshakePayload::ServerHello(server_random.clone()))?;
        self.write_handshake(HandshakePayload::Certificate(certificate))?;
        self.write_handshake(HandshakePayload::ServerHelloDone)?;

        println!("State -> Exchange");
        Ok(HelloData {
            client_random,
            server_random,
        })
    }

    /// Handles accepting the client key exchange and generating the master
    /// key from the provided encrypted pre-master key
    fn accept_exchange(&mut self, hello: &HelloData) -> SslResult<ExchangeData> {
        println!("State = Exchange");

        let encrypted_pm_key = match self.next_handshake()? {
            HandshakePayload::ClientKeyExchange(payload) => payload,
            _ => return Err(SslError::UnexpectedMessage),
        };

        println!("Got encrypted pre-master key");
        let pm_key_vec = self
            .stream
            .private_key
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &encrypted_pm_key)
            .map_err(|_| {
                println!("Failed to decrypt master key");
                SslError::Failure
            })?;

        let mut pm_key = [0u8; 48];
        pm_key.clone_from_slice(&pm_key_vec);

        println!("Decrypted pre-master key: {pm_key:?}");

        let mut randoms = [0u8; 64];
        randoms[..32].copy_from_slice(&hello.client_random.0);
        randoms[32..].copy_from_slice(&hello.server_random.0);

        let master_key = create_master_secret(&pm_key, &randoms);

        println!("Created master key: {master_key:?}");

        println!("State -> Cipher Change");

        Ok(ExchangeData {
            master_key,
            _randoms: randoms,
        })
    }

    /// Handles changing over ciphers when the ChangeCipherSpec message is
    /// received
    fn accept_cipher_change(
        &mut self,
        exchange_data: ExchangeData,
        hello_data: &HelloData,
    ) -> SslResult<()> {
        println!("State = Cipher Change");

        // Expect the client to change cipher spec
        match self.stream.next_message()?.ty {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(SslError::UnexpectedMessage),
        }

        let master_key = exchange_data.master_key;
        let client_write_key = compute_final_key(
            &master_key[32..37],
            &hello_data.client_random.0,
            &hello_data.server_random.0,
        );
        let server_write_key = compute_final_key(
            &master_key[37..42],
            &hello_data.server_random.0,
            &hello_data.client_random.0,
        );

        let client_write_key = Rc4::new_from_slice(&client_write_key).unwrap();
        let server_write_key = Rc4::new_from_slice(&server_write_key).unwrap();

        println!("Created RC4 keys from master key. Switching to CipherSpec");

        self.stream.processor = MessageProcessor::RC4 {
            master_key,
            read_key: client_write_key,
            write_key: server_write_key,
        };

        Ok(())
    }

    /// Accepts the finishing message from the client switching the clients
    /// CipherSpec and writing back the finished message
    fn accept_finished(&mut self) -> SslResult<()> {
        let (md5_hash, sha_hash) = match self.next_handshake()? {
            HandshakePayload::Finished(a, b) => (a, b),
            _ => return Err(SslError::UnexpectedMessage),
        };

        println!("Got finished {md5_hash:?} {sha_hash:?}");

        let cipher_spec_msg = Message {
            ty: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };

        self.stream.write_message(cipher_spec_msg)?;

        self.write_handshake(HandshakePayload::Finished(md5_hash, sha_hash))?;
        Ok(())
    }
}

/// Structure representing known types for encoding and decoding messages
pub enum MessageProcessor {
    None,
    RC4 {
        master_key: MasterKey,
        read_key: Rc4<U16>,
        write_key: Rc4<U16>,
    },
}

/// Get the 16 byte write secret used for creating macs
#[inline]
fn write_secret_client(key: &MasterKey) -> &[u8] {
    // Client [0..16]
    &key[0..16]
}

/// Get the 16 byte write secret used for creating macs
#[inline]
fn write_secret_server(key: &MasterKey) -> &[u8] {
    // Client [0..16]
    // Server [16..32]
    &key[16..32]
}

impl MessageProcessor {
    /// Appends the mac value to this message
    pub fn compute_mac(write_secret: &[u8], message: &[u8], seq: u64) -> [u8; 20] {
        let inner = {
            let mut sha = Sha1::new();
            sha.update(write_secret);
            sha.update(&[0x36; 40]);
            sha.update(&seq.to_be_bytes());
            sha.update(&message.len().to_be_bytes());
            sha.update(message);
            sha.digest().bytes()
        };
        let mut outer = Sha1::new();
        outer.update(write_secret);
        outer.update(&[0x5c; 40]);
        outer.update(&inner);
        outer.digest().bytes()
    }

    pub fn encrypt(&mut self, message: BorrowedMessage, seq: u64) -> OpaqueMessage {
        match self {
            MessageProcessor::None => OpaqueMessage {
                ty: message.content_type,
                payload: message.payload.to_vec(),
            },
            MessageProcessor::RC4 {
                write_key,
                master_key,
                ..
            } => {
                let mut payload = message.payload.to_vec();
                let mac = Self::compute_mac(write_secret_server(master_key), &payload, seq);
                payload.extend_from_slice(&mac);
                write_key.apply_keystream(&mut payload);
                OpaqueMessage {
                    ty: message.content_type,
                    payload,
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
                master_key,
                ..
            } => {
                let mut payload = message.payload.to_vec();
                read_key.apply_keystream(&mut payload);

                println!("{payload:?}");

                let mac = &payload[payload.len() - 20..];
                let payload = payload[..payload.len() - 20].to_vec();
                println!("{mac:?}");
                println!("{payload:?}");

                let expected_mac =
                    Self::compute_mac(write_secret_client(master_key), &payload, seq);

                println!("Decrypted message: \nMac: {mac:?}\nExpected Mac: {expected_mac:?}");

                // TODO: Remove mac

                Message {
                    ty: message.ty,
                    payload,
                }
            }
        }
    }
}
