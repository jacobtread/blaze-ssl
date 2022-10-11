use crate::msg::codec::{Codec, Reader};
use crate::msg::data::{Certificate, PrivateKey};
use crate::msg::deframer::{fragment_message, MessageDeframer};
use crate::msg::enc::{Crypt, PlainTextEncryptor, RC4Encryptor};
use crate::msg::enums::ContentType;
use crate::msg::handshake::HandshakePayload;
use crate::msg::joiner::HandshakeJoiner;
use crate::msg::types::{ProtocolVersion, SSLRandom};
use crate::msg::RawMessage;
use derive_more::From;
use rc4::{KeyInit, Rc4};
use ring::hmac;
use rsa::{PaddingScheme, RsaPrivateKey};
use std::fs::read;
use std::io;
use std::io::{BufRead, ErrorKind, Read, Write};
use ring::signature::RsaKeyPair;

pub struct SslStream<S> {
    stream: S,
    has_seen_eof: bool,
    certificate: Certificate,
    private_key: RsaPrivateKey,
    deframer: MessageDeframer,
    crypt: Box<dyn Crypt>,
}

#[derive(Debug, From)]
pub enum SslError {
    IO(io::Error),
    InvalidMessages,
    UnexpectedMessage,
    Failure,
}

impl<S> SslStream<S>
where
    S: Read + Write,
{
    pub fn new(value: S, cert: Certificate, private: RsaPrivateKey) -> Result<Self, SslError> {
        let stream = Self {
            stream: value,
            has_seen_eof: false,
            certificate: cert,
            private_key: private,
            deframer: MessageDeframer::new(),
            crypt: Box::new(PlainTextEncryptor::new()),
        };
        let handshaking = HandshakingStream {
            state: HandshakeState::WaitingHello,
            inner: stream,
            joiner: HandshakeJoiner::new(),
        };
        handshaking.handshake()
    }

    pub fn read_tls(&mut self) -> Result<usize, io::Error> {
        let res = self.deframer.read(&mut self.stream);
        if let Ok(0) = res {
            self.has_seen_eof = true;
        }
        res
    }

    pub fn take_message(&mut self) -> Result<RawMessage, SslError> {
        loop {
            if let Some(message) = self.deframer.messages.pop_front() {
                println!("Got raw message {message:?}");
                return Ok(message);
            }
            self.deframer.read(&mut self.stream)?;
            if self.deframer.invalid {
                return Err(SslError::InvalidMessages);
            }
        }
    }

    pub fn write_message(&mut self, message: RawMessage) -> io::Result<()> {
        for msg in fragment_message(&message) {
            let bytes = msg.encode();
            self.write(&bytes)?;
        }
        Ok(())
    }
}

impl<S> Write for SslStream<S>
where
    S: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut out = Vec::new();
        out.extend_from_slice(buf);
        self.crypt.encrypt(&mut out);
        self.stream.write(&out)
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
        let read_count = self.stream.read(buf)?;
        self.crypt.decrypt(buf);
        Ok(read_count)
    }
}

/// Stream wrapper where the client and server are in the
/// handshaking process. Provides additional structures for
/// reading handshake messages from the stream
pub struct HandshakingStream<S> {
    inner: SslStream<S>,
    state: HandshakeState,
    joiner: HandshakeJoiner,
}

pub enum HandshakeState {
    WaitingHello,
    Exchanging {
        server_random: SSLRandom,
        client_random: SSLRandom,
    },
    WaitCipherChange {
        master_key: [u8; 48],
        seed: [u8; 64],
    },
}

impl<S> HandshakingStream<S>
where
    S: Read + Write,
{
    fn take_handshake(&mut self) -> Result<HandshakePayload, SslError> {
        loop {
            println!("Taking handshake");
            if let Some(payload) = self.joiner.frames.pop_front() {
                println!("Got payload");
                return Ok(payload);
            } else {
                println!("Cant make handshake with this");
                let message = self.inner.take_message()?;
                if message.content_type != ContentType::Handshake {
                    return Err(SslError::UnexpectedMessage);
                }
                println!("Taking message");
                self.joiner.take_message(message);
            }
        }
    }

    pub fn handshake(mut self) -> Result<SslStream<S>, SslError> {
        loop {
            match &self.state {
                HandshakeState::WaitingHello => {
                    println!("Hit Hello");
                    let message = self.take_handshake()?;
                    let (_, client_random) = match message {
                        HandshakePayload::ClientHello(a, b) => (a, b),
                        _ => return Err(SslError::UnexpectedMessage),
                    };

                    let server_random = SSLRandom::new().map_err(|_| SslError::Failure)?;

                    let server_hello =
                        HandshakePayload::ServerHello(server_random.clone()).as_message();

                    self.inner.write_message(server_hello)?;

                    let certificate = self.inner.certificate.clone();
                    let cert = HandshakePayload::Certificate(certificate).as_message();
                    self.inner.write_message(cert)?;

                    let server_hello_done = HandshakePayload::ServerHelloDone.as_message();
                    self.inner.write_message(server_hello_done)?;

                    self.state = HandshakeState::Exchanging {
                        client_random,
                        server_random,
                    }
                }
                HandshakeState::Exchanging {
                    client_random,
                    server_random,
                } => {
                    println!("Hit Exchanging");
                    let enc_master = match self.take_handshake()? {
                        HandshakePayload::ClientKeyExchange(r) => r,
                        _ => return Err(SslError::UnexpectedMessage),
                    };

                    ring::agreement::UnparsedPublicKey::new();
                    ring::agreement::agree_ephemeral()

                    println!("Switching Cipher");
                    let master_key = self
                        .inner
                        .private_key
                        .decrypt(PaddingScheme::PKCS1v15Encrypt, &enc_master)
                        .map_err(|_| {
                            println!("Failed to decrypt");
                            SslError::Failure
                        })?;

                    let mut contents = Reader::new(&master_key);
                    let mut pre_master_key = [0; 48];
                    let bytes = contents.take(48).ok_or(SslError::Failure)?;
                    pre_master_key.clone_from_slice(bytes);

                    println!("Master Key {master_key:?}");

                    fn join_randoms(first: &[u8; 32], second: &[u8; 32]) -> [u8; 64] {
                        let mut randoms = [0u8; 64];
                        randoms[..32].copy_from_slice(first);
                        randoms[32..].copy_from_slice(second);
                        randoms
                    }

                    let seed = join_randoms(&client_random.0, &server_random.0);

                    let mut master_secret = [0u8; 48];
                    let signer = ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;

                    let mut current_a = hmac::sign();

                    self.state = HandshakeState::WaitCipherChange {
                        master_key: pre_master_key,
                        seed,
                    };
                }
                HandshakeState::WaitCipherChange { master_key, seed } => {
                    println!("Waiting cipher change");
                    let message = self.inner.take_message()?;
                    if message.content_type != ContentType::ChangeCipherSpec {
                        return Err(SslError::UnexpectedMessage);
                    }

                    let cipher = Rc4::new_from_slice(&master_key[0..16]).map_err(|err| {
                        println!("Failed to create rc4 {err:?}");
                        SslError::Failure
                    })?;
                    self.inner.crypt = Box::new(RC4Encryptor::new(cipher));

                    println!("Waiting finished");
                    let message = self.take_handshake()?;
                    let (md5_hash, sha_hash) = match message {
                        HandshakePayload::Finished { md5_hash, sha_hash } => (md5_hash, sha_hash),
                        _ => return Err(SslError::UnexpectedMessage),
                    };

                    println!("Got finished {md5_hash:?} {sha_hash:?}");

                    return Ok(self.inner);
                }
            }
        }
    }
}
