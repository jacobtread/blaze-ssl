use std::io::{Read, Write};
use crypto::rc4::Rc4;
use rsa::{PaddingScheme, PublicKey, RsaPublicKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::rand_core::{OsRng, RngCore};
use crate::codec::{Certificate, SSLRandom};
use crate::constants::PROTOCOL_SSL3;
use crate::handshake::{HandshakePayload, Transcript};
use crate::crypto::{compute_finished_md5, compute_finished_sha, create_crypto_state, CryptographicState, FinishedSender};
use crate::msgs::{FatalAlert, HandshakeJoiner, Message, MessageType};
use crate::stream::{BlazeError, BlazeResult, BlazeStream, ReadProcessor, WriteProcessor};

/// Stream wrapper where the client and server are in the
/// handshaking process. Provides additional structures for
/// reading handshake messages from the stream
pub struct ClientHandshake<S> {
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

impl<S> ClientHandshake<S>
    where
        S: Read + Write,
{
    /// Handles handshaking returning the underlying stream for use
    /// once handshaking is complete
    pub fn handshake(stream: BlazeStream<S>) -> Result<BlazeStream<S>, BlazeError> {
        let mut value = ClientHandshake {
            stream,
            joiner: HandshakeJoiner::new(),
            transcript: Transcript::new(),
        };
        let hello_data = value.emit_hello()?;
        let cert = value.accept_certificate()?;
        let state = value.start_key_exchange(&hello_data, &cert)?;
        value.emit_cipher_change_spec(&state)?;
        value.emit_finished(&state)?;
        value.accept_cipher_change(&state)?;
        value.accept_finished(&state)?;
        Ok(value.stream)
    }

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

    /// Handles the hello portion of the handshaking processes returns
    /// a struct containing the client and server randoms
    fn emit_hello(&mut self) -> BlazeResult<HelloData> {
        let client_random = SSLRandom::new()
            .map_err(|_| self.stream.alert_fatal(FatalAlert::IllegalParameter))?;

        // Send server hello, certificate, and server done
        let message = HandshakePayload::ClientHello(client_random.clone())
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;

        let server_random = match self.next_handshake()? {
            HandshakePayload::ServerHello(random) => random,
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        Ok(HelloData {
            client_random,
            server_random,
        })
    }

    fn accept_certificate(&mut self) -> BlazeResult<Certificate> {
        let certificate = match self.next_handshake()? {
            HandshakePayload::Certificate(cert) => cert,
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };
        Ok(certificate)
    }

    fn start_key_exchange(&mut self, hello: &HelloData, cert: &Certificate) -> BlazeResult<CryptographicState> {
        let mut rng = OsRng;
        let mut pre_master_secret = [0u8; 48];
        pre_master_secret[0..2].copy_from_slice(&PROTOCOL_SSL3.to_be_bytes());
        rng.fill_bytes(&mut pre_master_secret[2..]);
        let public_key = RsaPublicKey::from_public_key_der(&cert.0)
            .map_err(|_| self.stream.alert_fatal(FatalAlert::IllegalParameter))?;
        let pm_enc = public_key.encrypt(&mut OsRng, PaddingScheme::PKCS1v15Encrypt, &pre_master_secret)
            .map_err(|_| self.stream.alert_fatal(FatalAlert::IllegalParameter))?;
        self.emit_key_exchange(pm_enc)?;
        let client_random = &hello.client_random.0;
        let server_random = &hello.server_random.0;
        let state = create_crypto_state(&pre_master_secret, client_random, server_random);
        Ok(state)
    }

    fn emit_key_exchange(&mut self, pm_enc: Vec<u8>) -> BlazeResult<()> {
        let message = HandshakePayload::ClientKeyExchange(pm_enc)
            .as_message();
        self.transcript.push_msg(&message);
        self.stream.write_message(message)?;
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
        let key = Rc4::new(&state.client_write_key);
        let mut mac_secret = [0u8; 16];
        mac_secret.copy_from_slice(&state.client_write_secret);
        self.stream.write_processor = WriteProcessor::RC4 {
            mac_secret,
            key,
        };
        Ok(())
    }

    fn emit_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let master_key = &state.master_key;

        let md5_hash = compute_finished_md5(master_key, FinishedSender::Client, &self.transcript.client);
        let sha_hash = compute_finished_sha(master_key, FinishedSender::Client, &self.transcript.client);

        let message = HandshakePayload::Finished(md5_hash, sha_hash)
            .as_message();
        self.stream.write_message(message)?;
        Ok(())
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
        let key = Rc4::new(&state.server_write_key);
        let mut mac_secret = [0u8; 16];
        mac_secret.copy_from_slice(&state.server_write_secret);
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
                if !self.check_server_hashes(&state.master_key, md5_hash, sha_hash) {
                    return Err(self.stream.alert_fatal(FatalAlert::IllegalParameter));
                }
            }
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        Ok(())
    }

    /// Computes and compares the client hashes for the handshaking process returning
    /// whether they are matching hashes
    fn check_server_hashes(&mut self, master_key: &[u8; 48], md5_hash: [u8; 16], sha_hash: [u8; 20]) -> bool {
        let exp_md5_hash = compute_finished_md5(master_key, FinishedSender::Server, &self.transcript.full);
        let exp_sha_hash = compute_finished_sha(master_key, FinishedSender::Server, &self.transcript.full);
        exp_md5_hash == md5_hash && exp_sha_hash == sha_hash
    }
}