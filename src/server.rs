use std::io::{Read, Write};
use crypto::rc4::Rc4;
use rsa::PaddingScheme;
use crate::codec::SSLRandom;
use crate::handshake::{HandshakePayload, Transcript};
use crate::crypto::{compute_finished_md5, compute_finished_sha, create_crypto_state, CryptographicState, FinishedSender};
use crate::msgs::{FatalAlert, HandshakeJoiner, Message, MessageType};
use crate::stream::{BlazeError, BlazeResult, BlazeStream, ReadProcessor, SERVER_CERTIFICATE, SERVER_KEY, WriteProcessor};

/// Stream wrapper where the client and server are in the
/// handshaking process. Provides additional structures for
/// reading handshake messages from the stream
pub struct ServerHandshake<S> {
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

impl<S> ServerHandshake<S>
    where
        S: Read + Write,
{
    /// Handles handshaking returning the underlying stream for use
    /// once handshaking is complete
    pub fn handshake(stream: BlazeStream<S>) -> Result<BlazeStream<S>, BlazeError> {
        let mut value= ServerHandshake {
            stream,
            joiner: HandshakeJoiner::new(),
            transcript: Transcript::new()
        };
        let hello_data = value.accept_hello()?;
        let state = value.accept_exchange(hello_data)?;
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
    fn accept_hello(&mut self) -> BlazeResult<HelloData> {
        let client_random = match self.next_handshake()? {
            HandshakePayload::ClientHello( random) => random,
            _ => return Err(self.stream.alert_fatal(FatalAlert::UnexpectedMessage)),
        };

        let server_random = SSLRandom::new()
            .map_err(|_| {
                println!("SSL Random fail");
                self.stream.alert_fatal(FatalAlert::IllegalParameter)
            })?;

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
        let message = HandshakePayload::Certificate(SERVER_CERTIFICATE.clone())
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
            .map_err(|_| {
                println!("Failed to decrypt pm key");
                self.stream.alert_fatal(FatalAlert::IllegalParameter)
            })?;


        let client_random = &hello.client_random.0;
        let server_random = &hello.server_random.0;

        let state = create_crypto_state(&pm_key, client_random, server_random);
        Ok(state)
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
        let mut mac_secret = [0u8; 20];
        mac_secret.copy_from_slice(&state.client_write_secret);
        self.stream.read_processor = ReadProcessor::RC4 {
            mac_secret,
            key,
            seq: 0
        };
        Ok(())
    }

    /// Accepts the finishing message from the client switching the clients
    /// CipherSpec and writing back the finished message
    fn accept_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        match self.next_handshake()? {
            HandshakePayload::Finished(md5_hash, sha_hash) => {
                if !self.check_client_hashes(&state.master_key, md5_hash, sha_hash) {
                    println!("Finished hashes not matching");
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
        let mut mac_secret = [0u8; 20];
        mac_secret.copy_from_slice(&state.server_write_secret);
        self.stream.write_processor = WriteProcessor::RC4 {
            mac_secret,
            key,
            seq: 0
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