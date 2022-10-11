use derive_more::From;
use rc4::cipher::{BlockDecryptMut, StreamCipherError};
use rc4::consts::{U1, U16};
use rc4::{KeyInit, Rc4, StreamCipher};
use std::error::Error;

#[derive(Debug, From)]
pub enum CryptError {
    StreamCipherError(StreamCipherError),
}

pub trait Crypt {
    fn encrypt(&mut self, input: &mut [u8]);

    fn decrypt(&mut self, input: &mut [u8]);
}

pub struct RC4Encryptor {
    cipher: Rc4<U16>,
}

impl RC4Encryptor {
    pub fn new(cipher: Rc4<U16>) -> Self {
        Self { cipher }
    }
}

impl Crypt for RC4Encryptor {
    fn encrypt(&mut self, input: &mut [u8]) {
        self.cipher.apply_keystream(input);
    }

    fn decrypt(&mut self, input: &mut [u8]) {
        self.cipher.apply_keystream(input);
    }
}

pub struct PlainTextEncryptor;

impl PlainTextEncryptor {
    pub fn new() -> Self {
        Self {}
    }
}

impl Crypt for PlainTextEncryptor {
    fn encrypt(&mut self, _: &mut [u8]) {}

    fn decrypt(&mut self, _: &mut [u8]) {}
}
