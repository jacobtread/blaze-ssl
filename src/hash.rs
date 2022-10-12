use crate::handshake::HandshakeHashBuffer;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;

pub fn generate_key_block(out: &mut [u8], pm: &[u8], rand_1: &[u8; 32], rand_2: &[u8; 32]) {
    // The digest use for the outer hash
    let mut outer = Md5::new();
    // The digest used for the inner hash
    let mut inner = Sha1::new();

    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(rand_1);
    randoms[32..].copy_from_slice(rand_2);

    let mut inner_value = [0u8; 20];

    let salts = ["A", "BB", "CCC", "DDDD"].iter();

    for (chunk, salt) in out.chunks_mut(16).zip(salts) {
        inner.input(salt.as_bytes());
        inner.input(pm);
        inner.input(&randoms);
        inner.result(&mut inner_value);
        inner.reset();

        outer.input(pm);
        outer.input(&inner_value);
        outer.result(chunk);
        outer.reset();
    }
}

pub enum FinishedSender {
    Client,
    Server,
}

impl FinishedSender {
    pub fn value(&self) -> [u8; 4] {
        match self {
            FinishedSender::Client => 0x434C4E54u32.to_be_bytes(),
            FinishedSender::Server => 0x53525652u32.to_be_bytes(),
        }
    }
}

pub fn compute_finished_md5(
    master_secret: &[u8],
    sender: FinishedSender,
    hash_buffer: &HandshakeHashBuffer,
) -> [u8; 16] {
    let mut digest = Md5::new();
    let mut out = [0u8; 16];
    let pad1 = [0x36; 48];
    let pad2 = [0x5c; 48];
    digest.input(&hash_buffer.0);
    digest.input(&sender.value());
    digest.input(master_secret);
    digest.input(&pad1);
    digest.result(&mut out);
    digest.reset();

    digest.input(master_secret);
    digest.input(&pad2);
    digest.input(&out);
    digest.result(&mut out);
    out
}

pub fn compute_finished_sha(
    master_secret: &[u8],
    sender: FinishedSender,
    hash_buffer: &HandshakeHashBuffer,
) -> [u8; 20]{
    let mut digest = Sha1::new();
    let mut out = [0u8; 20];

    let pad1 = [0x36; 40];
    let pad2 = [0x5c; 40];
    digest.input(&hash_buffer.0);
    digest.input(&sender.value());
    digest.input(master_secret);
    digest.input(&pad1);
    digest.result(&mut out);
    digest.reset();

    digest.input(master_secret);
    digest.input(&pad2);
    digest.input(&out);
    digest.result(&mut out);
    out
}
