use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;


/// Structure for storing cryptographic keys and
/// state that may be required
pub struct CryptographicState {
    pub(crate) master_key: [u8; 48],
    pub(crate) client_write_secret: [u8; 20],
    pub(crate) server_write_secret: [u8; 20],
    pub(crate) client_write_key: [u8; 16],
    pub(crate) server_write_key: [u8; 16],
}

/// Creates the cryptographic state from the provided pre-master secret client random
/// and server random
pub fn create_crypto_state(pm_key: &[u8], cr: &[u8; 32], sr: &[u8; 32]) -> CryptographicState {
    let mut master_key = [0u8; 48];
    generate_key_block(&mut master_key, &pm_key, cr, sr);

    // Generate key block 80 bytes long (20x2 for write secrets + 16x2 for write keys) only 72 bytes used
    let mut key_block = [0u8; 80];
    generate_key_block(&mut key_block, &master_key, sr, cr);

    let mut client_write_secret = [0u8; 20];
    client_write_secret.copy_from_slice(&key_block[0..20]);
    let mut server_write_secret = [0u8; 20];
    server_write_secret.copy_from_slice(&key_block[20..40]);

    let mut client_write_key = [0u8; 16];
    client_write_key.copy_from_slice(&key_block[40..56]);
    let mut server_write_key = [0u8; 16];
    server_write_key.copy_from_slice(&key_block[56..72]);

    CryptographicState {
        master_key,
        client_write_secret,
        server_write_secret,
        client_write_key,
        server_write_key,
    }
}

pub fn generate_key_block(out: &mut [u8], pm: &[u8], rand_1: &[u8; 32], rand_2: &[u8; 32]) {
    // The digest use for the outer hash
    let mut outer = Md5::new();
    // The digest used for the inner hash
    let mut inner = Sha1::new();

    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(rand_1);
    randoms[32..].copy_from_slice(rand_2);

    let mut inner_value = [0u8; 20];

    let salts = ["A", "BB", "CCC", "DDDD", "EEEEE"].iter();

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

pub fn compute_mac(write_secret: &[u8], ty: u8, message: &[u8], seq: &u64) -> [u8; 20] {
    let mut digest = Sha1::new();
    let mut out = [0u8; 20];
    let pad1 = [0x36; 40];
    let pad2 = [0x5c; 40];
    // A = hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment)
    digest.input(write_secret);
    digest.input(&pad1);
    digest.input(&seq.to_be_bytes());
    digest.input(&[ty]);
    let length = u16::to_be_bytes(message.len() as u16);
    digest.input(&length);
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

pub enum FinishedSender {
    Client,
    Server,
}

impl FinishedSender {
    pub fn value(&self) -> [u8; 4] {
        let value: u32 = match self {
            FinishedSender::Client => 0x434C4E54,
            FinishedSender::Server => 0x53525652,
        };
        value.to_be_bytes()
    }
}

pub fn compute_finished_md5(
    master_secret: &[u8],
    sender: FinishedSender,
    transcript: &[u8],
) -> [u8; 16] {
    let mut digest = Md5::new();
    let mut out = [0u8; 16];
    let pad1 = [0x36; 48];
    let pad2 = [0x5c; 48];
    digest.input(transcript);
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
    transcript: &[u8],
) -> [u8; 20]{
    let mut digest = Sha1::new();
    let mut out = [0u8; 20];

    let pad1 = [0x36; 40];
    let pad2 = [0x5c; 40];
    digest.input(transcript);
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
