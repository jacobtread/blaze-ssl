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
