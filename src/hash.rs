use crypto::digest::Digest;
use crypto::hmac::Hmac;
use crypto::mac::{Mac, MacResult};
use crypto::md5::Md5;
use crypto::sha1::Sha1;

pub fn generate_key_block_2(out: &mut [u8], pm: &[u8], r1: &[u8], r2: &[u8]) {
    let mut outer_hasher = Md5::new();
    let mut inner_hasher = Sha1::new();

    let mut tag = [0u8; 20];
    inner_hasher.input(pm);
    inner_hasher.input(r1);
    inner_hasher.input(r2);
    inner_hasher.result(&mut tag);
    inner_hasher.reset();

    for chunk in out.chunks_mut(16) {
        outer_hasher.input(pm);
        outer_hasher.input(&tag);
        outer_hasher.result(chunk);
        outer_hasher.reset();

        inner_hasher.input(&tag);
        inner_hasher.input(pm);
        inner_hasher.input(r1);
        inner_hasher.input(r2);
        inner_hasher.result(&mut tag);
        inner_hasher.reset();
    }
}

fn get_tag(prev: &[u8], key: &[u8], a: &[u8], b: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Sha1::new(), key);
    hmac.input(prev);
    hmac.input(key);
    hmac.input(a);
    hmac.input(b);
    hmac.result()
}

fn concat_hmac(key: &[u8], a: &[u8], b: &[u8], c: &[u8]) -> MacResult {
    let mut hmac = Hmac::new(Md5::new(), key);
    hmac.input(key);
    hmac.input(a);
    hmac.input(b);
    hmac.input(c);
    hmac.result()
}

pub fn generate_key_block(out: &mut [u8], pm: &[u8], r1: &[u8; 32], r2: &[u8; 32]) {
    let mut tag = create_tag_sha(&[], pm, r1, r2);
    for chunk in out.chunks_mut(16) {
        let value = create_md5_value(pm, &tag);
        chunk.copy_from_slice(&value);
        tag = create_tag_sha(&tag, pm, r1, r2);
    }
}

fn create_tag_sha(prev: &[u8], pm: &[u8], r1: &[u8], r2: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.input(prev);
    hasher.input(pm);
    hasher.input(r1);
    hasher.input(r2);
    let mut out = [0u8; 20];
    hasher.result(&mut out);
    out
}

fn create_md5_value(pm: &[u8], tag: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.input(pm);
    hasher.input(tag);
    let mut out = [0u8; 16];
    hasher.result(&mut out);
    out
}
