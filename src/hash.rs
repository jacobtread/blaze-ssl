use ring::hmac;
use ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY;

pub fn generate_master_secret(pre: &[u8; 48], randoms: &[u8; 64]) -> [u8; 48] {
    let mut out = [0u8; 48];

    let alg = HMAC_SHA1_FOR_LEGACY_USE_ONLY;

    let hmac_key = hmac::Key::new(alg, pre);

    // A(1)
    let mut current_a = hmac::sign(&hmac_key, randoms);
    let chunk_size = alg.digest_algorithm().output_len;
    for chunk in out.chunks_mut(chunk_size) {
        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let p_term = concat_sign(&hmac_key, current_a.as_ref(), randoms);
        chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

        // A(i+1) = HMAC_hash(secret, A(i))
        current_a = hmac::sign(&hmac_key, current_a.as_ref());
    }

    out
}

fn concat_sign(key: &hmac::Key, a: &[u8], b: &[u8]) -> hmac::Tag {
    let mut ctx = hmac::Context::with_key(key);
    ctx.update(a);
    ctx.update(b);
    ctx.sign()
}
