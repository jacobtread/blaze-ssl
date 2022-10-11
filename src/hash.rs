use sha1_smol::Sha1;

pub fn generate_key_block(out: &mut [u8], pm: &[u8], sr: &[u8; 32], cr: &[u8; 32]) {
    let mut randoms = [0u8; 64];
    randoms[..32].clone_from_slice(sr);
    randoms[32..].clone_from_slice(cr);

    let mut tag = create_tag_sha(&[], pm, &randoms);
    for chunk in out.chunks_mut(16) {
        let value = create_md5_value(pm, &tag);
        chunk.copy_from_slice(&value);
        tag = create_tag_sha(&tag, pm, &randoms);
    }
}

fn create_tag_sha(prev: &[u8], pm: &[u8], rand: &[u8]) -> [u8; 20] {
    let mut out = Sha1::new();
    out.update(prev);
    out.update(pm);
    out.update(rand);
    out.digest().bytes()
}

fn create_md5_value(pm: &[u8], tag: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(pm);
    out.consume(tag);
    out.compute().0
}
