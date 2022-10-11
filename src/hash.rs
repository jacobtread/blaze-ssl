use sha1_smol::Sha1;

pub fn generate_key_block(out: &mut [u8], pm: &[u8], r1: &[u8; 32], r2: &[u8; 32]) {
    let mut tag = create_tag_sha(&[], pm, r1, r2);
    for chunk in out.chunks_mut(16) {
        let value = create_md5_value(pm, &tag);
        chunk.copy_from_slice(&value);
        tag = create_tag_sha(&tag, pm, r1, r2);
    }
}

fn create_tag_sha(prev: &[u8], pm: &[u8], r1: &[u8], r2: &[u8]) -> [u8; 20] {
    let mut out = Sha1::new();
    out.update(prev);
    out.update(pm);
    out.update(r1);
    out.update(r2);
    out.digest().bytes()
}

fn create_md5_value(pm: &[u8], tag: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(pm);
    out.consume(tag);
    out.compute().0
}
