use crate::stream::{CombinedRandom, MasterKey, PreMasterKey};
use sha1_smol::Sha1;

pub fn compute_final_key(key_slice: &[u8], first: &[u8], second: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(key_slice);
    out.consume(first);
    out.consume(second);
    out.compute().0
}

pub fn create_master_secret(pm: &PreMasterKey, rand: &CombinedRandom) -> MasterKey {
    let mut out = [0u8; 48];
    let mut tag = create_tag_sha(&[], pm, rand);
    for chunk in out.chunks_mut(16) {
        let value = create_md5_value(pm, &tag);
        chunk.copy_from_slice(&value);
        tag = create_tag_sha(&tag, pm, rand);
    }
    out
}

fn create_tag_sha(prev: &[u8], pm: &PreMasterKey, rand: &[u8]) -> [u8; 20] {
    let mut out = Sha1::new();
    out.update(prev);
    out.update(pm);
    out.update(rand);
    out.digest().bytes()
}

fn create_md5_value(pm: &PreMasterKey, tag: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(pm);
    out.consume(tag);
    out.compute().0
}
