use crate::stream::{CombinedRandom, MasterKey, PreMasterKey};
use sha1_smol::Sha1;

pub fn create_master_secret(pre: &PreMasterKey, randoms: &CombinedRandom) -> MasterKey {
    let mut out = [0u8; 48];
    let mut tag = create_sha_tag(pre, randoms);
    out[0..16].copy_from_slice(&create_md5_tag(pre, &tag));
    tag = create_sha_tag(pre, &tag);
    out[16..32].copy_from_slice(&create_md5_tag_2(pre, &tag, randoms));
    tag = create_sha_tag(pre, &tag);
    out[32..48].copy_from_slice(&create_md5_tag_2(pre, &tag, randoms));
    out
}

pub fn create_sha_tag(key: &PreMasterKey, randoms: &[u8]) -> [u8; 20] {
    let mut out = Sha1::new();
    out.update(key);
    out.update(randoms);
    out.digest().bytes()
}

pub fn create_md5_tag(key: &[u8; 48], value: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(key);
    out.consume(value);
    out.compute().0
}

pub fn create_md5_tag_2(key: &[u8; 48], value: &[u8], value_2: &[u8]) -> [u8; 16] {
    let mut out = md5::Context::new();
    out.consume(key);
    out.consume(value);
    out.consume(value_2);
    out.compute().0
}
