use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;

/// Function for generating master key and Key blocks
///
/// # Master Secret
/// out = &mut [u8; 48] (Master secret out)
/// secret = &[u8; 48] (Pre Master Secret)
/// rand_1 = &[u8; 32] (Client Random)
/// rand_2 = &[u8; 32] (Server Random)
///
/// master_secret =
///         MD5(pre_master_secret + SHA('A' + pre_master_secret +
///             ClientHello.random + ServerHello.random)) +
///         MD5(pre_master_secret + SHA('BB' + pre_master_secret +
///             ClientHello.random + ServerHello.random)) +
///         MD5(pre_master_secret + SHA('CCC' + pre_master_secret +
///             ClientHello.random + ServerHello.random));
/// # Key Block
/// out = &mut [u8; KEY_BLOCK_LENGTH] (Key Block out)
/// secret = &[u8; 48] (Master Secret)
/// rand_1 = &[u8; 32] (Server Random)
/// rand_2 = &[u8; 32] (Client Random)
///
/// key_block =
///         MD5(master_secret + SHA('A' + master_secret + ServerHello.random +
///             ClientHello.random)) +
///         MD5(master_secret + SHA('BB' + master_secret + ServerHello.random +
///             ClientHello.random)) +
///         MD5(master_secret + SHA('CCC' + master_secret + ServerHello.random +
///             ClientHello.random)) + [...];
///
pub fn generate_key_block(out: &mut [u8], secret: &[u8], rand_1: &[u8], rand_2: &[u8]) {
    let mut outer_hasher = Md5::new();
    let mut inner_hasher = Sha1::new();

    let mut tag = [0u8; 20];
    inner_hasher.input(secret);
    inner_hasher.input(rand_1);
    inner_hasher.input(rand_2);
    inner_hasher.result(&mut tag);
    inner_hasher.reset();

    for chunk in out.chunks_mut(16) {
        outer_hasher.input(secret);
        outer_hasher.input(&tag);
        outer_hasher.result(chunk);
        outer_hasher.reset();

        inner_hasher.input(&tag);
        inner_hasher.input(secret);
        inner_hasher.input(rand_1);
        inner_hasher.input(rand_2);
        inner_hasher.result(&mut tag);
        inner_hasher.reset();
    }
}
