use rand::prelude::*;

/*
    Helper function in order to create a byte
    array of u32 from u8 bytes.

    Example usage:
        nonce: le_words::<u8>(&some_bytes),
*/
pub fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    let mut out = [0u32; N];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        out[i] = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    out
}

pub fn get_key(context: &str) -> ([u8; 32], [u8; 32]) {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    (blake3::derive_key(context, &key), key)
}
