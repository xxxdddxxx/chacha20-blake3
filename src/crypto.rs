use rand::prelude::*;

pub fn get_key(context: &str) -> ([u8; 32], [u8; 32]) {
    let mut key = [0u8; 32];
    rand::rng().fill_bytes(&mut key);

    (blake3::derive_key(context, &key), key)
}