/*
    Chacha20Blake3 implementation in rust based off the RFC 8439 with the tweak of using blake3
    rather than poly1305.

    Construction of a payload goes with the init of a Chacha20Blake3 session (Session20b3):

        KK KK KK KK KK KK KK KK
        KK KK KK KK KK KK KK KK
        KK KK KK KK KK KK KK KK
        KK KK KK KK KK KK KK KK
        NN NN NN NN NN NN NN NN
        NN NN NN NN CC CC CC CC

        Session20b3:
            key:    256 bit key
            nonce:  96 bit nonce
            counter:32 bit counter

    For encryption we use the Chacha20Blake3Payload which features
    the ciphertext itself followed by a 256 bit tag at the end of the message.
    The tag is the generated hash from the blake3 function basing off the chacha20 key,
    nonce and ciphertext.
*/

pub mod crypto;

use rand::Rng;


/*
    Debugging macro for printing debug logs.
    Usage:
        dbg!(level, "text you want to print", ...);

    Being the level whatever propriety you want to characterize
    each message. For simplicity it assigns a color for the number
    based from the level.

*/
macro_rules! dbg {
    ($level:expr, $($arg:tt)*) => {{
        use colored::Colorize;
        let lvl: u8 = $level;
        let color: &str = match lvl {
            1 => "black",
            2 => "red",
            3 => "green",
            4 => "yellow",
            5 => "blue",
            6 => "magenta",
            7 => "cyan",
            8 => "white",
            _ => "white",
        };
        println!(
            "[{}]({:?})[{}]: {}",
            lvl.to_string().color(color),
            std::thread::current().id(),    // prints the thread id, useful for multithreading
            line!(),                        // prints the line in the code
            format!($($arg)*)
        )
    }};
}

pub struct Session20b3 {
    pub key: [u32; 8],
    pub nonce: [u32; 3],
    pub counter: u32,
}

pub struct Chacha20Blake3Payload {
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 32],
}

/*
    For future implementations, upgrades this function is SIMD compatible.
    Consider RFC 8439
*/
#[inline(always)]
fn quarter_round(state: &mut [u32; 16], x: usize, y: usize, z: usize, w: usize) {
    let mut a = state[x];
    let mut b = state[y];
    let mut c = state[z];
    let mut d = state[w];

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);

    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);

    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);

    state[x] = a;
    state[y] = b;
    state[z] = c;
    state[w] = d;
}

#[inline(always)]
fn inner_block(state: &mut [u32; 16]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

fn serialize(state: &[u32; 16]) -> [u8; 64] {
    let mut output = [0u8; 64];

    for (chunk, word) in output.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }

    output
}

pub fn chacha20_block(info: &Session20b3, counter: u32) -> [u8; 64] {
    let initial_state: [u32; 16] = [0x61707865,0x3320646e,0x79622d32,0x6b206574,
        info.key[0],info.key[1],info.key[2],info.key[3],
        info.key[4],info.key[5],info.key[6],info.key[7],
        counter,info.nonce[0],info.nonce[1],info.nonce[2],
    ];

    let mut state = initial_state;
    for _ in 0..10 {
        inner_block(&mut state);
    }

    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial_state[i]);
    }

    serialize(&state)
}

fn hchacha20(key: &[u32; 8], nonce16: &[u8; 16]) -> [u32; 8] {
    let mut nonce_words = [0u32; 4];

    for (i, chunk) in nonce16.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        nonce_words[i] = u32::from_le_bytes(b);
    }

    let initial_state: [u32; 16] = [0x61707865,0x3320646e,0x79622d32,0x6b206574,
        key[0], key[1], key[2], key[3],
        key[4], key[5], key[6], key[7],
        nonce_words[0],nonce_words[1],nonce_words[2],nonce_words[3],
    ];

    let mut state = initial_state;
    for _ in 0..10 {
        inner_block(&mut state);
    }

    [
        state[0],state[1],state[2],state[3],
        state[12],state[13],state[14],state[15],
    ]
}

pub fn xchacha20_encrypt(info: &Session20b3, plaintext: &[u8]) -> (Vec<u8>, [u32; 3]) {
    let mut nonce = [0u32; 3];
    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    for (i, chunk) in nonce_bytes.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        nonce[i] = u32::from_le_bytes(b);
    }

    let mut nonce16 = [0u8; 16];
    nonce16[0..12].copy_from_slice(&nonce_bytes);
    nonce16[12..16].copy_from_slice(&[0u8; 4]);

    let subkey = hchacha20(&info.key, &nonce16);

    let nonce12 = [0u32, nonce[0], nonce[1]];

    let xchacha_info = Session20b3 {
        key: subkey,
        nonce: nonce12,
        counter: info.counter,
    };

    let ciphertext = chacha20_encrypt(&xchacha_info, plaintext);

    (ciphertext, nonce)
}

pub fn xchacha20_decrypt(info: &Session20b3, ciphertext_with_nonce: &[u8]) -> Vec<u8> {
    let nonce_bytes_len = 12;
    if ciphertext_with_nonce.len() < nonce_bytes_len {
        return Vec::new();
    }

    let (ciphertext, nonce_bytes_slice) =
        ciphertext_with_nonce.split_at(ciphertext_with_nonce.len() - nonce_bytes_len);

    let mut nonce = [0u32; 3];
    for (i, chunk) in nonce_bytes_slice.chunks_exact(4).enumerate() {
        let mut b = [0u8; 4];
        b.copy_from_slice(chunk);
        nonce[i] = u32::from_le_bytes(b);
    }

    let mut nonce_bytes = [0u8; 12];
    for (i, w) in nonce.iter().enumerate() {
        nonce_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }

    let mut nonce16 = [0u8; 16];
    nonce16[0..12].copy_from_slice(&nonce_bytes);
    nonce16[12..16].copy_from_slice(&[0u8; 4]);

    let subkey = hchacha20(&info.key, &nonce16);

    let nonce12 = [0u32, nonce[0], nonce[1]];

    let xchacha_info = Session20b3 {
        key: subkey,
        nonce: nonce12,
        counter: info.counter,
    };

    chacha20_encrypt(&xchacha_info, ciphertext)
}

fn pad16(x: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let n = (16 - x.len() % 16) % 16;
    std::iter::repeat(0u8).take(n)
}

pub fn chacha20_aead_encrypt(
    info: &Session20b3,
    plaintext: &[u8],
    aad: &[u8],
) -> (Vec<u8>, [u8; 32]) {

    let otk = blake3_mac::derive_key(&info.key);

    let encryption_info = Session20b3 {
        key: info.key,
        nonce: info.nonce,
        counter: 1,
    };

    let ciphertext = chacha20_encrypt(&encryption_info, plaintext);

    let mut hasher = blake3::Hasher::new_keyed(&otk);

    hasher.update(aad);
    for _ in pad16(aad) {
        hasher.update(&[0u8]);
    }

    hasher.update(&ciphertext);
    for _ in pad16(&ciphertext) {
        hasher.update(&[0u8]);
    }

    hasher.update(&(aad.len() as u64).to_le_bytes());
    hasher.update(&(ciphertext.len() as u64).to_le_bytes());

    let mut tag = [0u8; 32];
    tag.copy_from_slice(hasher.finalize().as_bytes());

    let mut out = Vec::with_capacity(ciphertext.len() + 12);
    out.extend_from_slice(&ciphertext);
    for w in info.nonce.iter() {
        out.extend_from_slice(&w.to_le_bytes());
    }

    (out, tag)
}

pub fn chacha20_encrypt(info: &Session20b3, plaintext: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; plaintext.len()];

    for (j, (dst, src)) in out
        .chunks_exact_mut(64)
        .zip(plaintext.chunks_exact(64))
        .enumerate()
    {
        let key_stream = chacha20_block(info, info.counter + j as u32);
        for i in 0..64 {
            dst[i] = src[i] ^ key_stream[i];
        }
    }

    let tail = plaintext.len() % 64;
    if tail != 0 {
        let base = plaintext.len() - tail;
        let key_stream = chacha20_block(info, info.counter + (plaintext.len() / 64) as u32);
        for i in 0..tail {
            out[base + i] = plaintext[base + i] ^ key_stream[i];
        }
    }

    out
}

pub mod blake3_mac {
    pub fn derive_key(chacha_key: &[u32; 8]) -> [u8; 32] {
        let mut key_bytes = [0u8; 32];
        for (chunk, word) in key_bytes.chunks_exact_mut(4).zip(chacha_key.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }

        let mut out = [0u8; 32];
        out.copy_from_slice(blake3::hash(&key_bytes).as_bytes());
        out
    }

    pub fn hash(message: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(blake3::hash(message).as_bytes());
        out
    }

    pub fn keyed_hash(message: &[u8], key: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key);
        hasher.update(message);
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    #[inline]
    pub fn keyed_hash_nonce_ct(
        nonce: &[u32; 3],
        ciphertext: &[u8],
        key: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(key);
        for w in nonce {
            hasher.update(&w.to_le_bytes());
        }
        hasher.update(ciphertext);
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        out
    }

    pub fn verify(
        message: &[u8],
        expected_tag: &[u8; 32],
        key: Option<&[u8; 32]>,
    ) -> bool {
        let computed_tag = match key {
            Some(k) => keyed_hash(message, k),
            None => hash(message),
        };
        ct_eq_32(&computed_tag, expected_tag)
    }

    #[inline]
    pub fn verify_nonce_ct(
        nonce: &[u32; 3],
        ciphertext: &[u8],
        expected_tag: &[u8; 32],
        key: &[u8; 32],
    ) -> bool {
        let computed = keyed_hash_nonce_ct(nonce, ciphertext, key);
        ct_eq_32(&computed, expected_tag)
    }

    #[inline]
    pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= a[i] ^ b[i];
        }
        diff == 0
    }
}

pub mod macros {
    use crate::blake3_mac;
    use crate::chacha20_encrypt;
    use crate::Chacha20Blake3Payload;
    use crate::Session20b3;
    use rand::Rng;

    fn random_nonce() -> ([u32; 3], [u8; 12]) {
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce_bytes);

        let mut nonce = [0u32; 3];
        for (i, chunk) in nonce_bytes.chunks_exact(4).enumerate() {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            nonce[i] = u32::from_le_bytes(b);
        }

        (nonce, nonce_bytes)
    }

    fn seal(info: &Session20b3, plaintext: &[u8]) -> Vec<u8> {
        let (nonce, _) = random_nonce();
        let ciphertext = chacha20_encrypt(info, plaintext);
        let mac_key = blake3_mac::derive_key(&info.key);
        let tag = blake3_mac::keyed_hash_nonce_ct(&nonce, &ciphertext, &mac_key);

        let mut out = Vec::with_capacity(ciphertext.len() + 32 + 12);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag);
        for w in nonce.iter() {
            out.extend_from_slice(&w.to_le_bytes());
        }

        out
    }

    fn open(info: &Session20b3, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 32 + 12 {
            return None;
        }

        let (ct_and_tag, nonce_bytes) = payload.split_at(payload.len() - 12);
        let (ct, tag_bytes) = ct_and_tag.split_at(ct_and_tag.len() - 32);

        let mut tag = [0u8; 32];
        tag.copy_from_slice(tag_bytes);

        let mut nonce = [0u32; 3];
        for (i, chunk) in nonce_bytes.chunks_exact(4).enumerate() {
            let mut b = [0u8; 4];
            b.copy_from_slice(chunk);
            nonce[i] = u32::from_le_bytes(b);
        }

        let mac_key = blake3_mac::derive_key(&info.key);
        if !blake3_mac::verify_nonce_ct(&nonce, ct, &tag, &mac_key) {
            return None;
        }

        let decryption_info = Session20b3 {
            key: info.key,
            nonce,
            counter: info.counter,
        };

        Some(chacha20_encrypt(&decryption_info, ct))
    }

    pub fn encrypt_string(info: &Session20b3, plaintext: String) -> Vec<u8> {
        seal(info, plaintext.as_bytes())
    }

    pub fn encrypt_str(info: &Session20b3, plaintext: &str) -> Vec<u8> {
        seal(info, plaintext.as_bytes())
    }

    pub fn decrypt_string(info: &Session20b3, ciphertext: Vec<u8>) -> String {
        match open(info, &ciphertext) {
            Some(plain) => String::from_utf8_lossy(&plain).into_owned(),
            None => String::new(),
        }
    }

    pub fn decrypt_string_blake3(
        info: &Session20b3,
        payload: Chacha20Blake3Payload,
        strict: Option<bool>,
    ) -> String {
        let strict_mode = strict.unwrap_or(false);
        let mac_key = blake3_mac::derive_key(&info.key);

        if blake3_mac::verify_nonce_ct(
            &info.nonce,
            &payload.ciphertext,
            &payload.tag,
            &mac_key,
        ) {
            dbg!(3, "Authentication successful");
        } else {
            dbg!(2, "Authentication failed");
            if strict_mode {
                return String::new();
            }
        }

        String::from_utf8_lossy(&chacha20_encrypt(&info, &payload.ciphertext)).into_owned()
    }

    pub fn decrypt_str_b3k(
        info: &Session20b3,
        payload: Chacha20Blake3Payload,
        key: &[u8; 32],
        strict: Option<bool>,
    ) -> String {
        let strict_mode = strict.unwrap_or(false);

        if blake3_mac::verify_nonce_ct(&info.nonce, &payload.ciphertext, &payload.tag, key) {
            dbg!(3, "Authentication successful");
        } else {
            dbg!(2, "Authentication failed");
            if strict_mode {
                return String::new();
            }
        }

        String::from_utf8_lossy(&chacha20_encrypt(&info, &payload.ciphertext)).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let information: Session20b3 = Session20b3 {
            key: [
                0x03020100,
                0x07060504,
                0x0b0a0908,
                0x0f0e0d0c,
                0x13121110,
                0x17161514,
                0x1b1a1918,
                0x1f1e1d1c,
            ],
            nonce: [
                0x00000000,
                0x4a000000,
                0x00000000,
            ],
            counter: 0,
        };

        let plaintext: Vec<u8> = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
            .to_vec();

        let (encrypted_text, nonce) = xchacha20_encrypt(&information, &plaintext);

        let blake3_key = blake3_mac::derive_key(&information.key);
        let tag = blake3_mac::keyed_hash_nonce_ct(&nonce, &encrypted_text, &blake3_key);

        dbg!(1, "Blake3 Key: 0x{}", hex::encode(blake3_key));
        dbg!(1, "Tag: 0x{}", hex::encode(tag));

        assert!(blake3_mac::verify_nonce_ct(
            &nonce,
            &encrypted_text,
            &tag,
            &blake3_key
        ));
        assert!(!blake3_mac::verify_nonce_ct(
            &nonce,
            &encrypted_text,
            &tag,
            &[0u8; 32]
        ));

        let payload: Chacha20Blake3Payload = Chacha20Blake3Payload {
            ciphertext: encrypted_text.clone(),
            tag,
        };

        let mut ciphertext = encrypted_text.clone();
        for word in nonce.iter() {
            ciphertext.extend_from_slice(&word.to_le_bytes());
        }
        let roundtrip = xchacha20_decrypt(&information, &ciphertext);
        assert_eq!(
            roundtrip,
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec()
        );

        for (chunk_idx, chunk) in payload.ciphertext.chunks(16).enumerate() {
            print!("{:03}  ", chunk_idx * 16);
            for byte in chunk {
                print!("{:02x} ", byte);
            }
            for _ in chunk.len()..16 {
                print!("   ");
            }
            print!(" ");
            for byte in chunk {
                let c = if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                };
                print!("{c}");
            }
            println!();
        }

        let verif_context: &str = "SecureCommunicationProtocol 04-08-2026 00:00:00 Verification";

        let (key, seed) = crypto::get_key(verif_context);
        let mac1 = blake3::keyed_hash(&key, b"example input");
        dbg!(1, "{:?} - {:?}", mac1, seed);
    }

    #[test]
    fn speed_test() {
        use super::*;
        use std::time::Instant;

        let information = Session20b3 {
            key: [
                0x03020100,
                0x07060504,
                0x0b0a0908,
                0x0f0e0d0c,
                0x13121110,
                0x17161514,
                0x1b1a1918,
                0x1f1e1d1c,
            ],
            nonce: [0, 0x4a000000, 0],
            counter: 0,
        };

        let plaintext = vec![0xABu8; 255 * 1024 * 1024];

        let start = Instant::now();
        let (ciphertext, nonce) = xchacha20_encrypt(&information, &plaintext);
        let encrypt_elapsed = start.elapsed();

        let blake3_key = blake3_mac::derive_key(&information.key);

        let start = Instant::now();
        let tag = blake3_mac::keyed_hash_nonce_ct(&nonce, &ciphertext, &blake3_key);
        let tag_elapsed = start.elapsed();

        let start = Instant::now();
        let ok = blake3_mac::verify_nonce_ct(&nonce, &ciphertext, &tag, &blake3_key);
        let verify_elapsed = start.elapsed();
        assert!(ok);

        let mut to_decrypt = ciphertext.clone();
        for w in nonce.iter() {
            to_decrypt.extend_from_slice(&w.to_le_bytes());
        }

        let start = Instant::now();
        let decrypted = xchacha20_decrypt(&information, &to_decrypt);
        let decrypt_elapsed = start.elapsed();
        assert_eq!(decrypted, plaintext);

        let mb = 255.0;
        let start = Instant::now();
        let _ = chacha20_block(&information, 0);
        let single_block = start.elapsed();

        dbg!(1, "--- SPEED TEST ({} MiB) ---", mb);
        dbg!(2, "encrypt : {:?}  ({:.2} MiB/s)", encrypt_elapsed, mb / encrypt_elapsed.as_secs_f64());
        dbg!(3, "decrypt : {:?}  ({:.2} MiB/s)", decrypt_elapsed, mb / decrypt_elapsed.as_secs_f64());
        dbg!(4, "blake3  : {:?}  ({:.2} MiB/s)", tag_elapsed, mb / tag_elapsed.as_secs_f64());
        dbg!(5, "verify  : {:?}  ({:.2} MiB/s)", verify_elapsed, mb / verify_elapsed.as_secs_f64());
        dbg!(6, "1 block : {:?}", single_block);
    }
}