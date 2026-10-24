# Chacha20-Blake3 in Rust
[<img src="https://badges.ws/badge/Built_with_Rust-000000?logo=rust" alt="Built with Rust" />](https://www.rust-lang.org)
[<img src="https://badges.ws/maintenance/yes/2026" alt="Maintained in 2026" />](https://github.com/vladkens/badges)
<picture><img src="https://badges.ws/handmade" alt="Handmade badge preset" /></picture>

Chacha20 with Blake3 verification made in rust based off the [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439.html) with the Blake3 tweak. Translation was originally made out of a Chacha20-Poly1305 implementation in C.
# examples
It is possible to test this implementation with the ```FileEncrypt``` example
```bash
cargo build --example FileEncrypt --release
./target/release/examples/FileEncrypt
```
### example encryption
```
./target/release/examples/FileEncrypt encrypt test.txt test.locked key.bin 
[+] Starting file encryption...
[?] File size: 29 bytes
[+] Loading existing key from: key.bin
[+] Encrypting data...
[+] Serializing encrypted data...
[+] Encryption completed in 149.759µs
[?] Original size: 29 bytes
[?] Encrypted size: 29 bytes
[?] Total file size: 90 bytes
[?] Serialization overhead: 61 bytes
[+] Output file: test.locked
[+] Key file: key.bin
```
```test.locked```
```
00000000  54 61 ef 49 0d ac 0a 60  89 18 02 c4 52 a5 f0 4a  |Ta.I...`....R..J|
00000010  a2 6d a4 71 0b f0 08 ee  57 85 2c 89 fb 5c f8 91  |.m.q....W.,..\..|
00000020  46 6c 03 42 58 82 22 d6  a6 25 48 f0 1d 00 00 00  |Fl.BX."..%H.....|
00000030  00 00 00 00 d3 c1 36 80  82 8b be a9 40 53 b3 04  |......6.....@S..|
00000040  2f fb 5e 49 61 fc 1b 84  dd 08 ed 96 49 bc d1 42  |/.^Ia.......I..B|
00000050  90 01 02 af dc 6a 00 00  00 00                    |.....j....|
0000005a
```
### example decryption
```
./target/release/examples/FileEncrypt decrypt test.locked test.decr key.bin 
[+] Starting file decryption...
[+] Deserializing encrypted data...
[?] File version: 1
[?] Created at: 1792847618
[?] Encrypted data size: 29 bytes
[+] Loading key from: key.bin
[?] Key version: 1
[+] Verifying authentication...
[+] Authentication successful!
[+] Decrypting data...
[+] Decryption completed in 80.406µs
[?] Decrypted size: 29 bytes
[+] Output file: test.decr
```
```test.decr```
```
00000000  68 65 79 20 74 68 69 73  20 69 73 20 61 6e 20 65  |hey this is an e|
00000010  63 72 79 70 74 65 64 20  74 65 78 74 0a           |crypted text.|
0000001d
```
