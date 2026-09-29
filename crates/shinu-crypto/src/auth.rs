//! Password hashing and browser-session token generation for console users.

use crate::sha2::{Sha256State, sha256_bytes};
use crate::token::{constant_time_eq, mint};
use shinu_core::Result;
use std::fmt::Write as _;
use std::io::Read;

const PASSWORD_ITERATIONS: u32 = 210_000;
const PASSWORD_SALT_BYTES: usize = 32;
const PASSWORD_HASH_BYTES: usize = 32;

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn append_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = value.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        decoded[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Some(decoded)
}

struct HmacSha256 {
    inner: Sha256State,
    outer: Sha256State,
}

impl HmacSha256 {
    fn new(key: &[u8]) -> Self {
        let mut key_block = [0_u8; 64];
        if key.len() > key_block.len() {
            key_block[..32].copy_from_slice(&sha256_bytes(key));
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }

        let mut inner_pad = [0x36_u8; 64];
        let mut outer_pad = [0x5c_u8; 64];
        for index in 0..key_block.len() {
            inner_pad[index] ^= key_block[index];
            outer_pad[index] ^= key_block[index];
        }

        let mut inner = Sha256State::new();
        inner.update(&inner_pad);
        let mut outer = Sha256State::new();
        outer.update(&outer_pad);
        Self { inner, outer }
    }

    fn digest(&self, message: &[u8]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        inner.update(message);
        self.finish_inner(inner)
    }

    fn digest_parts(&self, first: &[u8], second: &[u8]) -> [u8; 32] {
        let mut inner = self.inner.clone();
        inner.update(first);
        inner.update(second);
        self.finish_inner(inner)
    }

    fn finish_inner(&self, inner: Sha256State) -> [u8; 32] {
        let inner_hash = inner.finish();
        let mut outer = self.outer.clone();
        outer.update(&inner_hash);
        outer.finish()
    }
}

fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    if iterations == 0 || out.is_empty() {
        return;
    }
    let block_count = out.len() / 32 + usize::from(!out.len().is_multiple_of(32));
    assert!(u32::try_from(block_count).is_ok());
    let hmac = HmacSha256::new(password);
    for block_index in 1..=block_count {
        let block_number = u32::try_from(block_index)
            .expect("PBKDF2 block index fits in a 32-bit block number")
            .to_be_bytes();
        let mut u = hmac.digest_parts(salt, &block_number);
        let mut block = u;

        for _ in 1..iterations {
            u = hmac.digest(&u);
            for (accumulator, next) in block.iter_mut().zip(u) {
                *accumulator ^= next;
            }
        }

        let offset = (block_index - 1) * 32;
        let length = (out.len() - offset).min(32);
        out[offset..offset + length].copy_from_slice(&block[..length]);
    }
}
/// Hashes a password with a self-describing PBKDF2-HMAC-SHA256 record.
pub fn hash_password(plain: &str) -> Result<String> {
    let mut salt = [0_u8; PASSWORD_SALT_BYTES];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut salt)?;
    let mut derived = [0_u8; PASSWORD_HASH_BYTES];
    pbkdf2_sha256(plain.as_bytes(), &salt, PASSWORD_ITERATIONS, &mut derived);
    let mut record = String::with_capacity(
        "pbkdf2$".len() + 10 + 1 + PASSWORD_SALT_BYTES * 2 + 1 + PASSWORD_HASH_BYTES * 2,
    );
    let _ = write!(record, "pbkdf2${PASSWORD_ITERATIONS}$");
    append_hex(&mut record, &salt);
    record.push('$');
    append_hex(&mut record, &derived);
    Ok(record)
}

/// Verifies a password using the iteration count encoded in its record.
pub fn verify_password(plain: &str, stored: &str) -> bool {
    let mut fields = stored.split('$');
    if fields.next() != Some("pbkdf2") {
        return false;
    }
    let Some(iterations) = fields.next().and_then(|value| value.parse::<u32>().ok()) else {
        return false;
    };
    let Some(salt_hex) = fields.next() else {
        return false;
    };
    let Some(hash_hex) = fields.next() else {
        return false;
    };
    if fields.next().is_some() || iterations == 0 {
        return false;
    }
    let Some(salt) = decode_hex::<PASSWORD_SALT_BYTES>(salt_hex) else {
        return false;
    };
    let Some(expected) = decode_hex::<PASSWORD_HASH_BYTES>(hash_hex) else {
        return false;
    };

    let mut derived = [0_u8; PASSWORD_HASH_BYTES];
    pbkdf2_sha256(plain.as_bytes(), &salt, iterations, &mut derived);
    constant_time_eq(&derived, &expected)
}

/// Creates a cryptographically random value for a browser session cookie.
pub fn new_session_token() -> Result<String> {
    // Keep session randomness identical to project-token randomness: both
    // are 256-bit values read directly from the kernel CSPRNG.
    mint()
}

#[cfg(test)]
mod auth_tests {
    use super::{
        HmacSha256, PASSWORD_HASH_BYTES, PASSWORD_ITERATIONS, PASSWORD_SALT_BYTES, hash_password,
        new_session_token, pbkdf2_sha256, verify_password,
    };
    use std::fmt::Write as _;

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for &byte in bytes {
            let _ = write!(&mut output, "{byte:02x}");
        }
        output
    }

    #[test]
    fn hmac_matches_rfc_4231_short_key_vector() {
        let key = [0x0b_u8; 20];
        let digest = HmacSha256::new(&key).digest(b"Hi There");
        assert_eq!(
            hex(&digest),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_long_key_vector() {
        let key = [0xaa_u8; 131];
        let digest =
            HmacSha256::new(&key).digest(b"Test Using Larger Than Block-Size Key - Hash Key First");
        assert_eq!(
            hex(&digest),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn pbkdf2_matches_sha256_vector_and_is_input_sensitive() {
        let mut expected = [0_u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut expected);
        assert_eq!(
            hex(&expected),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );

        let mut same = [0_u8; 32];
        pbkdf2_sha256(b"password", b"salt", 1, &mut same);
        assert_eq!(expected, same);
        let mut other_salt = [0_u8; 32];
        pbkdf2_sha256(b"password", b"salt2", 1, &mut other_salt);
        assert_ne!(expected, other_salt);
        let mut other_iterations = [0_u8; 32];
        pbkdf2_sha256(b"password", b"salt", 2, &mut other_iterations);
        assert_ne!(expected, other_iterations);
    }

    #[test]
    fn verification_uses_the_recorded_iteration_count() {
        let salt = [0x42_u8; PASSWORD_SALT_BYTES];
        let mut derived = [0_u8; PASSWORD_HASH_BYTES];
        pbkdf2_sha256(b"recorded iterations", &salt, 1, &mut derived);
        let stored = format!("pbkdf2$1${}${}", hex(&salt), hex(&derived));
        assert!(verify_password("recorded iterations", &stored));
    }

    #[test]
    fn password_records_round_trip_and_reject_tampering() {
        let stored = hash_password("correct horse battery staple").expect("hash password");
        assert!(verify_password("correct horse battery staple", &stored));
        assert!(!verify_password("wrong password", &stored));

        let mut tampered = stored;
        let index = tampered.rfind('$').expect("hash separator") + 1;
        let replacement = if tampered.as_bytes()[index] == b'0' {
            '1'
        } else {
            '0'
        };
        tampered.replace_range(index..=index, &replacement.to_string());
        assert!(!verify_password("correct horse battery staple", &tampered));
    }

    #[test]
    fn malformed_password_records_return_false() {
        for stored in [
            "",
            "sha256$210000$00$00",
            "pbkdf2$0$00$00",
            "pbkdf2$not-a-number$00$00",
            "pbkdf2$1$not-hex$00",
            "pbkdf2$1$00$00",
            "pbkdf2$1$0000000000000000000000000000000000000000000000000000000000000000$xyz",
            "pbkdf2$1$0000000000000000000000000000000000000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000$extra",
        ] {
            assert!(!verify_password("anything", stored), "accepted {stored:?}");
        }
    }

    #[test]
    fn session_tokens_are_random_hex_values() {
        let first = new_session_token().expect("first session token");
        let second = new_session_token().expect("second session token");
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    /// The cost parameter is the security property; wall-clock duration is
    /// not, and asserting on it made this test fail on slower CI runners
    /// while a debug build already spends ~1s here. Pin the iteration count
    /// that is actually recorded, so lowering it cannot pass unnoticed.
    #[test]
    fn password_records_pin_the_owasp_iteration_count() {
        let stored = hash_password("performance password").expect("hash password");
        assert_eq!(PASSWORD_ITERATIONS, 210_000);
        assert!(stored.starts_with(&format!("pbkdf2${PASSWORD_ITERATIONS}$")));
        assert!(verify_password("performance password", &stored));
    }
}
