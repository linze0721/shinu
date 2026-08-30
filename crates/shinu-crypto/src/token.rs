//! Project bearer-token persistence and authentication.
//!
//! Only SHA-256 hashes are stored in `<root>/tokens.json`; the plaintext token
//! exists only in the value returned by [`mint`]. Hashes are compared in fixed
//! time so a caller cannot use response timing to learn a stored token.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use shinu_core::{Error, Result};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::sha2::sha256_hex;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub hash: String,
    pub project: String,
    pub created_at: DateTime<Utc>,
}

pub fn load(root: &Path) -> Result<Vec<Token>> {
    let path = root.join("tokens.json");
    match std::fs::read_to_string(path) {
        Ok(contents) => Ok(serde_json::from_str(&contents)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

pub fn store(root: &Path, tokens: &[Token]) -> Result<()> {
    let contents = serde_json::to_string_pretty(tokens)?;
    let tmp = root.join("tokens.json.tmp");
    // Set the restrictive mode on creation and normalize stale temporary
    // files before writing hashes.

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(contents.as_bytes())?;
    }
    std::fs::rename(tmp, root.join("tokens.json"))?;
    Ok(())
}

pub fn mint() -> Result<String> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        token.push(HEX[(byte >> 4) as usize] as char);
        token.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(token)
}

pub fn hash(plain: &str) -> String {
    sha256_hex(plain.as_bytes())
}

pub(super) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    // Visit at least the width of a SHA-256 hex digest and inspect every
    // byte even when an earlier byte differs.
    for index in 0..left.len().max(right.len()).max(64) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(a ^ b);
    }
    difference == 0
}

pub fn authenticate(tokens: &[Token], plain: &str) -> Result<String> {
    let digest = hash(plain);
    for token in tokens {
        if constant_time_eq(digest.as_bytes(), token.hash.as_bytes()) {
            return Ok(token.project.clone());
        }
    }
    Err(Error::Auth("invalid token".into()))
}

#[cfg(test)]
mod token_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn test_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("shinu-token-{label}-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create token test root");
        root
    }

    #[test]
    fn mint_returns_distinct_lowercase_hex_tokens() {
        let first = mint().expect("mint first token");
        let second = mint().expect("mint second token");
        assert_eq!(first.len(), 64);
        assert_eq!(second.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert!(
            second
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_ne!(first, second);
    }

    #[test]
    fn hash_is_stable_and_input_sensitive() {
        assert_eq!(hash("stable"), hash("stable"));
        assert_ne!(hash("stable"), hash("different"));
    }

    #[test]
    fn authenticate_returns_matching_project() {
        let plain = "token-for-web";
        let tokens = vec![Token {
            hash: hash(plain),
            project: "web".into(),
            created_at: Utc::now(),
        }];
        assert_eq!(authenticate(&tokens, plain).expect("authenticate"), "web");
    }

    #[test]
    fn authenticate_rejects_unknown_token() {
        let tokens = vec![Token {
            hash: hash("known"),
            project: "web".into(),
            created_at: Utc::now(),
        }];
        assert!(matches!(
            authenticate(&tokens, "unknown"),
            Err(Error::Auth(message)) if message == "invalid token"
        ));
    }

    #[test]
    fn store_and_load_round_trip_tokens() {
        let root = test_root("round-trip");
        let tokens = vec![Token {
            hash: hash("round-trip-token"),
            project: "project-a".into(),
            created_at: Utc::now(),
        }];
        let tmp = root.join("tokens.json.tmp");
        std::fs::write(&tmp, b"stale").expect("seed token temp file");
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644))
            .expect("set permissive temp mode");
        store(&root, &tokens).expect("store tokens");
        let loaded = load(&root).expect("load tokens");
        assert_eq!(loaded, tokens);
        let mode = std::fs::metadata(root.join("tokens.json"))
            .expect("token metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_dir_all(root).expect("remove token test root");
    }

    #[test]
    fn constant_time_eq_rejects_shared_prefix_beyond_64_bytes() {
        let left = "a".repeat(64) + &"b".repeat(64);
        let right = "a".repeat(64) + &"c".repeat(64);
        assert_eq!(left.len(), 128);
        assert_eq!(right.len(), 128);
        assert_ne!(&left[64..], &right[64..]);
        assert!(!constant_time_eq(left.as_bytes(), right.as_bytes()));
    }
}
