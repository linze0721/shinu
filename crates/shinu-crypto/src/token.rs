//! Project bearer-token persistence and authentication.
//!
//! Only SHA-256 hashes are stored in `<root>/tokens.json`; the plaintext token
//! exists only in the value returned by [`mint`]. Hashes are compared in fixed
//! time so a caller cannot use response timing to learn a stored token.
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use shinu_core::{Error, Result};
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
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
        std::fs::write(&tmp, contents)?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(tmp, root.join("tokens.json"))?;
        Ok(())
    }

    pub fn mint() -> Result<String> {
        let mut bytes = [0_u8; 32];
        std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let mut token = String::with_capacity(64);
        for byte in bytes {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            token.push(HEX[(byte >> 4) as usize] as char);
            token.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Ok(token)
    }


    pub fn hash(plain: &str) -> String {
        // Token values are short and hashed for every request, so pure Rust
        // avoids forking a process on each authentication attempt. The
        // one-shot shell call in `sha256_file` below intentionally remains for
        // streaming multi-gigabyte downloads without buffering them in memory.
        sha256_hex(plain.as_bytes())
    }

    pub(super) fn constant_time_eq(left: &str, right: &str) -> bool {
        let left = left.as_bytes();
        let right = right.as_bytes();
        let mut difference = left.len() ^ right.len();
        for index in 0..64 {
            let a = left.get(index).copied().unwrap_or(0);
            let b = right.get(index).copied().unwrap_or(0);
            difference |= usize::from(a ^ b);
        }
        difference == 0
    }

    pub fn authenticate(tokens: &[Token], plain: &str) -> Result<String> {
        let digest = hash(plain);
        for token in tokens {
            // `==` can stop at the first differing byte and expose hash
            // prefixes through timing; the fixed-length XOR comparison does
            // all 64 byte comparisons before checking the accumulated result.
            if constant_time_eq(&digest, &token.hash) {
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
            assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
            assert!(second.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
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
    }
