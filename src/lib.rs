//! Facade over the workspace crates.
//!
//! The binaries were written against a single `shinu::` namespace, and the
//! split is meant to change how the code is organised rather than how it is
//! called. Re-exporting here keeps every existing call site valid, so the
//! restructuring can be reviewed as a move rather than as a rewrite of four
//! binaries at the same time.

pub use shinu_core::{
    btrfs, ckpt_image, ckpt_mem, ckpt_state, DEFAULT_ROOT, Error, FC_URL, FC_VERSION,
    GUEST_BLOCKED_CIDRS, Image, KERNEL_URL, MAX_UPLOAD_BYTES, Result, USAGE_SAMPLE_SECS,
    VSOCK_SSH_PORT, VSOCK_VNC_PORT, assets_dir, avail_bytes, base_path, cache_dir, chown_tree,
    env_u32, firecracker_bin, init_layout, is_blocked_guest_destination, is_rfc1918, jailer_bin,
    kernel_path, migrate_base, parse_ipv4, parse_ipv4_cidr, parse_net_base, resolve_root,
    shell_quote, shell_quote_word, space_image, vm_dir, vsock_helper,
};

// sha2 itself stays private to shinu-crypto, as it was private here; only the
// one hashing helper the daemon calls is surfaced.
pub use shinu_crypto::{auth, sha256_hex, token};

pub use shinu_store::{
    find, find_ckpt, is_referenced, log_chain, quota, reflog_entries, registry, state,
};

pub use shinu_image::{BaseConfig, ensure_assets, ensure_base, repair_base_resolv};

pub use shinu_proto::{http, proto};

pub use shinu_vm::{NetConfig, NetSpec, VmConfig, exec_in_vm, net_spec, tap_name, vm};
pub use shinu_vm::{net_slot, parse_net_allow, vm_config_json};
/// Connect to a Firecracker vsock UDS and consume only its handshake line.
///
/// The reply is read one byte at a time because buffering can consume the
/// first payload bytes that follow the newline.
pub fn vsock_connect(
    uds: &std::path::Path,
    port: u16,
) -> Result<std::os::unix::net::UnixStream> {
    use std::io::{Read, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(uds)?;
    let request = format!("CONNECT {port}\n");
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut reply = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if reply.len() >= 64 {
            return Err(Error::Invalid(format!(
                "vsock connect refused for {} port {port}: handshake too long",
                uds.display()
            )));
        }
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(Error::Invalid(format!(
                    "vsock connect refused for {} port {port}: EOF during handshake",
                    uds.display()
                )));
            }
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => reply.push(byte[0]),
            Err(error) => return Err(error.into()),
        }
    }
    if !reply.starts_with(b"OK ") {
        return Err(Error::Invalid(format!(
            "vsock connect refused for {} port {port}: {}",
            uds.display(),
            String::from_utf8_lossy(&reply).trim()
        )));
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::vsock_connect;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;
    use uuid::Uuid;

    #[test]
    fn vsock_handshake_leaves_payload_for_caller() {
        let path = std::env::temp_dir().join(format!("shinu-vsock-{}", Uuid::new_v4()));
        let listener = UnixListener::bind(&path).expect("bind test vsock");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept test vsock");
            let mut request = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut request)
                .expect("read connect request");
            assert_eq!(request, "CONNECT 2223\n");
            stream
                .write_all(b"OK 1\nRFB 003.008\n")
                .expect("write test payload");
        });
        let mut stream = vsock_connect(&path, 2223).expect("connect test vsock");
        let mut payload = [0u8; 12];
        stream
            .read_exact(&mut payload)
            .expect("read payload after handshake");
        assert_eq!(&payload, b"RFB 003.008\n");
        server.join().expect("join test vsock");
        std::fs::remove_file(path).expect("remove test vsock");
    }
}
