//! Flat facade over the workspace crates used by the binaries.

pub use shinu_core::{
    DEFAULT_ROOT, Error, FC_SNAPSHOT_VERSION, FC_URL, FC_VERSION, GUEST_BLOCKED_CIDRS, Image,
    KERNEL_URL, MAX_UPLOAD_BYTES, Result, USAGE_SAMPLE_SECS, VSOCK_SSH_PORT, VSOCK_VNC_PORT,
    assets_dir, avail_bytes, base_path, btrfs, cache_dir, chown_tree, ckpt_image, ckpt_mem,
    ckpt_state, env_u32, firecracker_bin, init_daemon_layout, init_layout,
    is_blocked_guest_destination, is_rfc1918, jailer_bin, kernel_path, migrate_base, parse_ipv4,
    parse_ipv4_cidr, parse_net_base, resolve_root, shell_quote, shell_quote_word, space_image,
    vm_dir, vsock_helper,
};

// Keep the hash implementation private; expose only helpers used by callers.
pub use shinu_crypto::{auth, sha256_hex, token};

pub use shinu_store::{
    find, find_ckpt, is_referenced, log_chain, quota, reflog_entries, registry, state,
};

pub use shinu_image::{BaseConfig, ensure_assets, ensure_base, repair_base_resolv};

pub use shinu_proto::{http, proto};

pub use shinu_vm::{
    NetConfig, NetSpec, VmConfig, exec_in_vm, net_slot, net_spec, parse_net_allow, tap_name, vm,
    vm_config_json,
};
/// Connect to a Firecracker vsock UDS and consume only its handshake line.
///
/// The reply is read one byte at a time because buffering can consume the
/// first payload bytes that follow the newline.
pub fn vsock_connect(uds: &std::path::Path, port: u16) -> Result<std::os::unix::net::UnixStream> {
    use std::io::{Read, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(uds)?;
    writeln!(stream, "CONNECT {port}")?;
    stream.flush()?;

    let mut reply = [0u8; 64];
    let mut reply_len = 0;
    let mut byte = [0u8; 1];
    loop {
        if reply_len >= reply.len() {
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
            Ok(_) => {
                reply[reply_len] = byte[0];
                reply_len += 1;
            }
            Err(error) => return Err(error.into()),
        }
    }
    if !reply[..reply_len].starts_with(b"OK ") {
        return Err(Error::Invalid(format!(
            "vsock connect refused for {} port {port}: {}",
            uds.display(),
            String::from_utf8_lossy(&reply[..reply_len]).trim()
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
