use std::fmt::Display;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;
use std::thread;

const BUFFER_SIZE: usize = 64 * 1024;

fn usage() -> ! {
    eprintln!("usage: shinu-vsock <uds_path> <port>");
    process::exit(2);
}

fn fail(error: impl Display) -> ! {
    eprintln!("shinu-vsock: {error}");
    process::exit(1);
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let uds = args.next().map(PathBuf::from).unwrap_or_else(|| usage());
    let port = args
        .next()
        .and_then(|arg| arg.to_str().and_then(|value| value.parse::<u16>().ok()))
        .unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    let mut stream = shinu::vsock_connect(&uds, port).unwrap_or_else(|error| fail(error));

    let mut to_socket = stream.try_clone().unwrap_or_else(|error| fail(error));
    // Do not half-close stdin: Firecracker's vsock multiplexer tears down both
    // directions. SSH carries end-of-input in its protocol, and ignoring copy
    // errors keeps unread guest output from being truncated.
    let _stdin_thread = thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; BUFFER_SIZE];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_socket.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
    });

    // Flush each chunk: stdout is a LineWriter and encrypted SSH traffic can
    // lack newlines long enough for buffering to deadlock key exchange.
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                stdout
                    .write_all(&buf[..n])
                    .unwrap_or_else(|error| fail(error));
                stdout.flush().unwrap_or_else(|error| fail(error));
            }
            Err(error) => fail(error),
        }
    }
}
