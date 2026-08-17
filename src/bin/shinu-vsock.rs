use std::fmt::Display;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process;
use std::thread;

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
    // No `shutdown(Write)` on stdin EOF, and no exit from this thread.
    //
    // Firecracker's vsock multiplexer has no half-close: shutting one
    // direction down tears the whole connection apart. SSH signals
    // end-of-input inside its own protocol, so the transport never has to
    // carry that signal. Errors are non-fatal for the same reason: when the
    // guest closes first this copy fails with EPIPE while the reverse
    // direction may still hold unread output, and exiting would truncate it.
    let _stdin_thread = thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = [0u8; 65536];
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

    // Explicit read/write/flush rather than `io::copy` into `io::stdout()`.
    //
    // `io::stdout()` is a `LineWriter`: it holds bytes until it sees a newline.
    // SSH's post-handshake traffic is encrypted binary that can contain no
    // newline for an entire session, so the reply to the client's very first
    // encrypted packet stayed in this buffer and both ends waited on each
    // other forever — key exchange completed, then the session hung (measured
    // on this host). Flushing every chunk is what makes the stream a stream.
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 65536];
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
