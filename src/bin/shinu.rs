use chrono::Utc;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use shinu::token::{self, Token};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process;
use std::sync::{atomic::{AtomicBool, Ordering}, Arc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:7878";

#[derive(Parser)]
#[command(name = "shinu")]
struct Cli {
    #[arg(long, global = true)]
    root: Option<PathBuf>,
    #[arg(long, global = true)]
    endpoint: Option<String>,
    #[arg(long, global = true)]
    token: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    New {
        name: String,
        #[arg(long)]
        image: Option<String>,
        #[arg(long)]
        vcpus: Option<u32>,
        #[arg(long, value_name = "MIB")]
        mem: Option<u32>,
        #[arg(long, value_name = "MIB")]
        disk: Option<u64>,
    },
    #[command(group(
        clap::ArgGroup::new("resize-options")
            .required(true)
            .multiple(true)
            .args(["vcpus", "mem", "disk"])
    ))]
    Resize {
        space: String,
        #[arg(long)]
        vcpus: Option<u32>,
        #[arg(long, value_name = "MIB")]
        mem: Option<u32>,
        #[arg(long, value_name = "MIB")]
        disk: Option<u64>,
    },
    Images,
    Ls {
        #[arg(long)]
        json: bool,
    },
    Rm {
        space: String,
    },
    Start {
        space: String,
    },
    Stop {
        space: String,
    },
    Desktop {
        space: String,
    },
    Vnc {
        space: String,
        #[arg(long, default_value_t = 5901)]
        port: u16,
    },
    Exec {
        space: String,
        #[arg(long, value_name = "FILE")]
        stdin: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    Push {
        space: String,
        local_file: String,
        guest_path: String,
    },
    Pull {
        space: String,
        guest_path: String,
        local_file: String,
    },
    Commit {
        space: String,
        #[arg(long)]
        note: String,
        #[arg(long)]
        hot: bool,
        #[arg(long)]
        full: bool,
    },
    Log {
        space: String,
        #[arg(long)]
        json: bool,
    },
    Reflog {
        space: String,
        #[arg(long)]
        json: bool,
    },
    Checkout {
        space: String,
        commit: Uuid,
    },
    Fork {
        commit: Uuid,
        name: String,
    },
    #[command(name = "rmckpt")]
    RmCkpt {
        commit: Uuid,
    },
    Gc {
        #[arg(long)]
        free_below: u64,
        #[arg(long)]
        dry_run: bool,
    },
    Usage {
        #[arg(long)]
        from: Option<i64>,
        #[arg(long)]
        to: Option<i64>,
        #[arg(long)]
        json: bool,
    },
    Limits {
        #[arg(long)]
        json: bool,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand)]
enum TokenCommand {
    New {
        #[arg(long)]
        project: String,
    },
    Ls,
    Rm {
        #[arg(name = "hash-prefix")]
        hash_prefix: String,
    },
}

#[derive(Clone)]
struct Endpoint {
    host: String,
    authority: String,
    port: u16,
    base_path: String,
}

impl Endpoint {
    fn parse(input: &str) -> Result<Self, String> {
        let input = input.trim();
        if input.is_empty() {
            return Err("endpoint must not be empty".to_string());
        }
        let remainder = if let Some(value) = input.strip_prefix("http://") {
            value
        } else if input.starts_with("https://") {
            return Err("HTTPS endpoints are not supported; use an http:// endpoint".to_string());
        } else if input.contains("://") {
            return Err("endpoint must use the http:// scheme".to_string());
        } else {
            input
        };
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        if authority.is_empty()
            || authority
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        {
            return Err("endpoint must contain a valid host".to_string());
        }

        let (host, port) = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .ok_or_else(|| "IPv6 endpoint is missing the closing ']'".to_string())?;
            let host = &authority[1..end];
            if host.is_empty() {
                return Err("endpoint host must not be empty".to_string());
            }
            let suffix = &authority[end + 1..];
            let port = if suffix.is_empty() {
                80
            } else {
                let port = suffix
                    .strip_prefix(':')
                    .ok_or_else(|| "invalid endpoint port".to_string())?;
                parse_port(port)?
            };
            (host.to_string(), port)
        } else if authority.matches(':').count() > 1 {
            return Err("IPv6 endpoints must use bracket notation, for example http://[::1]:7878".to_string());
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.is_empty() {
                return Err("endpoint host must not be empty".to_string());
            }
            (host.to_string(), parse_port(port)?)
        } else {
            (authority.to_string(), 80)
        };

        let base_path = if path.is_empty() {
            String::new()
        } else {
            format!("/{}", path.trim_matches('/'))
        };
        Ok(Self {
            host,
            authority: authority.to_string(),
            port,
            base_path,
        })
    }

    fn target(&self, path: &str) -> String {
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        if self.base_path.is_empty() {
            path
        } else {
            format!("{}{}", self.base_path, path)
        }
    }

    fn connect_address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn parse_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| format!("invalid endpoint port {value:?}"))?;
    if port == 0 {
        return Err("endpoint port must be between 1 and 65535".to_string());
    }
    Ok(port)
}

#[derive(Clone)]
struct HttpClient {
    endpoint: Endpoint,
    token: String,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

struct ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
}

impl HttpClient {
    fn new(endpoint: Endpoint, token: String) -> Result<Self, String> {
        if token.is_empty() {
            return Err("missing bearer token; create one with `shinu token new --project <id>` and set SHINU_TOKEN or pass --token".to_string());
        }
        if token.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err("token must not contain carriage returns or newlines".to_string());
        }
        Ok(Self { endpoint, token })
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<HttpResponse, String> {
        let body = body
            .map(|value| serde_json::to_vec(&value).map_err(|error| error.to_string()))
            .transpose()?;
        let (mut reader, head) = self.open_request(method, path, body.as_deref())?;
        let response_body = read_body(&mut reader, &head.headers)?;
        Ok(HttpResponse {
            status: head.status,
            body: response_body,
        })
    }

    fn open_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(BufReader<TcpStream>, ResponseHead), String> {
        let content_length = body.map_or(0, |body| body.len() as u64);
        let mut stream = self.start_request(
            method,
            path,
            content_length,
            body.map(|_| "application/json"),
        )?;
        if let Some(body) = body {
            stream.write_all(body).map_err(|error| error.to_string())?;
        }
        stream.flush().map_err(|error| error.to_string())?;
        Self::read_response(stream)
    }

    fn start_request(
        &self,
        method: &str,
        path: &str,
        content_length: u64,
        content_type: Option<&str>,
    ) -> Result<TcpStream, String> {
        let mut stream = TcpStream::connect(self.endpoint.connect_address())
            .map_err(|error| format!("could not connect to {}: {error}", self.endpoint.authority))?;
        let target = self.endpoint.target(path);
        let content_type = content_type
            .map(|value| format!("Content-Type: {value}\r\n"))
            .unwrap_or_default();
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n{content_type}Content-Length: {content_length}\r\n\r\n",
            self.endpoint.authority, self.token
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| error.to_string())?;
        Ok(stream)
    }

    fn read_response(stream: TcpStream) -> Result<(BufReader<TcpStream>, ResponseHead), String> {
        let mut reader = BufReader::new(stream);
        let head = read_response_head(&mut reader)?;
        Ok((reader, head))
    }
    fn open_raw_request(
        &self,
        method: &str,
        path: &str,
    ) -> Result<(TcpStream, ResponseHead), String> {
        let mut stream = self.start_request(method, path, 0, None)?;
        let mut head_bytes = Vec::new();
        let mut byte = [0u8; 1];
        while head_bytes.len() < 64 * 1024 {
            let count = stream.read(&mut byte).map_err(|error| error.to_string())?;
            if count == 0 {
                return Err("HTTP response ended before the VNC headers".to_string());
            }
            head_bytes.push(byte[0]);
            if head_bytes.ends_with(b"\r\n\r\n") {
                let mut cursor = Cursor::new(head_bytes);
                let head = read_response_head(&mut cursor)?;
                return Ok((stream, head));
            }
        }
        Err("HTTP response headers exceed 64 KiB".to_string())
    }

    fn stream_exec(
        &self,
        space: &str,
        command: &[String],
        stdin_path: Option<&str>,
    ) -> Result<i32, String> {
        let mut body = json!({ "cmd": command });
        if let Some(path) = stdin_path {
            body["stdin"] = Value::String(read_exec_stdin(path)?);
        }
        let encoded = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
        let (mut reader, head) = self.open_request(
            "POST",
            &format!("/v1/spaces/{}/exec", encode_path_segment(space)),
            Some(&encoded),
        )?;
        if !(200..300).contains(&head.status) {
            let response_body = read_body(&mut reader, &head.headers)?;
            return Err(http_error(head.status, &response_body));
        }
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        stream_ndjson(
            &mut reader,
            &head.headers,
            &mut stdout,
            &mut stderr,
        )
    }

    fn push_file(&self, space: &str, local_path: &str, guest_path: &str) -> Result<u64, String> {
        let mut source = upload_source(local_path)?;
        let target = format!(
            "/v1/spaces/{}/push?path={}",
            encode_path_segment(space),
            encode_query_value(guest_path)
        );
        let mut stream = self.start_request("POST", &target, source.length, None)?;
        copy_upload(&mut source.file, &mut stream, source.length)?;
        stream.flush().map_err(|error| error.to_string())?;
        let (mut reader, head) = Self::read_response(stream)?;
        let response_body = read_body(&mut reader, &head.headers)?;
        if !(200..300).contains(&head.status) {
            return Err(http_error(head.status, &response_body));
        }
        let response = response_value_from_body(&response_body)?;
        response
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| "push response did not include a byte count".to_string())
    }

    fn pull_file(&self, space: &str, guest_path: &str, local_path: &str) -> Result<u64, String> {
        let target = format!(
            "/v1/spaces/{}/pull?path={}",
            encode_path_segment(space),
            encode_query_value(guest_path)
        );
        let (mut reader, head) = self.open_request("GET", &target, None)?;
        if !(200..300).contains(&head.status) {
            let response_body = read_body(&mut reader, &head.headers)?;
            return Err(http_error(head.status, &response_body));
        }
        if local_path == "-" {
            let stdout = io::stdout();
            let mut output = stdout.lock();
            stream_body(&mut reader, &head.headers, &mut output)
        } else {
            let mut output = File::create(local_path)
                .map_err(|error| format!("could not create {local_path:?}: {error}"))?;
            stream_body(&mut reader, &head.headers, &mut output)
        }
    }
    fn proxy_vnc(&self, space: &str, port: u16) -> Result<i32, String> {
        let listener = TcpListener::bind(("127.0.0.1", port))
            .map_err(|error| format!("could not listen on localhost:{port}: {error}"))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("could not inspect VNC listener address: {error}"))?;
        println!("VNC proxy listening on {address}");
        for incoming in listener.incoming() {
            let local = incoming.map_err(|error| format!("could not accept VNC client: {error}"))?;
            let client = self.clone();
            let space = space.to_owned();
            thread::spawn(move || {
                if let Err(error) = client.proxy_vnc_connection(&space, local) {
                    eprintln!("VNC connection: {error}");
                }
            });
        }
        Ok(0)
    }

    fn proxy_vnc_connection(&self, space: &str, mut local: TcpStream) -> Result<(), String> {
        let path = format!("/v1/spaces/{}/vnc", encode_path_segment(space));
        let (mut remote, head) = self.open_raw_request("GET", &path)?;
        if !(200..300).contains(&head.status) {
            let mut reader = BufReader::new(remote);
            let body = read_body(&mut reader, &head.headers)?;
            return Err(http_error(head.status, &body));
        }

        let mut client_reader = local
            .try_clone()
            .map_err(|error| format!("could not clone VNC client stream: {error}"))?;
        let mut remote_writer = remote
            .try_clone()
            .map_err(|error| format!("could not clone VNC endpoint stream: {error}"))?;
        let stop_client_reader = Arc::new(AtomicBool::new(false));
        let stop_client_reader_thread = Arc::clone(&stop_client_reader);
        let client_thread = thread::spawn(move || {
            // Do not half-close either socket: Firecracker's vsock
            // multiplexer treats that as closing both directions.
            if client_reader
                .set_read_timeout(Some(Duration::from_millis(100)))
                .is_err()
            {
                return;
            }
            let mut buffer = [0u8; 64 * 1024];
            loop {
                match client_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(count) => {
                        if remote_writer.write_all(&buffer[..count]).is_err() {
                            break;
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) => {
                            if stop_client_reader_thread.load(Ordering::Acquire) {
                                break;
                            }
                        }
                    Err(_) => break,
                }
            }
        });

        let mut buffer = [0u8; 64 * 1024];
        loop {
            match remote.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if local.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
            }
        }
        stop_client_reader.store(true, Ordering::Release);
        let _ = client_thread.join();
        Ok(())
    }
}

struct UploadSource {
    file: File,
    length: u64,
    temporary_path: Option<PathBuf>,
}

impl Drop for UploadSource {
    fn drop(&mut self) {
        if let Some(path) = &self.temporary_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn upload_source(path: &str) -> Result<UploadSource, String> {
    if path == "-" {
        // Content-Length is mandatory on push; disk spooling keeps stdin streaming without a memory-sized buffer.
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| format!("could not generate temporary upload name: {error}"))?
            .as_nanos();
        let mut temporary_path = None;
        let mut file = None;
        for attempt in 0..16 {
            let candidate = std::env::temp_dir().join(format!(
                "shinu-push-{}-{timestamp}-{attempt}",
                process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(opened) => {
                    file = Some(opened);
                    temporary_path = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!("could not create temporary upload file: {error}"));
                }
            }
        }
        let mut file = file.ok_or_else(|| "could not create a unique temporary upload file".to_string())?;
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let length = io::copy(&mut input, &mut file)
            .map_err(|error| format!("could not read stdin: {error}"))?;
        file.flush()
            .map_err(|error| format!("could not flush temporary upload file: {error}"))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| format!("could not rewind temporary upload file: {error}"))?;
        return Ok(UploadSource {
            file,
            length,
            temporary_path,
        });
    }

    let file = File::open(path).map_err(|error| format!("could not open {path:?}: {error}"))?;
    let length = file
        .metadata()
        .map_err(|error| format!("could not inspect {path:?}: {error}"))?
        .len();
    Ok(UploadSource {
        file,
        length,
        temporary_path: None,
    })
}

fn copy_upload(source: &mut File, target: &mut TcpStream, length: u64) -> Result<(), String> {
    let mut remaining = length;
    let mut buffer = [0u8; 8192];
    while remaining > 0 {
        let amount = remaining.min(buffer.len() as u64) as usize;
        let count = source
            .read(&mut buffer[..amount])
            .map_err(|error| format!("could not read upload source: {error}"))?;
        if count == 0 {
            return Err("upload source ended before its advertised length".to_string());
        }
        target
            .write_all(&buffer[..count])
            .map_err(|error| format!("could not send upload: {error}"))?;
        remaining -= count as u64;
    }
    Ok(())
}

fn read_exec_stdin(path: &str) -> Result<String, String> {
    if path == "-" {
        let stdin = io::stdin();
        let mut input = stdin.lock();
        let mut content = String::new();
        input
            .read_to_string(&mut content)
            .map_err(|error| format!("could not read stdin: {error}"))?;
        Ok(content)
    } else {
        std::fs::read_to_string(path)
            .map_err(|error| format!("could not read exec stdin file {path:?}: {error}"))
    }
}

fn client_from_options(
    endpoint: Option<String>,
    token: Option<String>,
) -> Result<HttpClient, String> {
    let endpoint = endpoint
        .or_else(|| std::env::var("SHINU_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let token = token
        .or_else(|| std::env::var("SHINU_TOKEN").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "missing bearer token; create one with `shinu token new --project <id>` and set SHINU_TOKEN or pass --token"
                .to_string()
        })?;
    HttpClient::new(Endpoint::parse(&endpoint)?, token)
}

fn run() -> Result<i32, String> {
    let Cli {
        root,
        endpoint,
        token,
        command,
    } = Cli::parse();
    match command {
        Command::Token { command } => run_token(root, command),
        command => {
            let client = client_from_options(endpoint, token)?;
            run_command(&client, command)
        }
    }
}

fn create_space_body(
    name: &str,
    image: Option<String>,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u64>,
) -> Value {
    let mut body = json!({"name": name});
    let object = body
        .as_object_mut()
        .expect("create space body starts as a JSON object");
    if let Some(image) = image {
        object.insert("image".to_string(), Value::String(image));
    }
    if let Some(vcpus) = vcpus {
        object.insert("vcpus".to_string(), Value::from(vcpus));
    }
    if let Some(mem_mib) = mem_mib {
        object.insert("mem_mib".to_string(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = disk_mib {
        object.insert("disk_mib".to_string(), Value::from(disk_mib));
    }
    body
}

fn resize_space_body(
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u64>,
) -> Result<Value, String> {
    if vcpus.is_none() && mem_mib.is_none() && disk_mib.is_none() {
        return Err("resize requires at least one of --vcpus, --mem, or --disk".to_string());
    }
    let mut body = Value::Object(serde_json::Map::new());
    let object = body
        .as_object_mut()
        .expect("resize space body starts as a JSON object");
    if let Some(vcpus) = vcpus {
        object.insert("vcpus".to_string(), Value::from(vcpus));
    }
    if let Some(mem_mib) = mem_mib {
        object.insert("mem_mib".to_string(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = disk_mib {
        object.insert("disk_mib".to_string(), Value::from(disk_mib));
    }
    Ok(body)
}

fn run_command(client: &HttpClient, command: Command) -> Result<i32, String> {
    match command {
        Command::New {
            name,
            image,
            vcpus,
            mem,
            disk,
        } => {
            let data = response_value(client.request(
                "POST",
                "/v1/spaces",
                Some(create_space_body(&name, image, vcpus, mem, disk)),
            )?)?;
            print_space_summary(&data);
        }
        Command::Resize {
            space,
            vcpus,
            mem,
            disk,
        } => {
            let data = response_value(client.request(
                "PATCH",
                &format!("/v1/spaces/{}", encode_path_segment(&space)),
                Some(resize_space_body(vcpus, mem, disk)?),
            )?)?;
            print_space_summary(&data);
        }
        Command::Images => {
            let response = client.request("GET", "/v1/images", None)?;
            let body = successful_body(response)?;
            print_images(&response_value_from_body(&body)?);
        }
        Command::Ls { json } => {
            let response = client.request("GET", "/v1/spaces", None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_spaces(&response_value_from_body(&body)?);
            }
        }
        Command::Rm { space } => {
            let data = response_value(client.request(
                "DELETE",
                &format!("/v1/spaces/{}", encode_path_segment(&space)),
                None,
            )?)?;
            println!("removed {}", field_text(&data, "removed"));
        }
        Command::Start { space } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/spaces/{}/start", encode_path_segment(&space)),
                None,
            )?)?;
            if data.get("booted").and_then(Value::as_bool).unwrap_or(false) {
                println!("started {space}");
            } else {
                println!("running {space}");
            }
        }
        Command::Stop { space } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/spaces/{}/stop", encode_path_segment(&space)),
                None,
            )?)?;
            let stopped = field_text(&data, "stopped");
            let stopped = if stopped == "-" { space } else { stopped };
            if data
                .get("was_running")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                println!("stopped {stopped}");
            } else {
                println!("not running {stopped}");
            }
        }
        Command::Desktop { space } => {
            let command = vec![
                "sh".to_owned(),
                "-c".to_owned(),
                r#"if [ -d /etc/runit ]; then
    ln -sf /etc/sv/shinu-desktop /etc/runit/runsvdir/default/
    ln -sf /etc/sv/shinu-vsock-vnc /etc/runit/runsvdir/default/
    # runsvdir rescans on its own schedule, so the supervise directories a
    # `sv` command talks to do not exist the instant the symlink appears.
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        [ -e /etc/sv/shinu-desktop/supervise/ok ] \
            && [ -e /etc/sv/shinu-vsock-vnc/supervise/ok ] && break
        sleep 1
    done
    sv up shinu-desktop shinu-vsock-vnc
elif command -v systemctl >/dev/null 2>&1; then
    systemctl enable --now shinu-desktop shinu-vsock-vnc
else
    echo "unsupported guest init; expected runit or systemd" >&2
    exit 1
fi"#
                    .to_owned(),
            ];
            let status = client.stream_exec(&space, &command, None)?;
            if status == 0 {
                println!("desktop services enabled and running for {space}");
            }
            return Ok(status);
        }
        Command::Vnc { space, port } => return client.proxy_vnc(&space, port),
        Command::Exec { space, stdin, cmd } => {
            return client.stream_exec(&space, &cmd, stdin.as_deref());
        }
        Command::Push {
            space,
            local_file,
            guest_path,
        } => {
            let bytes = client.push_file(&space, &local_file, &guest_path)?;
            println!("pushed {bytes} bytes to {guest_path}");
        }
        Command::Pull {
            space,
            guest_path,
            local_file,
        } => {
            let bytes = client.pull_file(&space, &guest_path, &local_file)?;
            if local_file == "-" {
                eprintln!("pulled {bytes} bytes");
            } else {
                println!("pulled {bytes} bytes to {local_file}");
            }
         }
        Command::Commit {
            space,
            note,
            hot,
            full,
        } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/spaces/{}/commits", encode_path_segment(&space)),
                Some(json!({ "note": note, "hot": hot, "full": full })),
            )?)?;
            println!("{}  {}", short_id_value(data.get("id")), field_text(&data, "note"));
        }
        Command::Log { space, json } => {
            let response = client.request(
                "GET",
                &format!("/v1/spaces/{}/log", encode_path_segment(&space)),
                None,
            )?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_log(&response_value_from_body(&body)?);
            }
        }
        Command::Reflog { space, json } => {
            let response = client.request(
                "GET",
                &format!("/v1/spaces/{}/reflog", encode_path_segment(&space)),
                None,
            )?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_reflog(&response_value_from_body(&body)?);
            }
        }
        Command::Checkout { space, commit } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/spaces/{}/checkout", encode_path_segment(&space)),
                Some(json!({ "commit": commit.to_string() })),
            )?)?;
            println!(
                "checked out {} (auto commit {})",
                short_id_value(data.get("head")),
                short_id_value(data.get("auto_commit"))
            );
        }
        Command::Fork { commit, name } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/commits/{commit}/fork"),
                Some(json!({ "name": name })),
            )?)?;
            print_space_summary(&data);
        }
        Command::RmCkpt { commit } => {
            let data = response_value(client.request(
                "DELETE",
                &format!("/v1/commits/{commit}"),
                None,
            )?)?;
            println!("removed {}", field_text(&data, "removed"));
        }
        Command::Gc {
            free_below,
            dry_run,
        } => {
            let data = response_value(client.request(
                "POST",
                "/v1/gc",
                Some(json!({ "free_below": free_below, "dry_run": dry_run })),
            )?)?;
            if dry_run {
                println!("dry-run:");
            }
            if let Some(deleted) = data.get("deleted").and_then(Value::as_array) {
                for row in deleted {
                    println!(
                        "{}  {}  {}",
                        short_id_value(row.get("id")),
                        human(value_u64(row.get("exclusive")).unwrap_or(0)),
                        field_text(row, "note")
                    );
                }
            }
            println!(
                "reclaimed {} bytes",
                value_u64(data.get("reclaimed")).unwrap_or(0)
            );
        }
        Command::Usage { from, to, json } => {
            let path = usage_path(from, to);
            let response = client.request("GET", &path, None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_usage(&response_value_from_body(&body)?);
            }
        }
        Command::Limits { json } => {
            let response = client.request("GET", "/v1/limits", None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_limits(&response_value_from_body(&body)?);
            }
        }
        Command::Token { .. } => {
            return Err("token commands must be handled without an HTTP endpoint".to_string());
        }
    }
    Ok(0)
}

fn usage_path(from: Option<i64>, to: Option<i64>) -> String {
    let mut query = Vec::new();
    if let Some(from) = from {
        query.push(format!("from={from}"));
    }
    if let Some(to) = to {
        query.push(format!("to={to}"));
    }
    if query.is_empty() {
        "/v1/usage".to_string()
    } else {
        format!("/v1/usage?{}", query.join("&"))
    }
}

fn vm_time(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours}h {minutes}m {seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn print_usage(data: &Value) {
    println!("project: {}", field_text(data, "project"));
    println!(
        "spaces_created: {}",
        value_u64(data.get("spaces_created")).unwrap_or(0)
    );
    println!(
        "vm_seconds: {}",
        vm_time(value_u64(data.get("vm_seconds")).unwrap_or(0))
    );
    // A MiB-hour integral is fractional for short-lived spaces, so reading it
    // as an integer would report zero for anything under two minutes.
    println!(
        "disk_mib_hour: {:.2}",
        data.get("disk_mib_hour")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
    );
    println!("api_calls: {}", value_u64(data.get("api_calls")).unwrap_or(0));
}

fn print_limits(data: &Value) {
    let used = data.get("used").unwrap_or(&Value::Null);
    println!(
        "spaces: {}/{}",
        value_u64(used.get("spaces")).unwrap_or(0),
        value_u64(data.get("max_spaces")).unwrap_or(0)
    );
    println!(
        "max_vcpus: {}",
        value_u64(data.get("max_vcpus")).unwrap_or(0)
    );
    println!(
        "max_mem_mib: {}",
        human_mib(data.get("max_mem_mib"))
    );
    println!(
        "disk_mib: {}/{}",
        value_u64(used.get("disk_mib")).unwrap_or(0),
        value_u64(data.get("max_disk_mib")).unwrap_or(0)
    );
    println!(
        "running: {}/{}",
        value_u64(used.get("running")).unwrap_or(0),
        value_u64(data.get("max_running")).unwrap_or(0)
    );
    println!("api_per_min: {}", value_u64(data.get("api_per_min")).unwrap_or(0));
}

fn run_token(root: Option<PathBuf>, command: TokenCommand) -> Result<i32, String> {
    let root = shinu::resolve_root(root.as_deref());
    match command {
        TokenCommand::New { project } => {
            if project.trim().is_empty() {
                return Err("project must not be empty".to_string());
            }
            let plain = token::mint().map_err(|error| error.to_string())?;
            let mut tokens = token::load(&root).map_err(|error| error.to_string())?;
            tokens.push(Token {
                hash: token::hash(&plain),
                project,
                created_at: Utc::now(),
            });
            token::store(&root, &tokens).map_err(|error| error.to_string())?;
            println!("token: {plain}");
            println!("This plaintext token will not be shown again; store it securely now.");
        }
        TokenCommand::Ls => {
            let tokens = token::load(&root).map_err(|error| error.to_string())?;
            let rows = tokens
                .iter()
                .map(|record| {
                    vec![
                        record.project.clone(),
                        record.hash.chars().take(12).collect(),
                        seconds(&record.created_at.to_rfc3339()),
                    ]
                })
                .collect::<Vec<_>>();
            table(&["PROJECT", "HASH", "CREATED"], &rows);
        }
        TokenCommand::Rm { hash_prefix } => {
            let mut tokens = token::load(&root).map_err(|error| error.to_string())?;
            let index = find_token_index(&tokens, &hash_prefix)?;
            let removed = tokens.remove(index);
            token::store(&root, &tokens).map_err(|error| error.to_string())?;
            println!("removed token {}", removed.hash);
        }
    }
    Ok(0)
}

fn response_value(response: HttpResponse) -> Result<Value, String> {
    response_value_from_body(&successful_body(response)?)
}

fn successful_body(response: HttpResponse) -> Result<Vec<u8>, String> {
    if (200..300).contains(&response.status) {
        Ok(response.body)
    } else {
        Err(http_error(response.status, &response.body))
    }
}

fn response_value_from_body(body: &[u8]) -> Result<Value, String> {
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON response: {error}"))
    }
}

fn http_error(status: u16, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body)
        && let Some(message) = value.get("error").and_then(Value::as_str)
    {
        return format!("HTTP {status}: {message}");
    }
    let detail = String::from_utf8_lossy(body).trim().to_string();
    if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {detail}")
    }
}

fn print_raw_json(body: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(body).map_err(|error| format!("invalid UTF-8 response: {error}"))?;
    print!("{text}");
    if !text.ends_with('\n') {
        println!();
    }
    Ok(())
}

fn print_space_summary(data: &Value) {
    println!("{}  {}", field_text(data, "name"), field_text(data, "id"));
}

fn print_images(data: &Value) {
    let rows = data
        .as_array()
        .map(|images| {
            images
                .iter()
                .map(|image| {
                    vec![
                        field_text(image, "image"),
                        if image
                            .get("built")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                    ]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    table(&["IMAGE", "BUILT"], &rows);
}

fn human_mib(value: Option<&Value>) -> String {
    value_u64(value)
        .map(|mib| human(mib.saturating_mul(1024 * 1024)))
        .unwrap_or_else(|| "-".to_string())
}

fn print_spaces(data: &Value) {
    let rows = data
        .get("spaces")
        .and_then(Value::as_array)
        .map(|spaces| {
            spaces
                .iter()
                .map(|space| {
                    vec![
                        field_text(space, "name"),
                        field_text(space, "project"),
                        if space
                            .get("running")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            "running".to_string()
                        } else {
                            "stopped".to_string()
                        },
                        short_optional_value(space.get("head")),
                        human(value_u64(space.get("exclusive")).unwrap_or(0)),
                        seconds(&field_text(space, "created_at")),
                        field_text(space, "image"),
                        short_optional_value(space.get("vcpus")),
                        human_mib(space.get("mem_mib")),
                        human_mib(space.get("disk_mib")),
                    ]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    table(
        &[
            "NAME", "PROJECT", "STATE", "HEAD", "EXCLUSIVE", "CREATED", "IMAGE", "VCPU",
            "MEM", "DISK",
        ],
        &rows,
    );

    if let Some(ckpts) = data.get("ckpts").and_then(Value::as_array) {
        println!();
        let rows = ckpts
            .iter()
            .map(|ckpt| {
                let note = field_text(ckpt, "note");
                let note = if ckpt
                    .get("auto")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
                {
                    format!("(auto) {note}")
                } else {
                    note
                };
                vec![
                    field_text(ckpt, "id"),
                    human(value_u64(ckpt.get("exclusive")).unwrap_or(0)),
                    seconds(&field_text(ckpt, "created_at")),
                    note,
                ]
            })
            .collect::<Vec<_>>();
        table(&["ID", "EXCLUSIVE", "CREATED", "NOTE"], &rows);
    }
}

fn print_log(data: &Value) {
    print_checkpoint_list(data, "commits");
}

fn print_reflog(data: &Value) {
    print_checkpoint_list(data, "entries");
}

fn print_checkpoint_list(data: &Value, key: &str) {
    if let Some(commits) = data.get(key).and_then(Value::as_array) {
        for commit in commits {
            let note = field_text(commit, "note");
            let note = if commit
                .get("auto")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                format!("(auto) {note}")
            } else {
                note
            };
            println!(
                "{}  {}  {note}",
                short_id_value(commit.get("id")),
                seconds(&field_text(commit, "created_at"))
            );
        }
    }
}

fn field_text(value: &Value, field: &str) -> String {
    value
        .get(field)
        .map(value_text)
        .unwrap_or_else(|| "-".to_string())
}

fn value_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => "-".to_string(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| "-".to_string()),
    }
}

fn short_id_value(value: Option<&Value>) -> String {
    value.map_or_else(|| "-".to_string(), |value| short_id(&value_text(value)))
}

fn short_optional_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "-".to_string(),
        Some(value) => short_id(&value_text(value)),
    }
}

fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

fn value_u64(value: Option<&Value>) -> Option<u64> {
    match value {
        Some(Value::Number(number)) => number.as_u64(),
        Some(Value::String(value)) => value.parse().ok(),
        _ => None,
    }
}

fn human(n: u64) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1024 * 1024 {
        format!("{:.1} KiB", n as f64 / 1024.0)
    } else if n < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GiB", n as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn seconds(value: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|date| date.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|_| value.to_owned())
}

fn table(headers: &[&str], rows: &[Vec<String>]) {
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            rows.iter()
                .map(|row| row[index].chars().count())
                .max()
                .unwrap_or(0)
                .max(header.chars().count())
        })
        .collect();
    for (index, header) in headers.iter().enumerate() {
        if index > 0 {
            print!("  ");
        }
        if index + 1 == headers.len() {
            print!("{header}");
        } else {
            print!("{header:<width$}", width = widths[index]);
        }
    }
    println!();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                print!("  ");
            }
            if index + 1 == row.len() {
                print!("{cell}");
            } else {
                print!("{cell:<width$}", width = widths[index]);
            }
        }
        println!();
    }
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
fn encode_query_value(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}


fn read_response_head<R: BufRead>(reader: &mut R) -> Result<ResponseHead, String> {
    let mut status_line = String::new();
    if reader
        .read_line(&mut status_line)
        .map_err(|error| error.to_string())?
        == 0
    {
        return Err("HTTP response ended before the status line".to_string());
    }
    let status = parse_status_line(&status_line)?;
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("HTTP response ended before the headers".to_string());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed HTTP response header".to_string())?;
        headers.push((
            name.trim().to_ascii_lowercase(),
            value.trim().to_string(),
        ));
    }
    Ok(ResponseHead { status, headers })
}

fn parse_status_line(line: &str) -> Result<u16, String> {
    let mut fields = line.trim_end_matches(&['\r', '\n'][..]).splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("unsupported HTTP status line: {line:?}"));
    }
    let code = fields
        .next()
        .ok_or_else(|| "HTTP status line is missing a status code".to_string())?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("invalid HTTP status code: {code:?}"));
    }
    let status = code
        .parse::<u16>()
        .map_err(|error| format!("invalid HTTP status code: {error}"))?;
    if !(100..=599).contains(&status) {
        return Err(format!("invalid HTTP status code: {status}"));
    }
    Ok(status)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    header(headers, "transfer-encoding").is_some_and(|value| {
        value
            .split(',')
            .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, String> {
    header(headers, "content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|error| format!("invalid Content-Length: {error}"))
        })
        .transpose()
}

fn read_body<R: BufRead>(reader: &mut R, headers: &[(String, String)]) -> Result<Vec<u8>, String> {
    if is_chunked(headers) {
        let mut body = Vec::new();
        read_chunked(reader, |chunk| {
            body.extend_from_slice(chunk);
            Ok(())
        })?;
        return Ok(body);
    }
    if let Some(length) = content_length(headers)? {
        let mut body = vec![0u8; length];
        reader.read_exact(&mut body).map_err(|error| error.to_string())?;
        return Ok(body);
    }
    let mut body = Vec::new();
    reader
        .read_to_end(&mut body)
        .map_err(|error| error.to_string())?;
    Ok(body)
}
fn stream_body<R: BufRead, W: Write>(
    reader: &mut R,
    headers: &[(String, String)],
    output: &mut W,
) -> Result<u64, String> {
    let mut total = 0u64;
    let mut write_fragment = |fragment: &[u8]| {
        output
            .write_all(fragment)
            .map_err(|error| format!("could not write pull output: {error}"))?;
        total = total
            .checked_add(fragment.len() as u64)
            .ok_or_else(|| "pull response was too large".to_string())?;
        Ok(())
    };
    if is_chunked(headers) {
        read_chunked(reader, &mut write_fragment)?;
    } else if let Some(length) = content_length(headers)? {
        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            let count = reader
                .read(&mut buffer[..amount])
                .map_err(|error| error.to_string())?;
            if count == 0 {
                return Err("pull HTTP body ended before Content-Length".to_string());
            }
            write_fragment(&buffer[..count])?;
            remaining -= count;
        }
    } else {
        let mut buffer = [0u8; 8192];
        loop {
            let count = reader.read(&mut buffer).map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            write_fragment(&buffer[..count])?;
        }
    }
    output.flush().map_err(|error| format!("could not flush pull output: {error}"))?;
    Ok(total)
}


fn read_chunked<R: BufRead, F>(reader: &mut R, mut on_chunk: F) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    loop {
        let mut size_line = String::new();
        if reader
            .read_line(&mut size_line)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Err("chunked HTTP body ended before a chunk size".to_string());
        }
        let size_text = size_line
            .trim_end_matches(&['\r', '\n'][..])
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("invalid chunk size {size_text:?}: {error}"))?;
        if size == 0 {
            loop {
                let mut trailer = String::new();
                if reader
                    .read_line(&mut trailer)
                    .map_err(|error| error.to_string())?
                    == 0
                {
                    return Err("chunked HTTP body ended before trailers".to_string());
                }
                if trailer == "\r\n" || trailer == "\n" {
                    return Ok(());
                }
            }
        }
        let mut remaining = size;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            reader
                .read_exact(&mut buffer[..amount])
                .map_err(|error| error.to_string())?;
            on_chunk(&buffer[..amount])?;
            remaining -= amount;
        }
        let mut line_end = [0u8; 2];
        reader
            .read_exact(&mut line_end)
            .map_err(|error| error.to_string())?;
        if line_end != *b"\r\n" {
            return Err("chunked HTTP body is missing its CRLF".to_string());
        }
    }
}

fn stream_ndjson<R: BufRead>(
    reader: &mut R,
    headers: &[(String, String)],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32, String> {
    let mut pending = Vec::new();
    let mut exit_code = None;
    let mut feed = |fragment: &[u8]| {
        feed_ndjson(
            fragment,
            &mut pending,
            &mut exit_code,
            stdout,
            stderr,
        )
    };

    if is_chunked(headers) {
        read_chunked(reader, &mut feed)?;
    } else if let Some(length) = content_length(headers)? {
        let mut remaining = length;
        let mut buffer = [0u8; 8192];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            let count = reader
                .read(&mut buffer[..amount])
                .map_err(|error| error.to_string())?;
            if count == 0 {
                return Err("exec HTTP body ended before Content-Length".to_string());
            }
            feed(&buffer[..count])?;
            remaining -= count;
        }
    } else {
        let mut buffer = [0u8; 8192];
        loop {
            let count = reader.read(&mut buffer).map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            feed(&buffer[..count])?;
        }
    }

    if !pending.is_empty() {
        let line = std::str::from_utf8(&pending)
            .map_err(|error| format!("invalid UTF-8 in exec response: {error}"))?;
        if !line.trim().is_empty()
            && let Some(code) = dispatch_ndjson_line(line.trim_end_matches('\r'), stdout, stderr)?
            && exit_code.replace(code).is_some()
        {
            return Err("exec response contained multiple exit statuses".to_string());
        }
    }
    exit_code.ok_or_else(|| "exec response did not include an exit status".to_string())
}

fn feed_ndjson(
    fragment: &[u8],
    pending: &mut Vec<u8>,
    exit_code: &mut Option<i32>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<(), String> {
    pending.extend_from_slice(fragment);
    while let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
        let line = pending.drain(..=position).collect::<Vec<_>>();
        let line = std::str::from_utf8(&line[..line.len() - 1])
            .map_err(|error| format!("invalid UTF-8 in exec response: {error}"))?
            .trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        if let Some(code) = dispatch_ndjson_line(line, stdout, stderr)?
            && exit_code.replace(code).is_some()
        {
            return Err("exec response contained multiple exit statuses".to_string());
        }
    }
    Ok(())
}

fn dispatch_ndjson_line<'a>(
    line: &str,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
) -> Result<Option<i32>, String> {
    let value: Value = serde_json::from_str(line).map_err(|error| format!("invalid NDJSON line: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "exec NDJSON line must be a JSON object".to_string())?;
    if let Some(stream) = object.get("stream") {
        let stream = stream
            .as_str()
            .ok_or_else(|| "exec stream must be a string".to_string())?;
        let data = object
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| "exec stream line is missing string data".to_string())?;
        let writer = match stream {
            "stdout" => stdout,
            "stderr" => stderr,
            _ => return Err(format!("unknown exec stream {stream:?}")),
        };
        writer
            .write_all(data.as_bytes())
            .map_err(|error| error.to_string())?;
        writer.flush().map_err(|error| error.to_string())?;
        return Ok(None);
    }
    if let Some(exit) = object.get("exit") {
        let exit = exit
            .as_i64()
            .ok_or_else(|| "exec exit status must be an integer".to_string())?;
        if !(i32::MIN as i64..=i32::MAX as i64).contains(&exit) {
            return Err(format!("exec exit status is out of range: {exit}"));
        }
        return Ok(Some(exit as i32));
    }
    Err("exec NDJSON line must contain stream or exit".to_string())
}

fn find_token_index(tokens: &[Token], prefix: &str) -> Result<usize, String> {
    if prefix.is_empty() {
        return Err("hash prefix must not be empty".to_string());
    }
    let matches = tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| token.hash.starts_with(prefix))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(format!("no token matches hash prefix {prefix:?}")),
        [index] => Ok(*index),
        _ => Err(format!(
            "hash prefix {prefix:?} matches multiple tokens; provide a longer prefix"
        )),
    }
}

fn main() {
    match run() {
        Ok(code) => {
            if code != 0 {
                std::process::exit(code);
            }
        }
        Err(message) => {
            eprintln!("shinu: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_status_code() {
        assert_eq!(parse_status_line("HTTP/1.1 201 Created\r\n").unwrap(), 201);
    }
    #[test]
    fn encodes_query_values_without_leaking_reserved_path_bytes() {
        assert_eq!(
            encode_query_value("/root/a b?x&y=#%é"),
            "%2Froot%2Fa%20b%3Fx%26y%3D%23%25%C3%A9"
        );
    }

    #[test]
    fn create_body_omits_unspecified_optional_fields() {
        let body = create_space_body("dev", None, None, None, None);
        assert_eq!(body, json!({"name": "dev"}));
        assert!(body.get("image").is_none());
        assert!(body.get("vcpus").is_none());
        assert!(body.get("mem_mib").is_none());
        assert!(body.get("disk_mib").is_none());
    }

    #[test]
    fn resize_body_rejects_no_flags() {
        let error = resize_space_body(None, None, None).unwrap_err();
        assert!(error.contains("at least one"));
    }

    #[test]
    fn resize_body_includes_only_requested_fields() {
        let body = resize_space_body(Some(2), None, Some(4096)).unwrap();
        assert_eq!(body, json!({"vcpus": 2, "disk_mib": 4096}));
        assert!(body.get("mem_mib").is_none());
    }


    #[test]
    fn dispatches_ndjson_streams_and_exit() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            dispatch_ndjson_line(
                r#"{"stream":"stdout","data":"out\n"}"#,
                &mut stdout,
                &mut stderr,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            dispatch_ndjson_line(
                r#"{"stream":"stderr","data":"warn\n"}"#,
                &mut stdout,
                &mut stderr,
            )
            .unwrap(),
            None
        );
        assert_eq!(
            dispatch_ndjson_line(r#"{"exit":17}"#, &mut stdout, &mut stderr).unwrap(),
            Some(17)
        );
        assert_eq!(stdout, b"out\n");
        assert_eq!(stderr, b"warn\n");
    }

    #[test]
    fn token_prefix_must_match_exactly_one_record() {
        let tokens = vec![
            Token {
                hash: "abcdef001122".to_string(),
                project: "one".to_string(),
                created_at: Utc::now(),
            },
            Token {
                hash: "abc999001122".to_string(),
                project: "two".to_string(),
                created_at: Utc::now(),
            },
        ];
        let error = find_token_index(&tokens, "abc").unwrap_err();
        assert!(error.contains("multiple"));
        assert_eq!(find_token_index(&tokens, "abcdef"), Ok(0));
    }
}
