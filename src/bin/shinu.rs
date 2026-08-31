use chrono::Utc;
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use shinu::proto::SnapshotMode;
use shinu::token::{self, Token};
use shinu_client::{
    Client, Endpoint, Response, ResponseStream, encode_path_segment, encode_query_value,
};
use shinu_image::DEFAULT_DIFF_LIMIT;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

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
        #[arg(long)]
        network: Option<String>,
        #[arg(long, value_name = "DURATION", value_parser = parse_ttl_duration)]
        ttl: Option<u64>,
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
    Network {
        name: String,
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
    Proxy {
        space: String,
        port: u16,
        #[arg(long, default_value = "/")]
        path: String,
    },
    Exec {
        space: String,
        #[arg(long, value_name = "FILE")]
        stdin: Option<String>,
        #[arg(long, value_name = "ID")]
        session: Option<String>,
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
        #[arg(long, conflicts_with = "diff")]
        full: bool,
        #[arg(long, conflicts_with = "full")]
        diff: bool,
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
    /// Compare filesystems: SOURCE alone is a space versus HEAD; SOURCE plus
    /// a commit compares that space to the commit, or compares two commits.
    Diff {
        source: String,
        target: Option<String>,
        #[arg(
            long,
            help = "include all paths; by default exclude /dev, /proc, /run, /sys, /tmp, /var/log, /etc/machine-id, and /etc/ssh/ssh_host_*"
        )]
        all: bool,
        #[arg(long, default_value_t = DEFAULT_DIFF_LIMIT, help = "maximum reported entries (default 10000; larger values are capped by the daemon)")]
        limit: usize,
    },
    Checkout {
        space: String,
        commit: Uuid,
    },
    Fork {
        commit: Uuid,
        name: String,
        #[arg(long, value_name = "DURATION", value_parser = parse_ttl_duration)]
        ttl: Option<u64>,
    },
    #[command(group(
        clap::ArgGroup::new("lease-options")
            .required(true)
            .multiple(false)
            .args(["ttl", "clear"])
    ))]
    Lease {
        space: String,
        #[arg(long, value_name = "DURATION", value_parser = parse_ttl_duration)]
        ttl: Option<u64>,
        #[arg(long)]
        clear: bool,
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
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    Limits {
        #[command(subcommand)]
        command: Option<LimitsCommand>,
        #[arg(long)]
        json: bool,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
}

#[derive(Subcommand)]
enum JobCommand {
    Run {
        #[arg(value_name = "SPACE")]
        space: String,
        #[arg(long, value_name = "FILE")]
        stdin: Option<String>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    Ls {
        #[arg(long)]
        json: bool,
    },
    Status {
        #[arg(value_name = "UUID")]
        id: Uuid,
        #[arg(long)]
        json: bool,
    },
    Logs {
        #[arg(value_name = "UUID")]
        id: Uuid,
    },
    Wait {
        #[arg(value_name = "UUID")]
        id: Uuid,
    },
    Cancel {
        #[arg(value_name = "UUID")]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum LimitsCommand {
    Set {
        project: String,
        #[arg(long, value_name = "N|unlimited")]
        spaces: Option<String>,
        #[arg(long, value_name = "N|unlimited")]
        disk_mib: Option<String>,
        #[arg(long, value_name = "N|unlimited")]
        running: Option<String>,
        #[arg(long, value_name = "N|unlimited")]
        api_per_min: Option<String>,
        #[arg(long, value_name = "FIELD", value_delimiter = ',')]
        inherit: Vec<String>,
    },
    Clear {
        project: String,
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

fn request_json(
    client: &Client,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Response, String> {
    let body = body
        .map(|value| serde_json::to_vec(&value).map_err(|error| error.to_string()))
        .transpose()?;
    client
        .request(method, path, body.as_deref())
        .map_err(|error| error.to_string())
}

fn stream_exec(
    client: &Client,
    space: &str,
    command: &[String],
    stdin_path: Option<&str>,
    session_id: Option<&str>,
) -> Result<i32, String> {
    let mut body = json!({ "cmd": command });
    if let Some(path) = stdin_path {
        body["stdin"] = Value::String(read_exec_stdin(path)?);
    }
    if let Some(session) = session_id {
        body["session"] = Value::String(session.to_owned());
    }
    let encoded = serde_json::to_vec(&body).map_err(|error| error.to_string())?;
    let path = format!(
        "/v1/spaces/{}/exec",
        shinu_client::encode_path_segment(space)
    );
    let mut response = client
        .open_request("POST", &path, Some(&encoded))
        .map_err(|error| error.to_string())?;
    if !response.head().is_success() {
        let status = response.head().status;
        let body = response.read_body().map_err(|error| error.to_string())?;
        return Err(shinu_client::Error::http(status, body).to_string());
    }
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    stream_ndjson(&mut response, &mut stdout, &mut stderr)
}

fn push_file(
    client: &Client,
    space: &str,
    local_path: &str,
    guest_path: &str,
) -> Result<u64, String> {
    let mut source = upload_source(local_path)?;
    let target = format!(
        "/v1/spaces/{}/push?path={}",
        shinu_client::encode_path_segment(space),
        shinu_client::encode_query_value(guest_path)
    );
    let mut stream = client
        .start_request("POST", &target, source.length, false)
        .map_err(|error| error.to_string())?;
    copy_upload(&mut source.file, &mut stream, source.length)?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = Client::read_response(stream).map_err(|error| error.to_string())?;
    let body = response.read_body().map_err(|error| error.to_string())?;
    let status = response.head().status;
    if !(200..300).contains(&status) {
        return Err(shinu_client::Error::http(status, body).to_string());
    }
    let response = response_value_from_body(&body)?;
    response
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "push response did not include a byte count".to_string())
}

fn pull_file(
    client: &Client,
    space: &str,
    guest_path: &str,
    local_path: &str,
) -> Result<u64, String> {
    let target = format!(
        "/v1/spaces/{}/pull?path={}",
        shinu_client::encode_path_segment(space),
        shinu_client::encode_query_value(guest_path)
    );
    let mut response = client
        .open_request("GET", &target, None)
        .map_err(|error| error.to_string())?;
    if !response.head().is_success() {
        let status = response.head().status;
        let body = response.read_body().map_err(|error| error.to_string())?;
        return Err(shinu_client::Error::http(status, body).to_string());
    }
    if local_path == "-" {
        let stdout = io::stdout();
        let mut output = stdout.lock();
        stream_pull_body(&mut response, &mut output)
    } else {
        let mut output = File::create(local_path)
            .map_err(|error| format!("could not create {local_path:?}: {error}"))?;
        stream_pull_body(&mut response, &mut output)
    }
}

fn stream_pull_body(response: &mut ResponseStream, output: &mut impl Write) -> Result<u64, String> {
    let mut total = 0u64;
    response
        .stream_body(|fragment| {
            output.write_all(fragment).map_err(|error| {
                shinu_client::Error::invalid(format!("could not write pull output: {error}"))
            })?;
            total = total
                .checked_add(u64::try_from(fragment.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| shinu_client::Error::invalid("pull response was too large"))?;
            Ok(())
        })
        .map_err(|error| {
            let message = error.to_string();
            if message == "HTTP response body ended before Content-Length" {
                "pull HTTP body ended before Content-Length".to_owned()
            } else {
                message
            }
        })?;
    output
        .flush()
        .map_err(|error| format!("could not flush pull output: {error}"))?;
    Ok(total)
}

fn proxy_once(client: &Client, space: &str, port: u16, path: &str) -> Result<i32, String> {
    if port == 0 {
        return Err("proxy port must be between 1 and 65535".to_string());
    }
    if !path.starts_with('/')
        || path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err("proxy path must start with / and contain no control characters".to_string());
    }
    let target = format!(
        "/v1/spaces/{}/proxy/{port}{path}",
        shinu_client::encode_path_segment(space)
    );
    let mut response = client
        .open_request("GET", &target, None)
        .map_err(|error| error.to_string())?;
    let body = response.read_body().map_err(|error| error.to_string())?;
    let head = response.head();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    writeln!(output, "HTTP/1.1 {}", head.status).map_err(|error| error.to_string())?;
    for (name, value) in &head.headers {
        writeln!(output, "{name}: {value}").map_err(|error| error.to_string())?;
    }
    output
        .write_all(b"\r\n")
        .map_err(|error| error.to_string())?;
    output.write_all(&body).map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    Ok(i32::from(!(200..300).contains(&head.status)))
}

fn proxy_vnc(client: &Client, space: &str, port: u16) -> Result<i32, String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|error| format!("could not listen on localhost:{port}: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("could not inspect VNC listener address: {error}"))?;
    println!("VNC proxy listening on {address}");
    for incoming in listener.incoming() {
        let local = incoming.map_err(|error| format!("could not accept VNC client: {error}"))?;
        let client = client.clone();
        let space = space.to_owned();
        thread::spawn(move || {
            if let Err(error) = proxy_vnc_connection(&client, &space, local) {
                eprintln!("VNC connection: {error}");
            }
        });
    }
    Ok(0)
}

fn proxy_vnc_connection(client: &Client, space: &str, mut local: TcpStream) -> Result<(), String> {
    let path = format!(
        "/v1/spaces/{}/vnc",
        shinu_client::encode_path_segment(space)
    );
    let (mut remote, head) = client.open_raw_request("GET", &path).map_err(|error| {
        let message = error.to_string();
        if message == "HTTP response ended before the response headers" {
            "HTTP response ended before the VNC headers".to_owned()
        } else {
            message
        }
    })?;
    if !head.is_success() {
        let mut reader = BufReader::new(remote);
        let body =
            shinu_client::read_body(&mut reader, &head).map_err(|error| error.to_string())?;
        return Err(shinu_client::Error::http(head.status, body).to_string());
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
        // Do not half-close either socket: Firecracker's vsock multiplexer treats that as closing both directions.
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
                    ) =>
                {
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
        // Push requires Content-Length; spool stdin to disk instead of buffering it in memory.
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
        let file =
            file.ok_or_else(|| "could not create a unique temporary upload file".to_string())?;
        let mut source = UploadSource {
            file,
            length: 0,
            temporary_path,
        };
        let stdin = io::stdin();
        let mut input = stdin.lock();
        source.length = io::copy(&mut input, &mut source.file)
            .map_err(|error| format!("could not read stdin: {error}"))?;
        source
            .file
            .flush()
            .map_err(|error| format!("could not flush temporary upload file: {error}"))?;
        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|error| format!("could not rewind temporary upload file: {error}"))?;
        return Ok(source);
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
        let amount = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
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

const JOB_WAIT_INTERVAL: Duration = Duration::from_millis(250);

fn job_run_body(command: &[String], stdin_path: Option<&str>) -> Result<Value, String> {
    let mut body = json!({ "cmd": command });
    if let Some(path) = stdin_path {
        body["stdin"] = Value::String(read_exec_stdin(path)?);
    }
    Ok(body)
}

fn job_path(id: Uuid) -> String {
    format!("/v1/jobs/{id}")
}

fn job_logs_path(id: Uuid) -> String {
    format!("/v1/jobs/{id}/logs")
}
fn job_cancel_path(id: Uuid) -> String {
    format!("/v1/jobs/{id}/cancel")
}

fn job_wait_status(data: &Value) -> Result<Option<i32>, String> {
    let state = data
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| "job response is missing a string state".to_string())?;
    match state {
        "starting" | "running" | "canceling" => Ok(None),
        "canceled" | "lost" => Ok(Some(1)),
        "exited" => {
            let exit = data
                .get("exit_code")
                .and_then(Value::as_i64)
                .ok_or_else(|| "exited job response is missing an integer exit_code".to_string())?;
            let exit = i32::try_from(exit)
                .map_err(|_| format!("job exit status is out of range: {exit}"))?;
            Ok(Some(exit))
        }
        other => Err(format!("unknown job state {other:?}")),
    }
}

fn wait_for_job(client: &Client, id: Uuid) -> Result<i32, String> {
    loop {
        let data = response_value(request_json(client, "GET", &job_path(id), None)?)?;
        if let Some(status) = job_wait_status(&data)? {
            return Ok(status);
        }
        thread::sleep(JOB_WAIT_INTERVAL);
    }
}

fn run_job_command(client: &Client, command: JobCommand) -> Result<i32, String> {
    match command {
        JobCommand::Run { space, stdin, cmd } => {
            let body = job_run_body(&cmd, stdin.as_deref())?;
            let data = response_value(request_json(
                client,
                "POST",
                &format!("/v1/spaces/{}/jobs", encode_path_segment(&space)),
                Some(body),
            )?)?;
            println!(
                "{}  {}",
                field_text(&data, "id"),
                field_text(&data, "state")
            );
        }
        JobCommand::Ls { json } => {
            let response = request_json(client, "GET", "/v1/jobs", None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_jobs(&response_value_from_body(&body)?)?;
            }
        }
        JobCommand::Status { id, json } => {
            let response = request_json(client, "GET", &job_path(id), None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_job_status(&response_value_from_body(&body)?)?;
            }
        }
        JobCommand::Logs { id } => {
            let data = response_value(request_json(client, "GET", &job_logs_path(id), None)?)?;
            let stdout = io::stdout();
            let mut output = stdout.lock();
            let stderr = io::stderr();
            let mut errors = stderr.lock();
            write_job_logs(&data, &mut output, &mut errors)?;
        }
        JobCommand::Wait { id } => return wait_for_job(client, id),
        JobCommand::Cancel { id } => {
            let data = response_value(request_json(client, "POST", &job_cancel_path(id), None)?)?;
            print_job_status(&data)?;
        }
    }
    Ok(0)
}

fn client_from_options(endpoint: Option<String>, token: Option<String>) -> Result<Client, String> {
    let endpoint = endpoint.unwrap_or_else(shinu_client::endpoint_value_from_env_preserving_empty);
    let token = token
        .or_else(|| std::env::var("SHINU_TOKEN").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "missing bearer token; create one with `shinu token new --project <id>` and set SHINU_TOKEN or pass --token"
                .to_string()
        })?;
    Client::new(
        Endpoint::parse(&endpoint).map_err(|error| error.to_string())?,
        token,
    )
    .map_err(|error| error.to_string())
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

const TTL_DURATION_ERROR: &str = "TTL must be a positive integer followed by one of s, m, h, or d";

fn parse_ttl_duration(raw: &str) -> Result<u64, String> {
    let bytes = raw.as_bytes();
    let Some((&unit, digits)) = bytes.split_last() else {
        return Err(TTL_DURATION_ERROR.to_owned());
    };
    let multiplier = match unit {
        b's' => 1_u64,
        b'm' => 60,
        b'h' => 60 * 60,
        b'd' => 24 * 60 * 60,
        _ => return Err(TTL_DURATION_ERROR.to_owned()),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return Err(TTL_DURATION_ERROR.to_owned());
    }
    let number = std::str::from_utf8(digits).map_err(|_| TTL_DURATION_ERROR.to_owned())?;
    let number = number
        .parse::<u64>()
        .map_err(|_| "TTL duration number is too large".to_owned())?;
    if number == 0 {
        return Err("TTL duration must be greater than zero".to_owned());
    }
    number
        .checked_mul(multiplier)
        .ok_or_else(|| "TTL duration is too large".to_owned())
}

fn create_space_body(
    name: &str,
    image: Option<String>,
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u64>,
    network: Option<String>,
    ttl_seconds: Option<u64>,
) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("name".to_owned(), Value::String(name.to_owned()));
    if let Some(image) = image {
        object.insert("image".to_owned(), Value::String(image));
    }
    if let Some(vcpus) = vcpus {
        object.insert("vcpus".to_owned(), Value::from(vcpus));
    }
    if let Some(mem_mib) = mem_mib {
        object.insert("mem_mib".to_owned(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = disk_mib {
        object.insert("disk_mib".to_owned(), Value::from(disk_mib));
    }
    if let Some(network) = network {
        object.insert("network".to_owned(), Value::String(network));
    }
    if let Some(ttl_seconds) = ttl_seconds {
        object.insert("ttl_seconds".to_owned(), Value::from(ttl_seconds));
    }
    Value::Object(object)
}

fn fork_space_body(name: &str, ttl_seconds: Option<u64>) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("name".to_owned(), Value::String(name.to_owned()));
    if let Some(ttl_seconds) = ttl_seconds {
        object.insert("ttl_seconds".to_owned(), Value::from(ttl_seconds));
    }
    Value::Object(object)
}

fn lease_space_body(ttl_seconds: Option<u64>) -> Value {
    json!({"ttl_seconds": ttl_seconds})
}

fn resize_space_body(
    vcpus: Option<u32>,
    mem_mib: Option<u32>,
    disk_mib: Option<u64>,
) -> Result<Value, String> {
    if vcpus.is_none() && mem_mib.is_none() && disk_mib.is_none() {
        return Err("resize requires at least one of --vcpus, --mem, or --disk".to_string());
    }
    let mut object = serde_json::Map::new();
    if let Some(vcpus) = vcpus {
        object.insert("vcpus".to_owned(), Value::from(vcpus));
    }
    if let Some(mem_mib) = mem_mib {
        object.insert("mem_mib".to_owned(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = disk_mib {
        object.insert("disk_mib".to_owned(), Value::from(disk_mib));
    }
    Ok(Value::Object(object))
}

fn parse_limit_u32(raw: &str, field: &str) -> Result<u32, String> {
    if raw.trim().eq_ignore_ascii_case("unlimited") {
        Ok(0)
    } else {
        raw.trim().parse::<u32>().map_err(|error| {
            format!("--{field} must be a non-negative integer or unlimited: {error}")
        })
    }
}

fn parse_limit_u64(raw: &str, field: &str) -> Result<u64, String> {
    if raw.trim().eq_ignore_ascii_case("unlimited") {
        Ok(0)
    } else {
        raw.trim().parse::<u64>().map_err(|error| {
            format!("--{field} must be a non-negative integer or unlimited: {error}")
        })
    }
}

fn inherit_requested(fields: &[String], field: &str) -> Result<bool, String> {
    let mut found = false;
    for requested in fields {
        if !matches!(
            requested.as_str(),
            "spaces" | "disk-mib" | "running" | "api-per-min"
        ) {
            return Err(format!(
                "--inherit field must be one of: spaces, disk-mib, running, api-per-min (got {requested})"
            ));
        }
        if requested == field {
            if found {
                return Err(format!("--inherit {field} was specified more than once"));
            }
            found = true;
        }
    }
    Ok(found)
}

fn limits_set_body(
    spaces: Option<String>,
    disk_mib: Option<String>,
    running: Option<String>,
    api_per_min: Option<String>,
    inherit: &[String],
) -> Result<Value, String> {
    let spaces_inherit = inherit_requested(inherit, "spaces")?;
    let disk_inherit = inherit_requested(inherit, "disk-mib")?;
    let running_inherit = inherit_requested(inherit, "running")?;
    let api_inherit = inherit_requested(inherit, "api-per-min")?;
    let mut object = serde_json::Map::new();
    let mut fields = 0;

    if let Some(raw) = spaces {
        if spaces_inherit {
            return Err("--spaces and --inherit spaces cannot be combined".into());
        }
        object.insert(
            "max_spaces".into(),
            Value::from(parse_limit_u32(&raw, "spaces")?),
        );
        fields += 1;
    } else if spaces_inherit {
        object.insert("max_spaces".into(), Value::Null);
        fields += 1;
    }

    if let Some(raw) = disk_mib {
        if disk_inherit {
            return Err("--disk-mib and --inherit disk-mib cannot be combined".into());
        }
        object.insert(
            "max_disk_mib".into(),
            Value::from(parse_limit_u64(&raw, "disk-mib")?),
        );
        fields += 1;
    } else if disk_inherit {
        object.insert("max_disk_mib".into(), Value::Null);
        fields += 1;
    }

    if let Some(raw) = running {
        if running_inherit {
            return Err("--running and --inherit running cannot be combined".into());
        }
        object.insert(
            "max_running".into(),
            Value::from(parse_limit_u32(&raw, "running")?),
        );
        fields += 1;
    } else if running_inherit {
        object.insert("max_running".into(), Value::Null);
        fields += 1;
    }

    if let Some(raw) = api_per_min {
        if api_inherit {
            return Err("--api-per-min and --inherit api-per-min cannot be combined".into());
        }
        object.insert(
            "api_per_min".into(),
            Value::from(parse_limit_u32(&raw, "api-per-min")?),
        );
        fields += 1;
    } else if api_inherit {
        object.insert("api_per_min".into(), Value::Null);
        fields += 1;
    }

    if fields == 0 {
        return Err("limits set requires at least one limit flag or --inherit field".to_string());
    }
    Ok(Value::Object(object))
}

fn run_command(client: &Client, command: Command) -> Result<i32, String> {
    match command {
        Command::New {
            name,
            image,
            vcpus,
            mem,
            disk,
            network,
            ttl,
        } => {
            let data = response_value(request_json(
                client,
                "POST",
                "/v1/spaces",
                Some(create_space_body(
                    &name, image, vcpus, mem, disk, network, ttl,
                )),
            )?)?;
            print_space_summary(&data);
        }
        Command::Resize {
            space,
            vcpus,
            mem,
            disk,
        } => {
            let data = response_value(request_json(
                client,
                "PATCH",
                &format!("/v1/spaces/{}", encode_path_segment(&space)),
                Some(resize_space_body(vcpus, mem, disk)?),
            )?)?;
            print_space_summary(&data);
        }
        Command::Images => {
            let response = request_json(client, "GET", "/v1/images", None)?;
            let body = successful_body(response)?;
            print_images(&response_value_from_body(&body)?);
        }
        Command::Ls { json } => {
            let response = request_json(client, "GET", "/v1/spaces", None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_spaces(&response_value_from_body(&body)?);
            }
        }
        Command::Network { name } => {
            let response = request_json(client, "GET", "/v1/spaces", None)?;
            let body = successful_body(response)?;
            print_network(&response_value_from_body(&body)?, &name)?;
        }
        Command::Rm { space } => {
            let data = response_value(request_json(
                client,
                "DELETE",
                &format!("/v1/spaces/{}", encode_path_segment(&space)),
                None,
            )?)?;
            println!("removed {}", field_text(&data, "removed"));
        }
        Command::Start { space } => {
            let data = response_value(request_json(
                client,
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
            let data = response_value(request_json(
                client,
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
            let status = stream_exec(client, &space, &command, None, None)?;
            if status == 0 {
                println!("desktop services enabled and running for {space}");
            }
            return Ok(status);
        }
        Command::Proxy { space, port, path } => return proxy_once(client, &space, port, &path),
        Command::Vnc { space, port } => return proxy_vnc(client, &space, port),
        Command::Exec {
            space,
            stdin,
            session,
            cmd,
        } => {
            return stream_exec(client, &space, &cmd, stdin.as_deref(), session.as_deref());
        }
        Command::Job { command } => return run_job_command(client, command),
        Command::Push {
            space,
            local_file,
            guest_path,
        } => {
            let bytes = push_file(client, &space, &local_file, &guest_path)?;
            println!("pushed {bytes} bytes to {guest_path}");
        }
        Command::Pull {
            space,
            guest_path,
            local_file,
        } => {
            let bytes = pull_file(client, &space, &guest_path, &local_file)?;
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
            diff,
        } => {
            let snapshot = match (full, diff) {
                (true, false) => SnapshotMode::Full,
                (false, true) => SnapshotMode::Diff,
                (false, false) => SnapshotMode::None,
                (true, true) => unreachable!("clap rejects --full with --diff"),
            };
            let data = response_value(request_json(
                client,
                "POST",
                &format!("/v1/spaces/{}/commits", encode_path_segment(&space)),
                Some(json!({ "note": note, "hot": hot, "snapshot": snapshot })),
            )?)?;
            println!(
                "{}  {}",
                short_id_value(data.get("id")),
                field_text(&data, "note")
            );
        }
        Command::Log { space, json } => {
            let response = request_json(
                client,
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
            let response = request_json(
                client,
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
        Command::Diff {
            source,
            target,
            all,
            limit,
        } => {
            let mut path = format!("/v1/spaces/{}/diff", encode_path_segment(&source));
            let mut query = Vec::new();
            if let Some(target) = target {
                if source.parse::<Uuid>().is_ok() && target.parse::<Uuid>().is_ok() {
                    query.push(format!("from={}", encode_query_value(&source)));
                    query.push(format!("to={}", encode_query_value(&target)));
                } else {
                    query.push(format!("from={}", encode_query_value(&target)));
                }
            }
            if all {
                query.push("all=1".to_owned());
            }
            query.push(format!("limit={limit}"));
            path.push('?');
            path.push_str(&query.join("&"));
            let data = response_value(request_json(client, "GET", &path, None)?)?;
            print_diff(&data);
        }
        Command::Checkout { space, commit } => {
            let data = response_value(request_json(
                client,
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
        Command::Fork { commit, name, ttl } => {
            let data = response_value(request_json(
                client,
                "POST",
                &format!("/v1/commits/{commit}/fork"),
                Some(fork_space_body(&name, ttl)),
            )?)?;
            print_space_summary(&data);
        }
        Command::Lease { space, ttl, clear } => {
            let data = response_value(request_json(
                client,
                "PATCH",
                &format!("/v1/spaces/{}/lease", encode_path_segment(&space)),
                Some(lease_space_body(if clear { None } else { ttl })),
            )?)?;
            println!("expires_at: {}", expiry_text(data.get("expires_at")));
        }
        Command::RmCkpt { commit } => {
            let data = response_value(request_json(
                client,
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
            let data = response_value(request_json(
                client,
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
            let response = request_json(client, "GET", &path, None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_usage(&response_value_from_body(&body)?);
            }
        }
        Command::Limits {
            command: None,
            json,
        } => {
            let response = request_json(client, "GET", "/v1/limits", None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_limits(&response_value_from_body(&body)?);
            }
        }
        Command::Limits {
            command:
                Some(LimitsCommand::Set {
                    project,
                    spaces,
                    disk_mib,
                    running,
                    api_per_min,
                    inherit,
                }),
            json,
        } => {
            let path = format!("/v1/projects/{}/limits", encode_path_segment(&project));
            let response = request_json(
                client,
                "PATCH",
                &path,
                Some(limits_set_body(
                    spaces,
                    disk_mib,
                    running,
                    api_per_min,
                    &inherit,
                )?),
            )?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                print_limits(&response_value_from_body(&body)?);
            }
        }
        Command::Limits {
            command: Some(LimitsCommand::Clear { project }),
            json,
        } => {
            let path = format!("/v1/projects/{}/limits", encode_path_segment(&project));
            let response = request_json(client, "DELETE", &path, None)?;
            let body = successful_body(response)?;
            if json {
                print_raw_json(&body)?;
            } else {
                println!("cleared limits for {project}");
            }
        }
        Command::Token { .. } => {
            return Err("token commands must be handled without an HTTP endpoint".to_string());
        }
    }
    Ok(0)
}

fn usage_path(from: Option<i64>, to: Option<i64>) -> String {
    match (from, to) {
        (None, None) => "/v1/usage".to_owned(),
        (Some(from), None) => format!("/v1/usage?from={from}"),
        (None, Some(to)) => format!("/v1/usage?to={to}"),
        (Some(from), Some(to)) => format!("/v1/usage?from={from}&to={to}"),
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
    // MiB-hour usage is fractional for short-lived spaces; preserve the fraction.
    println!(
        "disk_mib_hour: {:.2}",
        data.get("disk_mib_hour")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
    );
    println!(
        "api_calls: {}",
        value_u64(data.get("api_calls")).unwrap_or(0)
    );
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
    println!("max_mem_mib: {}", human_mib(data.get("max_mem_mib")));
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
    println!(
        "api_per_min: {}",
        value_u64(data.get("api_per_min")).unwrap_or(0)
    );
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
                        record
                            .created_at
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
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

fn response_value(response: Response) -> Result<Value, String> {
    response_value_from_body(&successful_body(response)?)
}

fn successful_body(response: Response) -> Result<Vec<u8>, String> {
    response
        .into_success()
        .map(|response| response.body)
        .map_err(|error| error.to_string())
}

fn response_value_from_body(body: &[u8]) -> Result<Value, String> {
    if body.is_empty() {
        Ok(Value::Null)
    } else {
        serde_json::from_slice(body).map_err(|error| format!("invalid JSON response: {error}"))
    }
}

fn write_raw_json(output: &mut impl Write, body: &[u8]) -> Result<(), String> {
    let text =
        std::str::from_utf8(body).map_err(|error| format!("invalid UTF-8 response: {error}"))?;
    output
        .write_all(text.as_bytes())
        .map_err(|error| error.to_string())?;
    if !text.ends_with('\n') {
        output.write_all(b"\n").map_err(|error| error.to_string())?;
    }
    output.flush().map_err(|error| error.to_string())
}

fn print_raw_json(body: &[u8]) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_raw_json(&mut output, body)
}

fn job_command_text(value: &Value) -> String {
    let Some(command) = value.get("command").and_then(Value::as_array) else {
        return "-".to_owned();
    };
    if command.is_empty() {
        return "-".to_owned();
    }
    command.iter().map(value_text).collect::<Vec<_>>().join(" ")
}

fn job_rows(data: &Value) -> Vec<Vec<String>> {
    data.get("jobs")
        .and_then(Value::as_array)
        .map(|jobs| {
            jobs.iter()
                .map(|job| {
                    vec![
                        field_text(job, "id"),
                        field_text(job, "space"),
                        field_text(job, "state"),
                        seconds(&field_text(job, "created_at")),
                        seconds(&field_text(job, "started_at")),
                        seconds(&field_text(job, "finished_at")),
                        field_text(job, "exit_code"),
                        job_command_text(job),
                    ]
                })
                .collect()
        })
        .unwrap_or_default()
}

fn print_jobs(data: &Value) -> Result<(), String> {
    let rows = job_rows(data);
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_table(
        &mut output,
        &[
            "ID", "SPACE", "STATE", "CREATED", "STARTED", "FINISHED", "EXIT", "COMMAND",
        ],
        &rows,
    )
    .map_err(|error| error.to_string())
}

fn write_job_status(output: &mut impl Write, data: &Value) -> io::Result<()> {
    writeln!(output, "state: {}", field_text(data, "state"))?;
    writeln!(
        output,
        "created: {}",
        seconds(&field_text(data, "created_at"))
    )?;
    writeln!(
        output,
        "started: {}",
        seconds(&field_text(data, "started_at"))
    )?;
    writeln!(
        output,
        "finished: {}",
        seconds(&field_text(data, "finished_at"))
    )?;
    writeln!(output, "exit: {}", field_text(data, "exit_code"))?;
    writeln!(output, "error: {}", field_text(data, "error"))
}

fn print_job_status(data: &Value) -> Result<(), String> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    write_job_status(&mut output, data).map_err(|error| error.to_string())
}

fn write_job_logs(
    data: &Value,
    output: &mut impl Write,
    errors: &mut impl Write,
) -> Result<(), String> {
    let log = data
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| "job logs response is missing string data".to_string())?;
    output
        .write_all(log.as_bytes())
        .map_err(|error| error.to_string())?;
    output.flush().map_err(|error| error.to_string())?;
    if data
        .get("log_truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let retained = value_u64(data.get("log_bytes")).unwrap_or(0);
        writeln!(errors, "warning: job log truncated to {retained} bytes")
            .map_err(|error| error.to_string())?;
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
                        if image.get("built").and_then(Value::as_bool).unwrap_or(false) {
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
fn print_network(data: &Value, name: &str) -> Result<(), String> {
    shinu::state::validate_network_name(Some(name)).map_err(|error| error.to_string())?;
    let config = shinu::NetConfig::from_env().map_err(|error| error.to_string())?;
    let rows = data
        .get("spaces")
        .and_then(Value::as_array)
        .map(|spaces| {
            spaces
                .iter()
                .filter(|space| space.get("network").and_then(Value::as_str) == Some(name))
                .map(|space| {
                    let guest_ip = space
                        .get("id")
                        .and_then(Value::as_str)
                        .and_then(|id| Uuid::parse_str(id).ok())
                        .and_then(|id| shinu::net_spec(id, &config))
                        .and_then(|spec| spec.guest_cidr.strip_suffix("/30").map(str::to_owned))
                        .unwrap_or_else(|| "-".to_string());
                    vec![field_text(space, "name"), guest_ip]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    println!("network: {name}");
    table(&["NAME", "GUEST IP"], &rows);
    Ok(())
}

const SPACE_HEADERS: &[&str] = &[
    "NAME",
    "NETWORK",
    "PROJECT",
    "STATE",
    "HEAD",
    "EXCLUSIVE",
    "CREATED",
    "EXPIRES",
    "IMAGE",
    "VCPU",
    "MEM",
    "DISK",
];

fn space_rows(data: &Value) -> Vec<Vec<String>> {
    data.get("spaces")
        .and_then(Value::as_array)
        .map(|spaces| {
            spaces
                .iter()
                .map(|space| {
                    vec![
                        field_text(space, "name"),
                        space
                            .get("network")
                            .and_then(Value::as_str)
                            .map(str::to_owned)
                            .unwrap_or_else(|| "-".to_string()),
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
                        expiry_text(space.get("expires_at")),
                        field_text(space, "image"),
                        short_optional_value(space.get("vcpus")),
                        human_mib(space.get("mem_mib")),
                        human_mib(space.get("disk_mib")),
                    ]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn print_spaces(data: &Value) {
    let rows = space_rows(data);
    table(SPACE_HEADERS, &rows);
    if let Some(ckpts) = data.get("ckpts").and_then(Value::as_array) {
        println!();
        let rows = ckpts
            .iter()
            .map(|ckpt| {
                let note = field_text(ckpt, "note");
                let note = if ckpt.get("auto").and_then(Value::as_bool).unwrap_or(false) {
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
fn print_diff(data: &Value) {
    if let Some(entries) = data.get("entries").and_then(Value::as_array) {
        for entry in entries {
            println!(
                "{} {}",
                field_text(entry, "status"),
                field_text(entry, "path")
            );
        }
    }
    let summary = data.get("summary");
    let added = value_u64(summary.and_then(|value| value.get("added"))).unwrap_or(0);
    let removed = value_u64(summary.and_then(|value| value.get("removed"))).unwrap_or(0);
    let modified = value_u64(summary.and_then(|value| value.get("modified"))).unwrap_or(0);
    let total = value_u64(summary.and_then(|value| value.get("total"))).unwrap_or(0);
    println!("summary: +{added} -{removed} M{modified} ({total} total)");
    if data
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        let limit = value_u64(data.get("limit")).unwrap_or(0);
        println!("output truncated at {limit} entries");
    }
}

fn print_checkpoint_list(data: &Value, key: &str) {
    if let Some(commits) = data.get(key).and_then(Value::as_array) {
        for commit in commits {
            let note = field_text(commit, "note");
            let note = if commit.get("auto").and_then(Value::as_bool).unwrap_or(false) {
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
    match value {
        None | Some(Value::Null) => "-".to_owned(),
        Some(Value::String(value)) => short_id(value),
        Some(value) => short_id(&value_text(value)),
    }
}

fn short_optional_value(value: Option<&Value>) -> String {
    short_id_value(value)
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

#[expect(
    clippy::cast_precision_loss,
    reason = "Human-readable byte formatting intentionally rounds through f64 to preserve existing output."
)]
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
        .map(|date| {
            date.with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
        })
        .unwrap_or_else(|_| value.to_owned())
}

fn expiry_text(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "never".to_owned(),
        Some(Value::String(value)) => seconds(value),
        Some(value) => {
            let value = value_text(value);
            seconds(&value)
        }
    }
}

fn write_table(output: &mut impl Write, headers: &[&str], rows: &[Vec<String>]) -> io::Result<()> {
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
            write!(output, "  ")?;
        }
        if index + 1 == headers.len() {
            write!(output, "{header}")?;
        } else {
            write!(output, "{header:<width$}", width = widths[index])?;
        }
    }
    writeln!(output)?;
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            if index > 0 {
                write!(output, "  ")?;
            }
            if index + 1 == row.len() {
                write!(output, "{cell}")?;
            } else {
                write!(output, "{cell:<width$}", width = widths[index])?;
            }
        }
        writeln!(output)?;
    }
    Ok(())
}

fn table(headers: &[&str], rows: &[Vec<String>]) {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let _ = write_table(&mut output, headers, rows);
}

fn stream_ndjson(
    response: &mut ResponseStream,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<i32, String> {
    let mut pending = Vec::new();
    let mut exit_code = None;
    response
        .stream_body(|fragment| {
            feed_ndjson(fragment, &mut pending, &mut exit_code, stdout, stderr)
                .map_err(shinu_client::Error::from)
        })
        .map_err(|error| {
            let message = error.to_string();
            if message == "HTTP response body ended before Content-Length" {
                "exec HTTP body ended before Content-Length".to_owned()
            } else {
                message
            }
        })?;

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
        let line = std::str::from_utf8(&pending[..position])
            .map_err(|error| format!("invalid UTF-8 in exec response: {error}"))?
            .trim_end_matches('\r');
        if !line.trim().is_empty()
            && let Some(code) = dispatch_ndjson_line(line, stdout, stderr)?
            && exit_code.replace(code).is_some()
        {
            return Err("exec response contained multiple exit statuses".to_string());
        }
        pending.drain(..=position);
    }
    Ok(())
}

fn dispatch_ndjson_line<'a>(
    line: &str,
    stdout: &'a mut dyn Write,
    stderr: &'a mut dyn Write,
) -> Result<Option<i32>, String> {
    let value: Value =
        serde_json::from_str(line).map_err(|error| format!("invalid NDJSON line: {error}"))?;
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
        if !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&exit) {
            return Err(format!("exec exit status is out of range: {exit}"));
        }
        let exit_code =
            i32::try_from(exit).map_err(|_| format!("exec exit status is out of range: {exit}"))?;
        return Ok(Some(exit_code));
    }
    Err("exec NDJSON line must contain stream or exit".to_string())
}

fn find_token_index(tokens: &[Token], prefix: &str) -> Result<usize, String> {
    if prefix.is_empty() {
        return Err("hash prefix must not be empty".to_string());
    }
    let mut match_index = None;
    for (index, token) in tokens.iter().enumerate() {
        if !token.hash.starts_with(prefix) {
            continue;
        }
        if match_index.is_some() {
            return Err(format!(
                "hash prefix {prefix:?} matches multiple tokens; provide a longer prefix"
            ));
        }
        match_index = Some(index);
    }
    match_index.ok_or_else(|| format!("no token matches hash prefix {prefix:?}"))
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
    fn rejects_control_characters_in_endpoint_base_path() {
        assert!(Endpoint::parse("http://127.0.0.1:7878/base\r\nX-Injected: yes").is_err());
    }

    #[test]
    fn create_body_omits_unspecified_optional_fields() {
        let body = create_space_body("dev", None, None, None, None, None, None);
        assert_eq!(body, json!({"name": "dev"}));
        assert!(body.get("image").is_none());
        assert!(body.get("vcpus").is_none());
        assert!(body.get("mem_mib").is_none());
        assert!(body.get("disk_mib").is_none());
    }
    #[test]
    fn create_body_includes_network_when_requested() {
        let body = create_space_body("dev", None, None, None, None, Some("lan".into()), None);
        assert_eq!(body, json!({"name": "dev", "network": "lan"}));
    }

    #[test]
    fn parses_ttl_duration_units_and_checked_boundaries() {
        assert_eq!(parse_ttl_duration("1s"), Ok(1));
        assert_eq!(parse_ttl_duration("2m"), Ok(120));
        assert_eq!(parse_ttl_duration("3h"), Ok(10_800));
        assert_eq!(parse_ttl_duration("4d"), Ok(345_600));
        assert_eq!(parse_ttl_duration("18446744073709551615s"), Ok(u64::MAX));
        assert!(parse_ttl_duration("18446744073709551615m").is_err());
    }

    #[test]
    fn rejects_non_positive_or_non_integer_ttl_durations() {
        for raw in [
            "", "0s", "00m", "-1s", "+1s", "1.5s", "1", "1w", "1S", "1 s", "1s ",
        ] {
            assert!(
                parse_ttl_duration(raw).is_err(),
                "accepted invalid TTL {raw:?}"
            );
        }
    }

    #[test]
    fn parses_ttl_on_new_and_uuid_fork_commands() {
        let cli =
            Cli::try_parse_from(["shinu", "new", "dev", "--ttl", "2h"]).expect("parse new TTL");
        match cli.command {
            Command::New { ttl, .. } => assert_eq!(ttl, Some(7_200)),
            _ => panic!("unexpected command parsed"),
        }

        let cli = Cli::try_parse_from([
            "shinu",
            "fork",
            "00000000-0000-0000-0000-000000000000",
            "branch",
            "--ttl",
            "1d",
        ])
        .expect("parse fork TTL");
        match cli.command {
            Command::Fork { ttl, .. } => assert_eq!(ttl, Some(86_400)),
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn lease_requires_exactly_one_ttl_or_clear_flag() {
        assert!(Cli::try_parse_from(["shinu", "lease", "dev"]).is_err());
        assert!(Cli::try_parse_from(["shinu", "lease", "dev", "--ttl", "1m", "--clear"]).is_err());

        let cli =
            Cli::try_parse_from(["shinu", "lease", "dev", "--ttl", "1m"]).expect("parse lease TTL");
        match cli.command {
            Command::Lease { space, ttl, clear } => {
                assert_eq!(space, "dev");
                assert_eq!(ttl, Some(60));
                assert!(!clear);
            }
            _ => panic!("unexpected command parsed"),
        }

        let cli =
            Cli::try_parse_from(["shinu", "lease", "dev", "--clear"]).expect("parse lease clear");
        match cli.command {
            Command::Lease { ttl, clear, .. } => {
                assert!(ttl.is_none());
                assert!(clear);
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn ttl_request_bodies_preserve_omission_and_encode_clear_as_null() {
        assert_eq!(
            create_space_body("dev", None, None, None, None, None, Some(90)),
            json!({"name": "dev", "ttl_seconds": 90})
        );
        assert_eq!(fork_space_body("branch", None), json!({"name": "branch"}));
        assert_eq!(
            fork_space_body("branch", Some(90)),
            json!({"name": "branch", "ttl_seconds": 90})
        );
        assert_eq!(lease_space_body(Some(90)), json!({"ttl_seconds": 90}));
        assert_eq!(lease_space_body(None), json!({"ttl_seconds": null}));
    }

    #[test]
    fn renders_canonical_expiry_and_never_in_human_space_list() {
        let data = json!({
            "spaces": [
                {
                    "name": "leased",
                    "created_at": "2026-08-31T10:00:00+00:00",
                    "expires_at": "2026-08-31T12:34:56+02:00"
                },
                {
                    "name": "unleased",
                    "created_at": "2026-08-31T10:00:00+00:00",
                    "expires_at": null
                }
            ]
        });
        let rows = space_rows(&data);
        assert_eq!(rows[0][6], "2026-08-31T10:00:00Z");
        assert_eq!(rows[0][7], "2026-08-31T10:34:56Z");
        assert_eq!(rows[1][7], "never");

        let mut output = Vec::new();
        write_table(&mut output, SPACE_HEADERS, &rows).expect("write spaces table");
        let output = String::from_utf8(output).expect("UTF-8 spaces table");
        assert!(
            output
                .lines()
                .next()
                .unwrap_or_default()
                .contains("EXPIRES")
        );
        assert!(output.contains("never"));
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
    fn limits_set_body_maps_unlimited_and_inherit() {
        let inherit = vec!["disk-mib".to_owned()];
        let body = limits_set_body(
            Some("unlimited".into()),
            None,
            Some("3".into()),
            None,
            &inherit,
        )
        .expect("limit payload");
        assert_eq!(
            body,
            json!({
                "max_spaces": 0,
                "max_disk_mib": null,
                "max_running": 3
            })
        );
    }

    #[test]
    fn limits_set_body_requires_a_change_and_rejects_conflicts() {
        assert!(limits_set_body(None, None, None, None, &[]).is_err());
        let inherit = vec!["spaces".to_owned()];
        assert!(limits_set_body(Some("4".into()), None, None, None, &inherit).is_err());
    }

    #[test]
    fn parses_nested_limits_set_command() {
        let cli = Cli::try_parse_from([
            "shinu",
            "limits",
            "set",
            "project-a",
            "--spaces",
            "unlimited",
            "--inherit",
            "disk-mib",
        ])
        .expect("parse limits set command");
        match cli.command {
            Command::Limits {
                command:
                    Some(LimitsCommand::Set {
                        project,
                        spaces,
                        disk_mib,
                        inherit,
                        ..
                    }),
                json,
            } => {
                assert_eq!(project, "project-a");
                assert_eq!(spaces.as_deref(), Some("unlimited"));
                assert!(disk_mib.is_none());
                assert_eq!(inherit, vec!["disk-mib"]);
                assert!(!json);
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn parses_exec_session_flag_before_command_separator() {
        let cli = Cli::try_parse_from([
            "shinu",
            "exec",
            "demo",
            "--session",
            "agent_1",
            "--",
            "cd",
            "/tmp",
        ])
        .expect("parse exec session command");
        match cli.command {
            Command::Exec {
                space,
                session,
                cmd,
                stdin,
            } => {
                assert_eq!(space, "demo");
                assert_eq!(session.as_deref(), Some("agent_1"));
                assert_eq!(cmd, vec!["cd", "/tmp"]);
                assert!(stdin.is_none());
            }
            _ => panic!("unexpected command parsed"),
        }
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
    fn parses_job_run_with_stdin_and_command_separator() {
        let cli = Cli::try_parse_from([
            "shinu",
            "job",
            "run",
            "demo",
            "--stdin",
            "input.txt",
            "--",
            "printf",
            "%s",
            "hello",
        ])
        .expect("parse job run command");
        match cli.command {
            Command::Job {
                command: JobCommand::Run { space, stdin, cmd },
            } => {
                assert_eq!(space, "demo");
                assert_eq!(stdin.as_deref(), Some("input.txt"));
                assert_eq!(cmd, vec!["printf", "%s", "hello"]);
            }
            _ => panic!("unexpected command parsed"),
        }
    }

    #[test]
    fn rejects_invalid_job_uuid_in_clap_parse_path() {
        let parsed = Cli::try_parse_from(["shinu", "job", "status", "not-a-uuid"]);
        let error = match parsed {
            Ok(_) => panic!("invalid UUID unexpectedly parsed"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("invalid value"));
    }

    #[test]
    fn job_run_body_includes_command_and_optional_stdin() {
        let path = std::env::temp_dir().join(format!("shinu-job-stdin-{}", Uuid::new_v4()));
        std::fs::write(&path, "input\n").expect("write job stdin fixture");
        let path_text = path.to_string_lossy().into_owned();
        let body = job_run_body(&["cat".to_owned()], Some(&path_text)).expect("job body");
        std::fs::remove_file(path).expect("remove job stdin fixture");
        assert_eq!(body, json!({"cmd": ["cat"], "stdin": "input\n"}));
    }

    #[test]
    fn maps_terminal_job_states_to_wait_statuses() {
        assert_eq!(job_wait_status(&json!({"state": "starting"})), Ok(None));
        assert_eq!(job_wait_status(&json!({"state": "running"})), Ok(None));
        assert_eq!(job_wait_status(&json!({"state": "canceling"})), Ok(None));
        assert_eq!(
            job_wait_status(&json!({"state": "exited", "exit_code": 17})),
            Ok(Some(17))
        );
        assert_eq!(job_wait_status(&json!({"state": "canceled"})), Ok(Some(1)));
        assert_eq!(job_wait_status(&json!({"state": "lost"})), Ok(Some(1)));
    }

    #[test]
    fn raw_json_and_job_logs_preserve_output_contracts() {
        let mut raw = Vec::new();
        write_raw_json(&mut raw, br#"{"jobs":[]}"#).expect("write raw JSON");
        assert_eq!(raw, b"{\"jobs\":[]}\n");

        let mut output = Vec::new();
        let mut errors = Vec::new();
        write_job_logs(
            &json!({
                "data": "line 1\nline 2",
                "log_bytes": 13,
                "log_truncated": true
            }),
            &mut output,
            &mut errors,
        )
        .expect("write job logs");
        assert_eq!(output, b"line 1\nline 2");
        assert!(
            String::from_utf8(errors)
                .expect("UTF-8 warning")
                .contains("truncated")
        );
    }

    #[test]
    fn renders_job_status_fields_and_stable_list_rows() {
        let status = json!({
            "state": "exited",
            "created_at": "2026-08-31T10:00:00+00:00",
            "started_at": "2026-08-31T10:00:01+00:00",
            "finished_at": "2026-08-31T10:00:02+00:00",
            "exit_code": 3,
            "error": null
        });
        let mut rendered = Vec::new();
        write_job_status(&mut rendered, &status).expect("write job status");
        let rendered = String::from_utf8(rendered).expect("UTF-8 status");
        assert!(rendered.contains("state: exited"));
        assert!(rendered.contains("exit: 3"));
        assert!(rendered.contains("finished: 2026-08-31T10:00:02Z"));

        let rows = job_rows(&json!({
            "jobs": [{
                "id": "job-id",
                "space": "space-id",
                "state": "running",
                "created_at": "2026-08-31T10:00:00+00:00",
                "command": ["echo", "hello"]
            }]
        }));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], "job-id");
        assert_eq!(rows[0][1], "space-id");
        assert_eq!(rows[0][2], "running");
        assert_eq!(rows[0][7], "echo hello");
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
