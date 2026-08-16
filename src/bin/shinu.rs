use chrono::Utc;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};
use shinu::token::{self, Token};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
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
    },
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
    Exec {
        space: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    Commit {
        space: String,
        #[arg(long)]
        note: String,
        #[arg(long)]
        hot: bool,
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
        let stream = TcpStream::connect(self.endpoint.connect_address())
            .map_err(|error| format!("could not connect to {}: {error}", self.endpoint.authority))?;
        let mut stream = stream;
        let target = self.endpoint.target(path);
        let content_length = body.map_or(0, <[u8]>::len);
        let content_type = if body.is_some() {
            "Content-Type: application/json\r\n"
        } else {
            ""
        };
        let request = format!(
            "{method} {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n{content_type}Content-Length: {content_length}\r\n\r\n",
            self.endpoint.authority, self.token
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| error.to_string())?;
        if let Some(body) = body {
            stream.write_all(body).map_err(|error| error.to_string())?;
        }
        stream.flush().map_err(|error| error.to_string())?;

        let mut reader = BufReader::new(stream);
        let head = read_response_head(&mut reader)?;
        Ok((reader, head))
    }

    fn stream_exec(&self, space: &str, command: &[String]) -> Result<i32, String> {
        let body = json!({ "cmd": command });
        let (mut reader, head) = self.open_request(
            "POST",
            &format!("/v1/spaces/{}/exec", encode_path_segment(space)),
            Some(&serde_json::to_vec(&body).map_err(|error| error.to_string())?),
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

fn run_command(client: &HttpClient, command: Command) -> Result<i32, String> {
    match command {
        Command::New { name } => {
            let data = response_value(client.request(
                "POST",
                "/v1/spaces",
                Some(json!({ "name": name })),
            )?)?;
            print_space_summary(&data);
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
        Command::Exec { space, cmd } => {
            return client.stream_exec(&space, &cmd);
        }
        Command::Commit { space, note, hot } => {
            let data = response_value(client.request(
                "POST",
                &format!("/v1/spaces/{}/commits", encode_path_segment(&space)),
                Some(json!({ "note": note, "hot": hot })),
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
        Command::Token { .. } => {
            return Err("token commands must be handled without an HTTP endpoint".to_string());
        }
    }
    Ok(0)
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
                    ]
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    table(
        &["NAME", "PROJECT", "STATE", "HEAD", "EXCLUSIVE", "CREATED"],
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
        let mut chunk = vec![0u8; size];
        reader
            .read_exact(&mut chunk)
            .map_err(|error| error.to_string())?;
        let mut line_end = [0u8; 2];
        reader
            .read_exact(&mut line_end)
            .map_err(|error| error.to_string())?;
        if line_end != *b"\r\n" {
            return Err("chunked HTTP body is missing its CRLF".to_string());
        }
        on_chunk(&chunk)?;
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
