use serde_json::{json, Map, Value};
use shinu::shell_quote_word;
use std::env;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:7878";
const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "shinu-mcp";

struct Server {
    endpoint: String,
    token: Option<String>,
}

impl Server {
    fn from_env() -> Self {
        let endpoint = env::var("SHINU_ENDPOINT")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
        let token = env::var("SHINU_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        Self { endpoint, token }
    }

    fn client(&self) -> Result<HttpClient, String> {
        let token = self.token.as_deref().ok_or_else(|| {
            "SHINU_TOKEN is not configured; set SHINU_TOKEN to a Shinu API bearer token before calling a tool"
                .to_string()
        })?;
        if token.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err("SHINU_TOKEN must not contain carriage returns or newlines".to_string());
        }
        Ok(HttpClient {
            endpoint: Endpoint::parse(&self.endpoint)?,
            token: token.to_string(),
        })
    }

    fn execute_tool(&self, name: &str, arguments: &Map<String, Value>) -> Result<String, String> {
        let client = self.client()?;
        match name {
            "shinu_list_spaces" => client.request_text("GET", "/v1/spaces", None),
            "shinu_list_images" => client.request_text("GET", "/v1/images", None),
            "shinu_create_space" => {
                let name = required_string(arguments, "name")?;
                let body = create_space_body(name, arguments)?;
                client.request_text("POST", "/v1/spaces", Some(body))
            }
            "shinu_resize_space" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}", encode_path_segment(&space));
                let body = resize_space_body(arguments)?;
                client.request_text("PATCH", &path, Some(body))
            }
            "shinu_start" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}/start", encode_path_segment(&space));
                client.request_text("POST", &path, None)
            }
            "shinu_stop" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}/stop", encode_path_segment(&space));
                client.request_text("POST", &path, None)
            }
            "shinu_write_file" => {
                let space = required_string(arguments, "space")?;
                let path = required_string(arguments, "path")?;
                let content = required_text(arguments, "content")?;
                let command = vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("cat > {}", shell_quote_word(&path)),
                ];
                let request_path = format!(
                    "/v1/spaces/{}/exec",
                    encode_path_segment(&space)
                );
                let response = client.request(
                    "POST",
                    &request_path,
                    Some(json!({ "cmd": command, "stdin": content })),
                )?;
                if !(200..300).contains(&response.status) {
                    return Err(http_error(response.status, &response.body));
                }
                aggregate_exec(&response.body)
            }
            "shinu_read_file" => {
                let space = required_string(arguments, "space")?;
                let path = required_string(arguments, "path")?;
                let command = vec!["cat".to_string(), path];
                let request_path = format!(
                    "/v1/spaces/{}/exec",
                    encode_path_segment(&space)
                );
                let response = client.request(
                    "POST",
                    &request_path,
                    Some(json!({ "cmd": command })),
                )?;
                if !(200..300).contains(&response.status) {
                    return Err(http_error(response.status, &response.body));
                }
                aggregate_stdout(&response.body)
            }
            "shinu_exec" => {
                let space = required_string(arguments, "space")?;
                let command = required_command(arguments)?;
                let path = format!(
                    "/v1/spaces/{}/exec",
                    encode_path_segment(&space)
                );
                let response = client.request("POST", &path, Some(json!({ "cmd": command })))?;
                if !(200..300).contains(&response.status) {
                    return Err(http_error(response.status, &response.body));
                }
                aggregate_exec(&response.body)
            }
            "shinu_commit" => {
                let space = required_string(arguments, "space")?;
                let note = required_string(arguments, "note")?;
                let hot = required_bool(arguments, "hot")?;
                let full = required_bool(arguments, "full")?;
                let path = format!(
                    "/v1/spaces/{}/commits",
                    encode_path_segment(&space)
                );
                client.request_text(
                    "POST",
                    &path,
                    Some(json!({ "note": note, "hot": hot, "full": full })),
                )
            }
            "shinu_log" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}/log", encode_path_segment(&space));
                client.request_text("GET", &path, None)
            }
            "shinu_reflog" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}/reflog", encode_path_segment(&space));
                client.request_text("GET", &path, None)
            }
            "shinu_checkout" => {
                let space = required_string(arguments, "space")?;
                let commit = required_string(arguments, "commit")?;
                let path = format!(
                    "/v1/spaces/{}/checkout",
                    encode_path_segment(&space)
                );
                client.request_text(
                    "POST",
                    &path,
                    Some(json!({ "commit": commit })),
                )
            }
            "shinu_fork" => {
                let commit = required_string(arguments, "commit")?;
                let name = required_string(arguments, "name")?;
                let path = format!(
                    "/v1/commits/{}/fork",
                    encode_path_segment(&commit)
                );
                client.request_text("POST", &path, Some(json!({ "name": name })))
            }
            "shinu_delete_space" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}", encode_path_segment(&space));
                client.request_text("DELETE", &path, None)
            }
            _ => Err(format!("unknown Shinu tool {name}")),
        }
    }
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
            return Err("SHINU_ENDPOINT must not be empty".to_string());
        }
        if input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err("SHINU_ENDPOINT must not contain whitespace or control characters".to_string());
        }
        let remainder = if let Some(value) = input.strip_prefix("http://") {
            value
        } else if input.starts_with("https://") {
            return Err(
                "HTTPS endpoints are not supported by the stdio client; use an HTTP endpoint behind the configured proxy"
                    .to_string(),
            );
        } else if input.contains("://") {
            return Err("SHINU_ENDPOINT must use the http:// scheme".to_string());
        } else {
            input
        };
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        if authority.is_empty() {
            return Err("SHINU_ENDPOINT must contain a host".to_string());
        }
        let (host, port) = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .ok_or_else(|| "IPv6 endpoint is missing the closing ']'".to_string())?;
            let host = &authority[1..end];
            if host.is_empty() {
                return Err("SHINU_ENDPOINT host must not be empty".to_string());
            }
            let suffix = &authority[end + 1..];
            let port = if suffix.is_empty() {
                80
            } else {
                let port = suffix
                    .strip_prefix(':')
                    .ok_or_else(|| "invalid SHINU_ENDPOINT port".to_string())?;
                parse_port(port)?
            };
            (host.to_string(), port)
        } else if authority.matches(':').count() > 1 {
            return Err(
                "IPv6 SHINU_ENDPOINT values must use bracket notation, for example http://[::1]:7878"
                    .to_string(),
            );
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.is_empty() {
                return Err("SHINU_ENDPOINT host must not be empty".to_string());
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
        .map_err(|_| format!("invalid SHINU_ENDPOINT port {value:?}"))?;
    if port == 0 {
        return Err("SHINU_ENDPOINT port must be between 1 and 65535".to_string());
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
        let body = read_body(&mut reader, &head.headers)?;
        Ok(HttpResponse {
            status: head.status,
            body,
        })
    }

    fn request_text(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<String, String> {
        let response = self.request(method, path, body)?;
        if !(200..300).contains(&response.status) {
            return Err(http_error(response.status, &response.body));
        }
        body_text(&response.body)
    }

    fn open_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<(BufReader<TcpStream>, ResponseHead), String> {
        let mut stream = TcpStream::connect(self.endpoint.connect_address())
            .map_err(|error| format!("could not connect to {}: {error}", self.endpoint.authority))?;
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
            stream
                .write_all(body)
                .map_err(|error| error.to_string())?;
        }
        stream.flush().map_err(|error| error.to_string())?;
        let mut reader = BufReader::new(stream);
        let head = read_response_head(&mut reader)?;
        Ok((reader, head))
    }
}

fn required_string(arguments: &Map<String, Value>, field: &str) -> Result<String, String> {
    match arguments.get(field) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.clone()),
        Some(Value::String(_)) => Err(format!("argument {field} must not be empty")),
        Some(_) => Err(format!("argument {field} must be a string")),
        None => Err(format!("missing required argument {field}")),
    }
}
fn required_text(arguments: &Map<String, Value>, field: &str) -> Result<String, String> {
    match arguments.get(field) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(format!("argument {field} must be a string")),
        None => Err(format!("missing required argument {field}")),
    }
}


fn required_bool(arguments: &Map<String, Value>, field: &str) -> Result<bool, String> {
    arguments
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| match arguments.get(field) {
            Some(_) => format!("argument {field} must be a boolean"),
            None => format!("missing required argument {field}"),
        })
}

fn optional_string(arguments: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    match arguments.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(format!("argument {field} must not be empty")),
        Some(_) => Err(format!("argument {field} must be a string")),
    }
}

fn optional_u64(arguments: &Map<String, Value>, field: &str) -> Result<Option<u64>, String> {
    match arguments.get(field) {
        None => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("argument {field} must be a non-negative integer")),
        Some(_) => Err(format!("argument {field} must be a non-negative integer")),
    }
}

fn create_space_body(
    name: String,
    arguments: &Map<String, Value>,
) -> Result<Value, String> {
    let mut body = json!({"name": name});
    let object = body
        .as_object_mut()
        .expect("create space body starts as a JSON object");
    if let Some(image) = optional_string(arguments, "image")? {
        object.insert("image".to_string(), Value::String(image));
    }
    if let Some(vcpus) = optional_u64(arguments, "vcpus")? {
        object.insert("vcpus".to_string(), Value::from(vcpus));
    }
    if let Some(mem_mib) = optional_u64(arguments, "mem_mib")? {
        object.insert("mem_mib".to_string(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = optional_u64(arguments, "disk_mib")? {
        object.insert("disk_mib".to_string(), Value::from(disk_mib));
    }
    Ok(body)
}

fn resize_space_body(arguments: &Map<String, Value>) -> Result<Value, String> {
    let vcpus = optional_u64(arguments, "vcpus")?;
    let mem_mib = optional_u64(arguments, "mem_mib")?;
    let disk_mib = optional_u64(arguments, "disk_mib")?;
    if vcpus.is_none() && mem_mib.is_none() && disk_mib.is_none() {
        return Err("resize requires at least one of vcpus, mem_mib, or disk_mib".to_string());
    }
    let mut body = Value::Object(Map::new());
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


fn required_command(arguments: &Map<String, Value>) -> Result<Vec<String>, String> {
    let value = arguments
        .get("cmd")
        .ok_or_else(|| "missing required argument cmd".to_string())?;
    let values = value
        .as_array()
        .ok_or_else(|| "argument cmd must be an array of strings".to_string())?;
    if values.is_empty() {
        return Err("argument cmd must contain at least one command argument".to_string());
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("argument cmd[{index}] must be a string"))
        })
        .collect()
}

fn validate_arguments(name: &str, arguments: &Map<String, Value>) -> Result<(), String> {
    match name {
        "shinu_list_spaces" | "shinu_list_images" => Ok(()),
        "shinu_create_space" => {
            required_string(arguments, "name")?;
            optional_string(arguments, "image")?;
            optional_u64(arguments, "vcpus")?;
            optional_u64(arguments, "mem_mib")?;
            optional_u64(arguments, "disk_mib")?;
            Ok(())
        }
        "shinu_resize_space" => {
            required_string(arguments, "space")?;
            resize_space_body(arguments)?;
            Ok(())
        }
        "shinu_start" | "shinu_stop" => {
            required_string(arguments, "space")?;
            Ok(())
        }
        "shinu_write_file" => {
            required_string(arguments, "space")?;
            required_string(arguments, "path")?;
            required_text(arguments, "content")?;
            Ok(())
        }
        "shinu_read_file" => {
            required_string(arguments, "space")?;
            required_string(arguments, "path")?;
            Ok(())
        }
        "shinu_exec" => {
            required_string(arguments, "space")?;
            required_command(arguments)?;
            Ok(())
        }
        "shinu_commit" => {
            required_string(arguments, "space")?;
            required_string(arguments, "note")?;
            required_bool(arguments, "hot")?;
            required_bool(arguments, "full")?;
            Ok(())
        }
        "shinu_log" | "shinu_reflog" => {
            required_string(arguments, "space")?;
            Ok(())
        }
        "shinu_checkout" => {
            required_string(arguments, "space")?;
            required_string(arguments, "commit")?;
            Ok(())
        }
        "shinu_fork" => {
            required_string(arguments, "commit")?;
            required_string(arguments, "name")?;
            Ok(())
        }
        "shinu_delete_space" => {
            required_string(arguments, "space")?;
            Ok(())
        }
        _ => Err(format!("unknown Shinu tool {name}")),
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

fn body_text(body: &[u8]) -> Result<String, String> {
    std::str::from_utf8(body)
        .map(str::to_owned)
        .map_err(|error| format!("HTTP response was not valid UTF-8: {error}"))
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

fn aggregate_exec(body: &[u8]) -> Result<String, String> {
    let text = body_text(body)?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit = None;
    for (index, raw_line) in text.split('\n').enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid exec NDJSON line {}: {error}", index + 1))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("exec NDJSON line {} must be a JSON object", index + 1))?;
        if let Some(stream) = object.get("stream") {
            let stream = stream.as_str().ok_or_else(|| {
                format!("exec stream on NDJSON line {} must be a string", index + 1)
            })?;
            let data = object
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("exec stream on NDJSON line {} is missing string data", index + 1)
                })?;
            match stream {
                "stdout" => stdout.push_str(data),
                "stderr" => stderr.push_str(data),
                _ => return Err(format!("unknown exec stream {stream:?}")),
            }
        } else if let Some(value) = object.get("exit") {
            let code = value
                .as_i64()
                .ok_or_else(|| format!("exec exit on NDJSON line {} must be an integer", index + 1))?;
            if exit.replace(code).is_some() {
                return Err("exec response contained multiple exit statuses".to_string());
            }
        } else {
            return Err(format!(
                "exec NDJSON line {} must contain stream or exit",
                index + 1
            ));
        }
    }
    let exit = exit.ok_or_else(|| "exec response did not include an exit status".to_string())?;
    let mut result = String::from("stdout:\n");
    result.push_str(&stdout);
    if !stdout.ends_with('\n') {
        result.push('\n');
    }
    result.push_str("stderr:\n");
    result.push_str(&stderr);
    if !stderr.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&format!("exit: {exit}"));
    Ok(result)
}
fn aggregate_stdout(body: &[u8]) -> Result<String, String> {
    let text = body_text(body)?;
    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut exit = None;
    for (index, raw_line) in text.split('\n').enumerate() {
        let line = raw_line.trim_end_matches('\r');
        if line.trim().is_empty() {
            continue;
        }
        let value: Value = serde_json::from_str(line)
            .map_err(|error| format!("invalid exec NDJSON line {}: {error}", index + 1))?;
        let object = value
            .as_object()
            .ok_or_else(|| format!("exec NDJSON line {} must be a JSON object", index + 1))?;
        if let Some(stream) = object.get("stream") {
            let stream = stream.as_str().ok_or_else(|| {
                format!("exec stream on NDJSON line {} must be a string", index + 1)
            })?;
            let data = object
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!("exec stream on NDJSON line {} is missing string data", index + 1)
                })?;
            match stream {
                "stdout" => stdout.push_str(data),
                "stderr" => stderr.push_str(data),
                _ => return Err(format!("unknown exec stream {stream:?}")),
            }
        } else if let Some(value) = object.get("exit") {
            let code = value
                .as_i64()
                .ok_or_else(|| format!("exec exit on NDJSON line {} must be an integer", index + 1))?;
            if exit.replace(code).is_some() {
                return Err("exec response contained multiple exit statuses".to_string());
            }
        } else {
            return Err(format!(
                "exec NDJSON line {} must contain stream or exit",
                index + 1
            ));
        }
    }
    let exit = exit.ok_or_else(|| "exec response did not include an exit status".to_string())?;
    if exit != 0 {
        if stderr.is_empty() {
            return Err(format!("guest command exited with status {exit}"));
        }
        return Err(format!("guest command exited with status {exit}: {stderr}"));
    }
    Ok(stdout)
}

fn parse_port_status(line: &str) -> Result<u16, String> {
    let mut fields = line.trim_end_matches(&['\r', '\n'][..]).splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("unsupported HTTP status line: {line:?}"));
    }
    let code = fields
        .next()
        .ok_or_else(|| "HTTP status line is missing a status code".to_string())?;
    let status = code
        .parse::<u16>()
        .map_err(|error| format!("invalid HTTP status code {code:?}: {error}"))?;
    if !(100..=599).contains(&status) {
        return Err(format!("invalid HTTP status code: {status}"));
    }
    Ok(status)
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
    let status = parse_port_status(&status_line)?;
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
        reader
            .read_exact(&mut body)
            .map_err(|error| error.to_string())?;
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

fn schema(properties: Value, required: &[&str]) -> Value {
    json!({
        "type": "object",
        "properties": properties,
        "required": required,
    })
}

fn tool_definitions() -> Vec<Value> {
    vec![
        json!({
            "name": "shinu_list_spaces",
            "description": "在需要选择工作区、检查运行状态或查看当前 HEAD 与磁盘占用时使用；它返回当前项目可见的全部 space。",
            "inputSchema": schema(json!({}), &[]),
        }),
        json!({
            "name": "shinu_list_images",
            "description": "在创建 space 前查看可用的 guest image 及其构建状态；它只列出固定的 void、ubuntu、arch、rocky image。",
            "inputSchema": schema(json!({}), &[]),
        }),
        json!({
            "name": "shinu_create_space",
            "description": "在开始一个需要隔离的实验、需要独立分支或需要并行比较方案时使用；它创建一个新的命名 space。image 只在创建时设定，之后不可更换。",
            "inputSchema": schema(json!({
                "name": {"type": "string", "minLength": 1, "description": "新 space 的名称。"},
                "image": {"type": "string", "enum": ["void", "ubuntu", "arch", "rocky"], "description": "guest image；只在创建时设定，之后固定。"},
                "vcpus": {"type": "integer", "minimum": 1, "description": "该 space 的 vCPU 数量；省略时使用 daemon 默认值。"},
                "mem_mib": {"type": "integer", "minimum": 1, "description": "该 space 的内存上限，单位 MiB；省略时使用 daemon 默认值。"},
                "disk_mib": {"type": "integer", "minimum": 1, "description": "该 space 的磁盘容量，单位 MiB；省略时使用 daemon 默认值。"}
            }), &["name"]),
        }),
        json!({
            "name": "shinu_resize_space",
            "description": "调整 space 的 vCPU、内存或磁盘；space 必须处于 STOPPED 状态，先调用 shinu_stop。至少提供一个尺寸参数；磁盘只能增大、不能缩小，因为缩小会造成数据丢失。image 在创建时固定，不能通过 resize 更换。",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "space": {"type": "string", "minLength": 1, "description": "要调整的 space。"},
                    "vcpus": {"type": "integer", "minimum": 1, "description": "新的 vCPU 数量。"},
                    "mem_mib": {"type": "integer", "minimum": 1, "description": "新的内存上限，单位 MiB。"},
                    "disk_mib": {"type": "integer", "minimum": 1, "description": "新的磁盘容量，单位 MiB；只能增大，不能缩小。"}
                },
                "required": ["space"],
                "anyOf": [
                    {"required": ["vcpus"]},
                    {"required": ["mem_mib"]},
                    {"required": ["disk_mib"]}
                ]
            },
        }),
        json!({
            "name": "shinu_start",
            "description": "在需要执行命令或继续实验时启动已停止的 space；需要 commit 或 checkout 时不要用它替代 shinu_stop。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要启动的 space。"}
            }), &["space"]),
        }),
        json!({
            "name": "shinu_stop",
            "description": "在 commit 或 checkout 前停止 space；这是满足后端停止状态要求的明确方式。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要停止的 space。"}
            }), &["space"]),
        }),
        json!({
            "name": "shinu_write_file",
            "description": "向 space 写入文本文件；此工具仅支持 JSON 文本内容，不适合二进制载荷，二进制请使用 CLI shinu push。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "目标 space。"},
                "path": {"type": "string", "minLength": 1, "description": "guest 内目标文件路径。"},
                "content": {"type": "string", "description": "要写入的文本内容；不支持二进制数据。"}
            }), &["space", "path", "content"]),
        }),
        json!({
            "name": "shinu_read_file",
            "description": "从 space 读取文本文件并返回聚合后的 stdout；此工具仅支持文本，不适合二进制载荷，二进制请使用 CLI shinu pull。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "目标 space。"},
                "path": {"type": "string", "minLength": 1, "description": "guest 内要读取的文件路径。"}
            }), &["space", "path"]),
        }),
        json!({
            "name": "shinu_exec",
            "description": "在需要于隔离的 space 内执行不可信代码、构建命令或实验步骤时使用。响应会聚合 stdout、stderr 和退出码；长命令会一直阻塞到命令结束，因此不要用它期待流式的中间响应。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要执行命令的 space。"},
                "cmd": {"type": "array", "minItems": 1, "items": {"type": "string"}, "description": "命令及其参数，数组第一个元素是可执行文件。"}
            }), &["space", "cmd"]),
        }),
        json!({
            "name": "shinu_commit",
            "description": "在需要把当前实验状态存成可回滚的检查点、或在下一轮试错前保留安全副本时使用；hot 与 full 都必须显式选择，full 检查点需要 space 正在运行并会保存 guest 内存与进程状态。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要存档的 space。"},
                "note": {"type": "string", "minLength": 1, "description": "描述这个存档用途的非空备注。"},
                "hot": {"type": "boolean", "description": "是否创建 hot commit。"},
                "full": {"type": "boolean", "description": "是否同时保存 guest 内存与 CPU 状态；需要 space 正在运行。"}
            }), &["space", "note", "hot", "full"]),
        }),
        json!({
            "name": "shinu_log",
            "description": "在需要查看 space 的显式 commit 历史、判断可回滚目标或理解当前分支来源时使用。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要查看历史的 space。"}
            }), &["space"]),
        }),
        json!({
            "name": "shinu_reflog",
            "description": "在 checkout、试错或清理后找不到原来的状态时使用；reflog 能帮助定位被丢弃的 head 和自动存档。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要查看 reflog 的 space。"}
            }), &["space"]),
        }),
        json!({
            "name": "shinu_checkout",
            "description": "在需要把 space 回滚到某个 commit、复现旧状态或从安全存档继续试错时使用；space 必须先停止，先调用 shinu_stop；commit 必须使用完整 UUID，列表中显示的 8 字符短 ID 会被拒绝；checkout 前会自动存档当前状态，所以回滚是安全的，必要时可通过 reflog 找回它。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要切换状态的 space。"},
                "commit": {"type": "string", "minLength": 1, "description": "目标 commit 的 ID。"}
            }), &["space", "commit"]),
        }),
        json!({
            "name": "shinu_fork",
            "description": "在需要从已知的 commit 开出并行实验、保留原 space 不变或比较多个方案时使用；它从该存档创建新的 space。",
            "inputSchema": schema(json!({
                "commit": {"type": "string", "minLength": 1, "description": "作为新 space 起点的 commit ID。"},
                "name": {"type": "string", "minLength": 1, "description": "新 space 的名称。"}
            }), &["commit", "name"]),
        }),
        json!({
            "name": "shinu_delete_space",
            "description": "在一个实验完成、确认不再需要其状态并需要释放 space 与配额时使用；删除前先确认重要状态已 commit 或 fork。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要删除的 space。"}
            }), &["space"]),
        }),
    ]
}

fn is_known_tool(name: &str) -> bool {
    matches!(
        name,
        "shinu_list_spaces"
            | "shinu_list_images"
            | "shinu_create_space"
            | "shinu_resize_space"
            | "shinu_start"
            | "shinu_stop"
            | "shinu_write_file"
            | "shinu_read_file"
            | "shinu_exec"
            | "shinu_commit"
            | "shinu_log"
            | "shinu_reflog"
            | "shinu_checkout"
            | "shinu_fork"
            | "shinu_delete_space"
    )
}

fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_error(id: Value, code: i32, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message.into()}
    })
}

fn tool_result(text: String, is_error: bool) -> Value {
    json!({
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    })
}

fn valid_id(value: Option<&Value>) -> bool {
    value.is_none_or(|value| matches!(value, Value::Null | Value::String(_) | Value::Number(_)))
}

fn dispatch(server: &Server, request: &Map<String, Value>, id: Value) -> Value {
    if request.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return rpc_error(id, -32600, "Invalid Request");
    }
    let Some(method) = request.get("method").and_then(Value::as_str) else {
        return rpc_error(id, -32600, "Invalid Request");
    };
    match method {
        "initialize" => {
            if let Some(params) = request.get("params")
                && !params.is_object()
            {
                return rpc_error(id, -32602, "Invalid params: initialize params must be an object");
            }
            rpc_result(
                id,
                json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION")},
                }),
            )
        }
        "tools/list" => {
            if let Some(params) = request.get("params")
                && !params.is_object()
            {
                return rpc_error(id, -32602, "Invalid params: tools/list params must be an object");
            }
            rpc_result(id, json!({"tools": tool_definitions()}))
        }
        "tools/call" => {
            let Some(params) = request.get("params").and_then(Value::as_object) else {
                return rpc_error(id, -32602, "Invalid params: tools/call params must be an object");
            };
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return rpc_error(id, -32602, "Invalid params: tools/call requires a string name");
            };
            if !is_known_tool(name) {
                return rpc_error(id, -32602, format!("Invalid params: unknown tool {name}"));
            }
            let arguments = match params.get("arguments") {
                None => Map::new(),
                Some(Value::Object(arguments)) => arguments.clone(),
                Some(_) => {
                    return rpc_error(
                        id,
                        -32602,
                        "Invalid params: tools/call arguments must be an object",
                    );
                }
            };
            if let Err(error) = validate_arguments(name, &arguments) {
                return rpc_error(id, -32602, format!("Invalid params: {error}"));
            }
            match server.execute_tool(name, &arguments) {
                Ok(text) => rpc_result(id, tool_result(text, false)),
                Err(error) => rpc_result(id, tool_result(error, true)),
            }
        }
        _ => rpc_error(id, -32601, "Method not found"),
    }
}

fn write_response(output: &mut impl Write, response: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, response)
        .map_err(|error| io::Error::other(error.to_string()))?;
    output.write_all(b"\n")?;
    output.flush()
}

fn handle_line(server: &Server, line: &str, output: &mut impl Write) -> io::Result<()> {
    let value = match serde_json::from_str::<Value>(line) {
        Ok(value) => value,
        Err(_) => return write_response(output, &rpc_error(Value::Null, -32700, "Parse error")),
    };
    let Some(request) = value.as_object() else {
        return write_response(output, &rpc_error(Value::Null, -32600, "Invalid Request"));
    };
    let has_id = request.contains_key("id");
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let envelope_valid = request.get("jsonrpc").and_then(Value::as_str) == Some("2.0")
        && request.get("method").and_then(Value::as_str).is_some()
        && valid_id(request.get("id"));
    if !envelope_valid {
        return write_response(output, &rpc_error(Value::Null, -32600, "Invalid Request"));
    }
    let response = dispatch(server, request, id);
    if has_id {
        write_response(output, &response)?;
    }
    Ok(())
}

fn main() {
    let server = Server::from_env();
    let stdin = io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = stdout.lock();
    // stdout is the JSON-RPC protocol channel; diagnostics on it would corrupt framing, so logs stay on stderr.
    for line in input.by_ref().lines() {
        match line {
            Ok(line) if line.trim().is_empty() => continue,
            Ok(line) => {
                if let Err(error) = handle_line(&server, &line, &mut output) {
                    eprintln!("shinu-mcp: could not write JSON-RPC response: {error}");
                    break;
                }
            }
            Err(error) => {
                eprintln!("shinu-mcp: could not read JSON-RPC request: {error}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(value: Value) -> Map<String, Value> {
        value
            .as_object()
            .expect("test arguments must be an object")
            .clone()
    }

    #[test]
    fn validates_lifecycle_and_file_tools() {
        assert!(validate_arguments("shinu_start", &arguments(json!({"space": "dev"}))).is_ok());
        assert!(validate_arguments("shinu_stop", &arguments(json!({"space": "dev"}))).is_ok());
        assert!(validate_arguments(
            "shinu_write_file",
            &arguments(json!({"space": "dev", "path": "/tmp/note", "content": ""}))
        )
        .is_ok());
        assert!(validate_arguments(
            "shinu_read_file",
            &arguments(json!({"space": "dev", "path": "/tmp/note"}))
        )
        .is_ok());

        assert!(validate_arguments("shinu_start", &Map::new()).is_err());
        assert!(validate_arguments(
            "shinu_write_file",
            &arguments(json!({"space": "dev", "path": "/tmp/note"}))
        )
        .is_err());
        assert!(validate_arguments(
            "shinu_read_file",
            &arguments(json!({"space": "dev", "path": 7}))
        )
        .is_err());
    }

    #[test]
    fn validates_image_and_resize_tools() {
        assert!(validate_arguments("shinu_list_images", &Map::new()).is_ok());
        assert!(validate_arguments(
            "shinu_resize_space",
            &arguments(json!({"space": "dev", "mem_mib": 2048}))
        )
        .is_ok());
        assert!(validate_arguments(
            "shinu_resize_space",
            &arguments(json!({"space": "dev"}))
        )
        .is_err());
        assert!(validate_arguments(
            "shinu_resize_space",
            &arguments(json!({"space": "dev", "disk_mib": "2048"}))
        )
        .is_err());
    }

    #[test]
    fn read_file_aggregation_returns_raw_stdout_and_reports_failures() {
        let output = aggregate_stdout(
            br#"{"stream":"stdout","data":"first\n"}
{"stream":"stdout","data":"second"}
{"exit":0}
"#,
        )
        .unwrap();
        assert_eq!(output, "first\nsecond");

        let error = aggregate_stdout(
            br#"{"stream":"stderr","data":"cat: missing\n"}
{"exit":1}
"#,
        )
        .unwrap_err();
        assert!(error.contains("cat: missing"));
        assert!(error.contains("status 1"));
    }

    #[test]
    fn known_tools_match_tool_definitions() {
        let definitions = tool_definitions();
        assert_eq!(definitions.len(), 15);
        for definition in definitions {
            let name = definition
                .get("name")
                .and_then(Value::as_str)
                .expect("tool definition name");
            assert!(is_known_tool(name), "tool {name} missing from known-tool match");
        }
    }
}
