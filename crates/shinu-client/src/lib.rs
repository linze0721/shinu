//! Synchronous HTTP/1.1 transport shared by the CLI and MCP entry points.
//!
//! This crate deliberately stops at the transport boundary. Callers own JSON
//! command payloads, response presentation, and any protocol layered on top of
//! HTTP. Body readers accept callbacks so a caller can stream bytes without
//! first collecting the response.

use serde_json::Value;
use std::borrow::Cow;
use std::env;
use std::fmt;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpStream;

/// The endpoint used when `SHINU_ENDPOINT` is not configured.
pub const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:7878";
const MAX_RAW_RESPONSE_HEADERS: usize = 64 * 1024;
const BODY_BUFFER_SIZE: usize = 8192;

/// Errors returned by the shared transport.
#[derive(Debug)]
pub enum Error {
    /// An operating-system I/O error.
    Io(io::Error),
    /// A TCP connection error with the destination retained for diagnostics.
    Connect {
        authority: String,
        source: io::Error,
    },
    /// A malformed endpoint, response, or body framing condition.
    Invalid(String),
    /// A non-successful HTTP response, retaining its body for presentation.
    Http { status: u16, body: Vec<u8> },
}

impl Error {
    /// Construct a transport validation error.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    /// Construct an error for a non-successful HTTP response.
    pub fn http(status: u16, body: Vec<u8>) -> Self {
        Self::Http { status, body }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => fmt::Display::fmt(error, formatter),
            Self::Connect { authority, source } => {
                write!(formatter, "could not connect to {authority}: {source}")
            }
            Self::Invalid(message) => formatter.write_str(message),
            Self::Http { status, body } => formatter.write_str(&http_error(*status, body)),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Connect { source, .. } => Some(source),
            Self::Invalid(_) | Self::Http { .. } => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<String> for Error {
    fn from(message: String) -> Self {
        Self::Invalid(message)
    }
}

/// Result type used by transport operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Return the configured endpoint string, using the standard local default.
pub fn endpoint_value_from_env() -> String {
    env::var("SHINU_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned())
}
/// Return the configured endpoint string without treating an explicitly empty
/// environment value as missing.
pub fn endpoint_value_from_env_preserving_empty() -> String {
    env::var("SHINU_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_owned())
}

/// Parsed HTTP endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    authority: String,
    port: u16,
    base_path: String,
}

impl Endpoint {
    /// Parse an endpoint using the CLI's established error wording.
    pub fn parse(input: &str) -> Result<Self> {
        Self::parse_inner(input, false)
    }

    /// Parse an endpoint using the MCP environment variable's established
    /// error wording.
    pub fn parse_environment(input: &str) -> Result<Self> {
        Self::parse_inner(input, true)
    }

    /// Read `SHINU_ENDPOINT`, falling back to [`DEFAULT_ENDPOINT`].
    pub fn from_env() -> Result<Self> {
        Self::parse_environment(&endpoint_value_from_env())
    }

    fn parse_inner(input: &str, environment_wording: bool) -> Result<Self> {
        let input = input.trim();
        let field = if environment_wording {
            "SHINU_ENDPOINT"
        } else {
            "endpoint"
        };
        if input.is_empty() {
            return Err(Error::invalid(format!("{field} must not be empty")));
        }
        if input
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(Error::invalid(if environment_wording {
                "SHINU_ENDPOINT must not contain whitespace or control characters".to_owned()
            } else {
                "endpoint must not contain whitespace or control characters".to_owned()
            }));
        }
        let remainder = if let Some(value) = input.strip_prefix("http://") {
            value
        } else if input.starts_with("https://") {
            return Err(Error::invalid(if environment_wording {
                "HTTPS endpoints are not supported by the stdio client; use an HTTP endpoint behind the configured proxy".to_owned()
            } else {
                "HTTPS endpoints are not supported; use an http:// endpoint".to_owned()
            }));
        } else if input.contains("://") {
            return Err(Error::invalid(format!(
                "{field} must use the http:// scheme"
            )));
        } else {
            input
        };
        let (authority, path) = remainder
            .split_once('/')
            .map_or((remainder, ""), |(authority, path)| (authority, path));
        if path
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(Error::invalid(if environment_wording {
                "SHINU_ENDPOINT must not contain whitespace or control characters".to_owned()
            } else {
                "endpoint must not contain whitespace or control characters".to_owned()
            }));
        }
        if authority.is_empty()
            || authority
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(Error::invalid(if environment_wording {
                "SHINU_ENDPOINT must contain a host".to_owned()
            } else {
                "endpoint must contain a valid host".to_owned()
            }));
        }

        let (host, port) = if authority.starts_with('[') {
            let end = authority
                .find(']')
                .ok_or_else(|| Error::invalid("IPv6 endpoint is missing the closing ']'"))?;
            let host = &authority[1..end];
            if host.is_empty() {
                return Err(Error::invalid(if environment_wording {
                    "SHINU_ENDPOINT host must not be empty".to_owned()
                } else {
                    "endpoint host must not be empty".to_owned()
                }));
            }
            let suffix = &authority[end + 1..];
            let port = if suffix.is_empty() {
                80
            } else {
                let port = suffix.strip_prefix(':').ok_or_else(|| {
                    Error::invalid(if environment_wording {
                        "invalid SHINU_ENDPOINT port".to_owned()
                    } else {
                        "invalid endpoint port".to_owned()
                    })
                })?;
                parse_port(port, environment_wording)?
            };
            (host.to_owned(), port)
        } else if authority.matches(':').count() > 1 {
            return Err(Error::invalid(if environment_wording {
                "IPv6 SHINU_ENDPOINT values must use bracket notation, for example http://[::1]:7878".to_owned()
            } else {
                "IPv6 endpoints must use bracket notation, for example http://[::1]:7878".to_owned()
            }));
        } else if let Some((host, port)) = authority.rsplit_once(':') {
            if host.is_empty() {
                return Err(Error::invalid(if environment_wording {
                    "SHINU_ENDPOINT host must not be empty".to_owned()
                } else {
                    "endpoint host must not be empty".to_owned()
                }));
            }
            (host.to_owned(), parse_port(port, environment_wording)?)
        } else {
            (authority.to_owned(), 80)
        };

        let base_path = if path.is_empty() {
            String::new()
        } else {
            format!("/{}", path.trim_matches('/'))
        };
        Ok(Self {
            host,
            authority: authority.to_owned(),
            port,
            base_path,
        })
    }

    /// Return the host used to establish the TCP connection.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Return the original authority used in the HTTP `Host` header.
    pub fn authority(&self) -> &str {
        &self.authority
    }

    /// Return the parsed TCP port.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Join a request path to the endpoint's optional base path.
    pub fn target<'a>(&self, path: &'a str) -> Cow<'a, str> {
        if self.base_path.is_empty() && path.starts_with('/') {
            return Cow::Borrowed(path);
        }
        let mut target = String::with_capacity(self.base_path.len() + path.len() + 1);
        target.push_str(&self.base_path);
        if !path.starts_with('/') {
            target.push('/');
        }
        target.push_str(path);
        Cow::Owned(target)
    }

    /// Return the address accepted by [`TcpStream::connect`].
    pub fn connect_address(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

fn parse_port(value: &str, environment_wording: bool) -> Result<u16> {
    let port = value.parse::<u16>().map_err(|_| {
        Error::invalid(if environment_wording {
            format!("invalid SHINU_ENDPOINT port {value:?}")
        } else {
            format!("invalid endpoint port {value:?}")
        })
    })?;
    if port == 0 {
        return Err(Error::invalid(if environment_wording {
            "SHINU_ENDPOINT port must be between 1 and 65535".to_owned()
        } else {
            "endpoint port must be between 1 and 65535".to_owned()
        }));
    }
    Ok(port)
}

/// A bearer-authenticated HTTP client.
#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
    token: String,
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("endpoint", &self.endpoint)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Client {
    /// Construct a client for an already-parsed endpoint and bearer token.
    pub fn new(endpoint: Endpoint, token: impl Into<String>) -> Result<Self> {
        let token = token.into();
        if token.is_empty() {
            return Err(Error::invalid(
                "missing bearer token; create one with `shinu token new --project <id>` and set SHINU_TOKEN or pass --token",
            ));
        }
        if token.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err(Error::invalid(
                "token must not contain carriage returns or newlines",
            ));
        }
        Ok(Self { endpoint, token })
    }

    /// Send a request with an optional raw body and collect its response body.
    pub fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Response> {
        let mut response = self.open_request(method, path, body)?;
        let body = response.read_body()?;
        Ok(Response {
            status: response.head.status,
            headers: response.head.headers,
            body,
        })
    }

    /// Send a request, returning an error for any non-2xx response.
    pub fn request_checked(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<Response> {
        self.request(method, path, body)?.into_success()
    }

    /// Send a request, require a 2xx response, and decode it as UTF-8.
    pub fn request_text(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<String> {
        let response = self.request_checked(method, path, body)?;
        body_text(&response.body)
    }

    /// Start a request and parse its response head while retaining a buffered
    /// reader for streaming the response body.
    pub fn open_request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<ResponseStream> {
        let content_length = match body {
            Some(bytes) => u64::try_from(bytes.len())
                .map_err(|_| Error::invalid("request body is too large"))?,
            None => 0,
        };
        let mut stream = self.start_request(method, path, content_length, body.is_some())?;
        if let Some(body) = body {
            stream.write_all(body)?;
        }
        stream.flush()?;
        Self::read_response(stream)
    }

    /// Write only the request head and return the connected stream.
    ///
    /// This primitive is used for uploads whose body is copied directly from a
    /// file, so the upload never has to be collected in memory.
    pub fn start_request(
        &self,
        method: &str,
        path: &str,
        content_length: u64,
        json_body: bool,
    ) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(self.endpoint.connect_address()).map_err(|source| {
            Error::Connect {
                authority: self.endpoint.authority.clone(),
                source,
            }
        })?;
        write_request_head(
            &mut stream,
            &self.endpoint,
            &self.token,
            method,
            path,
            content_length,
            json_body,
        )?;
        Ok(stream)
    }

    /// Parse a response from a stream after the request body has been sent.
    pub fn read_response(stream: TcpStream) -> Result<ResponseStream> {
        let mut reader = BufReader::new(stream);
        let head = read_response_head(&mut reader)?;
        Ok(ResponseStream { head, reader })
    }

    /// Send a request and parse its head without buffering payload bytes.
    ///
    /// Unlike [`Self::open_request`], this returns the raw stream so a caller
    /// that upgrades into a bidirectional protocol (such as VNC) can preserve
    /// every payload byte after the HTTP header.
    pub fn open_raw_request(&self, method: &str, path: &str) -> Result<(TcpStream, ResponseHead)> {
        let mut stream = self.start_request(method, path, 0, false)?;
        let mut head_bytes = Vec::new();
        let mut byte = [0u8; 1];
        while head_bytes.len() < MAX_RAW_RESPONSE_HEADERS {
            let count = stream.read(&mut byte)?;
            if count == 0 {
                return Err(Error::invalid(
                    "HTTP response ended before the response headers",
                ));
            }
            head_bytes.push(byte[0]);
            if head_bytes.ends_with(b"\r\n\r\n") {
                let mut cursor = Cursor::new(head_bytes);
                let head = read_response_head(&mut cursor)?;
                return Ok((stream, head));
            }
        }
        Err(Error::invalid("HTTP response headers exceed 64 KiB"))
    }
}

fn write_request_head(
    writer: &mut impl Write,
    endpoint: &Endpoint,
    token: &str,
    method: &str,
    path: &str,
    content_length: u64,
    json_body: bool,
) -> io::Result<()> {
    let target = endpoint.target(path);
    let content_type = if json_body {
        "Content-Type: application/json\r\n"
    } else {
        ""
    };
    write!(
        writer,
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n{content_type}Content-Length: {content_length}\r\n\r\n",
        endpoint.authority
    )
}

/// Parsed response status and headers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseHead {
    /// HTTP status code.
    pub status: u16,
    /// Header names are normalized to lowercase; values retain their text.
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// Find a header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Return whether `Transfer-Encoding` contains `chunked`.
    pub fn is_chunked(&self) -> bool {
        self.header("transfer-encoding").is_some_and(|value| {
            value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
        })
    }

    /// Return whether the response has a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Parse the optional `Content-Length` header.
    pub fn content_length(&self) -> Result<Option<usize>> {
        self.header("content-length")
            .map(|value| {
                value
                    .parse::<usize>()
                    .map_err(|error| Error::invalid(format!("invalid Content-Length: {error}")))
            })
            .transpose()
    }
}

/// A response whose body can be consumed incrementally.
pub struct ResponseStream {
    head: ResponseHead,
    reader: BufReader<TcpStream>,
}

impl ResponseStream {
    /// Return the parsed response head.
    pub const fn head(&self) -> &ResponseHead {
        &self.head
    }

    /// Collect the response body according to its framing headers.
    pub fn read_body(&mut self) -> Result<Vec<u8>> {
        read_body(&mut self.reader, &self.head)
    }

    /// Stream body fragments to a callback without collecting the body.
    pub fn stream_body<F>(&mut self, on_chunk: F) -> Result<u64>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        stream_body(&mut self.reader, &self.head, on_chunk)
    }

    /// Recover the buffered reader and parsed head for a caller that needs
    /// lower-level access after consuming no payload bytes.
    pub fn into_parts(self) -> (BufReader<TcpStream>, ResponseHead) {
        (self.reader, self.head)
    }
}

/// A fully collected HTTP response.
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// HTTP status code.
    pub status: u16,
    /// Header names are normalized to lowercase; values retain their text.
    pub headers: Vec<(String, String)>,
    /// Response payload bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// Return whether the response has a 2xx status.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// Convert a non-2xx response into the shared HTTP error representation.
    pub fn into_success(self) -> Result<Self> {
        if self.is_success() {
            Ok(self)
        } else {
            Err(Error::http(self.status, self.body))
        }
    }
}

/// Read a response status line and headers from a buffered reader.
pub fn read_response_head<R: BufRead + ?Sized>(reader: &mut R) -> Result<ResponseHead> {
    let mut status_line = String::new();
    if reader.read_line(&mut status_line)? == 0 {
        return Err(Error::invalid("HTTP response ended before the status line"));
    }
    let status = parse_status_line(&status_line)?;
    let mut headers = Vec::new();
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(Error::invalid("HTTP response ended before the headers"));
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::invalid("malformed HTTP response header"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(ResponseHead { status, headers })
}

fn parse_status_line(line: &str) -> Result<u16> {
    let mut fields = line.trim_end_matches(&['\r', '\n'][..]).splitn(3, ' ');
    let version = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(Error::invalid(format!(
            "unsupported HTTP status line: {line:?}"
        )));
    }
    let code = fields
        .next()
        .ok_or_else(|| Error::invalid("HTTP status line is missing a status code"))?;
    if code.len() != 3 || !code.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::invalid(format!(
            "invalid HTTP status code: {code:?}"
        )));
    }
    let status = code
        .parse::<u16>()
        .map_err(|error| Error::invalid(format!("invalid HTTP status code: {error}")))?;
    if !(100..=599).contains(&status) {
        return Err(Error::invalid(format!(
            "invalid HTTP status code: {status}"
        )));
    }
    Ok(status)
}

/// Collect a body framed by chunked transfer encoding, Content-Length, or
/// connection close.
pub fn read_body<R: BufRead + ?Sized>(reader: &mut R, head: &ResponseHead) -> Result<Vec<u8>> {
    if head.is_chunked() {
        let mut body = Vec::new();
        stream_chunked(reader, &mut |chunk| {
            body.try_reserve(chunk.len())
                .map_err(|_| Error::invalid("HTTP response body is too large"))?;
            body.extend_from_slice(chunk);
            Ok(())
        })?;
        return Ok(body);
    }
    if let Some(length) = head.content_length()? {
        let mut body = Vec::new();
        body.try_reserve_exact(length)
            .map_err(|_| Error::invalid("HTTP response body is too large"))?;
        body.resize(length, 0);
        reader.read_exact(&mut body)?;
        return Ok(body);
    }
    let mut body = Vec::new();
    reader.read_to_end(&mut body)?;
    Ok(body)
}

/// Stream a body framed by chunked transfer encoding, Content-Length, or
/// connection close to a generic callback.
pub fn stream_body<R, F>(reader: &mut R, head: &ResponseHead, mut on_chunk: F) -> Result<u64>
where
    R: BufRead + ?Sized,
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut total = 0u64;
    let mut deliver = |chunk: &[u8]| {
        total = total
            .checked_add(
                u64::try_from(chunk.len())
                    .map_err(|_| Error::invalid("HTTP response body is too large"))?,
            )
            .ok_or_else(|| Error::invalid("HTTP response body is too large"))?;
        on_chunk(chunk)
    };
    if head.is_chunked() {
        stream_chunked(reader, &mut deliver)?;
    } else if let Some(length) = head.content_length()? {
        let mut remaining = length;
        let mut buffer = [0u8; BODY_BUFFER_SIZE];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            let count = reader.read(&mut buffer[..amount])?;
            if count == 0 {
                return Err(Error::invalid(
                    "HTTP response body ended before Content-Length",
                ));
            }
            deliver(&buffer[..count])?;
            remaining -= count;
        }
    } else {
        let mut buffer = [0u8; BODY_BUFFER_SIZE];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            deliver(&buffer[..count])?;
        }
    }
    Ok(total)
}

fn stream_chunked<R, F>(reader: &mut R, on_chunk: &mut F) -> Result<()>
where
    R: BufRead + ?Sized,
    F: FnMut(&[u8]) -> Result<()>,
{
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(Error::invalid(
                "chunked HTTP body ended before a chunk size",
            ));
        }
        let size_text = line
            .trim_end_matches(&['\r', '\n'][..])
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16).map_err(|error| {
            Error::invalid(format!("invalid chunk size {size_text:?}: {error}"))
        })?;
        if size == 0 {
            loop {
                line.clear();
                if reader.read_line(&mut line)? == 0 {
                    return Err(Error::invalid("chunked HTTP body ended before trailers"));
                }
                if line == "\r\n" || line == "\n" {
                    return Ok(());
                }
            }
        }

        let mut remaining = size;
        let mut buffer = [0u8; BODY_BUFFER_SIZE];
        while remaining > 0 {
            let amount = remaining.min(buffer.len());
            reader.read_exact(&mut buffer[..amount])?;
            on_chunk(&buffer[..amount])?;
            remaining -= amount;
        }
        let mut line_end = [0u8; 2];
        reader.read_exact(&mut line_end)?;
        if line_end != *b"\r\n" {
            return Err(Error::invalid("chunked HTTP body is missing its CRLF"));
        }
    }
}

/// Decode a response body as UTF-8 using the shared client wording.
pub fn body_text(body: &[u8]) -> Result<String> {
    std::str::from_utf8(body)
        .map(str::to_owned)
        .map_err(|error| Error::invalid(format!("HTTP response was not valid UTF-8: {error}")))
}

/// Format an HTTP failure while retaining JSON daemon error messages.
pub fn http_error(status: u16, body: &[u8]) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body)
        && let Some(message) = value.get("error").and_then(Value::as_str)
    {
        return format!("HTTP {status}: {message}");
    }
    let detail = String::from_utf8_lossy(body);
    let detail = detail.trim();
    if detail.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status}: {detail}")
    }
}

fn percent_encode(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }
    encoded
}

/// Percent-encode one path segment according to RFC 3986.
pub fn encode_path_segment(value: &str) -> String {
    percent_encode(value)
}

/// Percent-encode one query value according to RFC 3986.
pub fn encode_query_value(value: &str) -> String {
    percent_encode(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(status: u16, headers: &[(&str, &str)]) -> ResponseHead {
        ResponseHead {
            status,
            headers: headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn client_debug_output_redacts_bearer_token() {
        let endpoint = Endpoint::parse("http://127.0.0.1:7878").expect("endpoint");
        let client = Client::new(endpoint, "secret-token").expect("client");
        let debug = format!("{client:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret-token"));
    }

    #[test]
    fn endpoint_parsing_preserves_base_path_and_ipv6_target() {
        let endpoint = Endpoint::parse("http://[::1]:7878/base/").expect("endpoint");
        assert_eq!(endpoint.host(), "::1");
        assert_eq!(endpoint.authority(), "[::1]:7878");
        assert_eq!(endpoint.port(), 7878);
        assert_eq!(endpoint.target("/v1/spaces"), "/base/v1/spaces");
        assert_eq!(endpoint.connect_address(), "[::1]:7878");
    }

    #[test]
    fn endpoint_parsing_rejects_unsafe_and_invalid_forms() {
        for value in [
            "",
            "https://localhost",
            "ftp://localhost",
            "http://localhost:0",
            "http://localhost:65536",
            "http://[::1",
            "http://::1:7878",
            "http://localhost/base\r\nX-Injected: yes",
        ] {
            assert!(Endpoint::parse(value).is_err(), "accepted {value:?}");
        }
        assert!(
            Endpoint::parse_environment("https://localhost")
                .unwrap_err()
                .to_string()
                .contains("stdio client")
        );
    }

    #[test]
    fn request_head_bytes_match_daemon_client_contract() {
        let endpoint = Endpoint::parse("http://localhost:7878/base").expect("endpoint");
        let mut bytes = Vec::new();
        write_request_head(
            &mut bytes,
            &endpoint,
            "secret",
            "POST",
            "/v1/spaces",
            7,
            true,
        )
        .expect("request head");
        assert_eq!(
            bytes,
            b"POST /base/v1/spaces HTTP/1.1\r\nHost: localhost:7878\r\nAuthorization: Bearer secret\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n"
        );
    }

    #[test]
    fn response_head_and_content_length_body_are_shared() {
        let mut input = Cursor::new(
            b"HTTP/1.1 201 Created\r\nContent-Length: 7\r\nX-Test: yes\r\n\r\npayloadtrailing",
        );
        let parsed = read_response_head(&mut input).expect("response head");
        assert_eq!(parsed.status, 201);
        assert_eq!(parsed.header("X-TEST"), Some("yes"));
        assert_eq!(read_body(&mut input, &parsed).expect("body"), b"payload");
    }

    #[test]
    fn chunked_body_supports_extensions_and_trailers_without_collecting() {
        let mut input =
            Cursor::new(b"4;first=yes\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: value\r\n\r\n");
        let parsed = head(200, &[("transfer-encoding", "chunked")]);
        let mut chunks = Vec::new();
        let total = stream_body(&mut input, &parsed, |chunk| {
            chunks.push(chunk.to_owned());
            Ok(())
        })
        .expect("chunked body");
        assert_eq!(total, 9);
        assert_eq!(chunks, vec![b"Wiki".to_vec(), b"pedia".to_vec()]);
    }

    #[test]
    fn close_delimited_body_is_read_to_eof() {
        let mut input = Cursor::new(b"close body");
        let parsed = head(200, &[]);
        assert_eq!(read_body(&mut input, &parsed).expect("body"), b"close body");
    }

    #[test]
    fn malformed_response_framing_is_rejected() {
        assert!(read_response_head(&mut Cursor::new(b"HTTP/2 200 OK\r\n\r\n")).is_err());
        let parsed = head(200, &[("content-length", "not-a-number")]);
        assert!(read_body(&mut Cursor::new(b"body"), &parsed).is_err());
        let parsed = head(200, &[("transfer-encoding", "chunked")]);
        assert!(stream_body(&mut Cursor::new(b"4\r\nno\r\n"), &parsed, |_| Ok(())).is_err());
    }

    #[test]
    fn percent_encoding_covers_reserved_and_non_ascii_bytes() {
        let value = "/root/a b?x&y=#%é";
        assert_eq!(
            encode_path_segment(value),
            "%2Froot%2Fa%20b%3Fx%26y%3D%23%25%C3%A9"
        );
        assert_eq!(
            encode_query_value(value),
            "%2Froot%2Fa%20b%3Fx%26y%3D%23%25%C3%A9"
        );
    }

    #[test]
    fn shared_http_errors_preserve_daemon_json_and_plain_text() {
        assert_eq!(
            http_error(404, br#"{"error":"missing"}"#),
            "HTTP 404: missing"
        );
        assert_eq!(
            http_error(502, b"  upstream failed\n"),
            "HTTP 502: upstream failed"
        );
        assert_eq!(
            Error::http(404, br#"{"error":"missing"}"#.to_vec()).to_string(),
            "HTTP 404: missing"
        );
    }
}
