use std::io::{self, BufRead, Write};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_HEADERS: usize = 100;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub token: Option<String>,
    pub body: Vec<u8>,
    pub cookies: std::collections::HashMap<String, String>,
    pub origin: Option<String>,
    pub forwarded_proto: Option<String>,
    pub host: Option<String>,
}

fn invalid(message: impl Into<String>) -> shinu_core::Error {
    shinu_core::Error::Invalid(message.into())
}

fn ascii_case_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn is_ows(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value.iter().position(|byte| !is_ows(*byte)).unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !is_ows(*byte))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn read_line<R: BufRead + ?Sized>(
    stream: &mut R,
    total: &mut usize,
) -> shinu_core::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let available = stream.fill_buf()?;
        if available.is_empty() {
            if line.is_empty() {
                return Ok(None);
            }
            return Err(invalid("incomplete HTTP line"));
        }

        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        // Inspect the buffered bytes before extending the line so a peer
        // cannot make the parser allocate without bound by omitting '\n'.
        if *total > MAX_HEADER_BYTES
            || take > MAX_HEADER_BYTES.saturating_sub(*total)
        {
            return Err(invalid("HTTP request line and headers exceed 64 KiB"));
        }
        line.extend_from_slice(&available[..take]);
        stream.consume(take);
        *total += take;
        if newline.is_some() {
            return Ok(Some(line));
        }
    }
}

fn line_content(line: &[u8]) -> shinu_core::Result<&[u8]> {
    if line.last().copied() != Some(b'\n') {
        return Err(invalid("HTTP line is not terminated"));
    }
    let mut end = line.len() - 1;
    if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    if line[..end].contains(&b'\r') {
        return Err(invalid("HTTP line contains an embedded carriage return"));
    }
    Ok(&line[..end])
}

fn bytes_to_string(bytes: &[u8], field: &str) -> shinu_core::Result<String> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| invalid(format!("HTTP {field} is not valid UTF-8")))
}

fn bearer_token(value: &[u8]) -> Option<String> {
    let value = trim_ows(value);
    if value.len() < 6 || !ascii_case_eq(&value[..6], b"Bearer") {
        return None;
    }
    let rest = &value[6..];
    if rest.first().copied().is_none_or(|byte| !is_ows(byte)) {
        return None;
    }
    let token = rest
        .iter()
        .position(|byte| !is_ows(*byte))
        .map_or(&[][..], |start| &rest[start..]);
    if token.is_empty()
        || token
            .iter()
            .any(|byte| *byte <= b' ' || *byte == 0x7f)
    {
        return None;
    }
    String::from_utf8(token.to_vec()).ok()
}

pub fn parse_cookies(header: &str) -> std::collections::HashMap<String, String> {
    let mut cookies = std::collections::HashMap::new();
    for part in header.split(';') {
        let part = part.trim();
        let Some((name, value)) = part.split_once('=') else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        // Split only at the first equals sign: cookie values may contain
        // additional equals signs even though session tokens do not.
        cookies.insert(name.to_owned(), value.trim().to_owned());
    }
    cookies
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub path: String,
    pub token: Option<String>,
    pub content_length: Option<usize>,
    pub cookies: std::collections::HashMap<String, String>,
    pub origin: Option<String>,
    pub forwarded_proto: Option<String>,
    pub host: Option<String>,
}

impl RequestHead {
    pub fn into_request(self, body: Vec<u8>) -> Request {
        Request {
            method: self.method,
            path: self.path,
            token: self.token,
            body,
            cookies: self.cookies,
            origin: self.origin,
            forwarded_proto: self.forwarded_proto,
            host: self.host,
        }
    }
}

fn parse_head_inner(
    stream: &mut impl BufRead,
    max_body_bytes: Option<usize>,
) -> shinu_core::Result<RequestHead> {
    let mut header_bytes = 0;
    let request_line = read_line(stream, &mut header_bytes)?
        .ok_or_else(|| invalid("missing HTTP request line"))?;
    let request_line = line_content(&request_line)?;
    let mut fields = request_line.split(|byte| *byte == b' ');
    let method = fields
        .next()
        .ok_or_else(|| invalid("missing HTTP method"))?;
    let path = fields
        .next()
        .ok_or_else(|| invalid("missing HTTP path"))?;
    let version = fields
        .next()
        .ok_or_else(|| invalid("missing HTTP version"))?;
    if fields.next().is_some()
        || method.is_empty()
        || method.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
        || path.is_empty()
        || path.iter().any(|byte| *byte <= b' ' || *byte == 0x7f)
        || version != b"HTTP/1.1"
    {
        return Err(invalid("malformed HTTP request line"));
    }

    let method = bytes_to_string(method, "method")?;
    let path = bytes_to_string(path, "path")?;
    let mut token = None;
    let mut cookies = std::collections::HashMap::new();
    let mut origin = None;
    let mut forwarded_proto = None;
    let mut host = None;
    let mut content_length = None;
    let mut header_count = 0;
    loop {
        let line = read_line(stream, &mut header_bytes)?
            .ok_or_else(|| invalid("incomplete HTTP headers"))?;
        let line = line_content(&line)?;
        if line.is_empty() {
            break;
        }
        header_count += 1;
        // Bounding the number of fields prevents a peer from forcing
        // unbounded per-header parsing work with many tiny lines.
        if header_count > MAX_HEADERS {
            return Err(invalid("HTTP request has more than 100 headers"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| invalid("HTTP header has no colon"))?;
        let name = &line[..colon];
        if name.is_empty()
            || name
                .iter()
                .any(|byte| *byte <= b' ' || *byte >= 0x7f)
        {
            return Err(invalid("invalid HTTP header name"));
        }
        let value = trim_ows(&line[colon + 1..]);
        if ascii_case_eq(name, b"Content-Length") {
            if content_length.is_some() {
                return Err(invalid("duplicate Content-Length header"));
            }
            let value = std::str::from_utf8(value)
                .map_err(|_| invalid("Content-Length is not valid ASCII"))?;
            let length = value
                .parse::<usize>()
                .map_err(|_| invalid("invalid Content-Length"))?;
            // The normal parser supplies the JSON cap; streaming routes
            // deliberately omit it so they can enforce their own limit.
            if max_body_bytes.is_some_and(|max| length > max) {
                return Err(invalid("Content-Length exceeds 1 MiB"));
            }
            content_length = Some(length);
        } else if ascii_case_eq(name, b"Authorization") {
            // A malformed scheme is left as no token so the auth layer
            // returns its uniform 401 rather than exposing parser detail.
            token = bearer_token(value);
        } else if ascii_case_eq(name, b"Cookie") {
            let value = bytes_to_string(value, "Cookie")?;
            cookies.extend(parse_cookies(&value));
        } else if ascii_case_eq(name, b"Origin") {
            origin = Some(bytes_to_string(value, "Origin")?);
        } else if ascii_case_eq(name, b"X-Forwarded-Proto") {
            forwarded_proto = Some(bytes_to_string(value, "X-Forwarded-Proto")?);
        } else if ascii_case_eq(name, b"Host") {
            host = Some(bytes_to_string(value, "Host")?);
        }
    }
    Ok(RequestHead {
        method,
        path,
        token,
        content_length,
        cookies,
        origin,
        forwarded_proto,
        host,
    })
}

/// Reads only the request line and headers, leaving the body in `stream`.
pub fn parse_head(stream: &mut impl BufRead) -> shinu_core::Result<RequestHead> {
    parse_head_inner(stream, None)
}

/// Reads a buffered request body while retaining the historical 1 MiB cap.
pub fn read_body(
    stream: &mut impl BufRead,
    content_length: Option<usize>,
) -> shinu_core::Result<Vec<u8>> {
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY_BYTES {
        return Err(invalid("Content-Length exceeds 1 MiB"));
    }
    let mut body = vec![0; length];
    if let Err(error) = stream.read_exact(&mut body) {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            return Err(invalid("request body is shorter than Content-Length"));
        }
        return Err(shinu_core::Error::Io(error));
    }
    Ok(body)
}

pub fn parse(stream: &mut impl BufRead) -> shinu_core::Result<Request> {
    let head = parse_head_inner(stream, Some(MAX_BODY_BYTES))?;
    let body = read_body(stream, head.content_length)?;
    Ok(head.into_request(body))
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        302 => "Found",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

fn json_io_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

pub fn respond(
    writer: &mut impl Write,
    status: u16,
    body: &serde_json::Value,
) -> io::Result<()> {
    let body = serde_json::to_vec(body).map_err(json_io_error)?;
    write!(
        writer,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    )?;
    writer.write_all(&body)
}

pub fn respond_html(
    writer: &mut impl Write,
    status: u16,
    body: &str,
) -> io::Result<()> {
    let body = body.as_bytes();
    write!(
        writer,
        "HTTP/1.1 {status} {}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    )?;
    writer.write_all(body)
}

fn asset_content_type(path: &str) -> &'static str {
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
    if extension.eq_ignore_ascii_case("html") {
        "text/html; charset=utf-8"
    } else if extension.eq_ignore_ascii_case("css") {
        "text/css"
    } else if extension.eq_ignore_ascii_case("js") {
        "text/javascript"
    } else if extension.eq_ignore_ascii_case("svg") {
        "image/svg+xml"
    } else if extension.eq_ignore_ascii_case("ico") {
        "image/x-icon"
    } else {
        "application/octet-stream"
    }
}

pub fn respond_asset(
    writer: &mut impl Write,
    path: &str,
    body: &[u8],
) -> io::Result<()> {
    // Demo assets are embedded in the binary and change with each build;
    // no-cache avoids pairing a cached JS bundle with a newer API.
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        asset_content_type(path),
        body.len()
    )?;
    writer.write_all(body)
}

pub fn respond_redirect(writer: &mut impl Write, location: &str) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 302 {}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        reason_phrase(302)
    )
}

pub fn respond_with_cookie(
    writer: &mut impl Write,
    status: u16,
    body: &serde_json::Value,
    cookie: &str,
) -> io::Result<()> {
    let body = serde_json::to_vec(body).map_err(json_io_error)?;
    write!(
        writer,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: {cookie}\r\nConnection: close\r\n\r\n",
        reason_phrase(status),
        body.len()
    )?;
    writer.write_all(&body)
}

/// Build a session cookie. `Secure` must only be enabled for HTTPS
/// requests; adding it during local HTTP development makes browsers
/// discard the cookie and leaves a successful login immediately unauthenticated.
pub fn set_cookie(name: &str, value: &str, secure: bool, max_age: u64) -> String {
    let secure_suffix = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; HttpOnly; SameSite=Strict; Path=/; Max-Age={max_age}{secure_suffix}"
    )
}

pub fn clear_cookie(name: &str) -> String {
    format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

fn respond_chunked_start_with_type(
    writer: &mut impl Write,
    content_type: &str,
) -> io::Result<()> {
    write!(
        writer,
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    )?;
    // Flush the headers before the VM command starts so clients can begin
    // consuming the stream without waiting for its first output line.
    writer.flush()
}

pub fn respond_chunked_start(writer: &mut impl Write) -> io::Result<()> {
    respond_chunked_start_with_type(writer, "application/x-ndjson")
}

pub fn respond_chunked_binary_start(writer: &mut impl Write) -> io::Result<()> {
    respond_chunked_start_with_type(writer, "application/octet-stream")
}

pub fn respond_chunk_bytes(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    write!(writer, "{:x}\r\n", payload.len())?;
    writer.write_all(payload)?;
    writer.write_all(b"\r\n")?;
    writer.flush()
}

pub fn respond_chunk(
    writer: &mut impl Write,
    line: &serde_json::Value,
) -> io::Result<()> {
    let mut payload = serde_json::to_vec(line).map_err(json_io_error)?;
    payload.push(b'\n');
    // JSON is serialized to bytes first; binary callers use
    // `respond_chunk_bytes` so no UTF-8 conversion can corrupt payloads.
    respond_chunk_bytes(writer, &payload)
}

pub fn respond_chunked_end(writer: &mut impl Write) -> io::Result<()> {
    writer.write_all(b"0\r\n\r\n")?;
    writer.flush()
}

/// The single translation from domain errors to HTTP status codes.
pub fn status_for(error: &shinu_core::Error) -> u16 {
    match error {
        shinu_core::Error::Auth(_) => 401,
        shinu_core::Error::NotFound(_) => 404,
        shinu_core::Error::Invalid(_) => 400,
        shinu_core::Error::Quota(_) => 429,
        shinu_core::Error::Btrfs(_)
        | shinu_core::Error::Io(_)
        | shinu_core::Error::Json(_)
        | shinu_core::Error::Internal(_) => 500,
    }
}

#[cfg(test)]
mod http_tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    #[test]
    fn parses_get_without_body() {
        let mut input = Cursor::new(
            b"GET /v1/spaces HTTP/1.1\r\nHost: localhost\r\n\r\n",
        );
        let request = parse(&mut input).unwrap();
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/v1/spaces");
        assert_eq!(request.token, None);
        assert!(request.body.is_empty());
    }

    #[test]
    fn head_and_body_split_matches_parse() {
        let raw = b"POST /v1/spaces HTTP/1.1\r\nContent-Length: 7\r\nAuthorization: Bearer abc\r\n\r\npayloadtrailing";
        let expected = parse(&mut Cursor::new(raw)).expect("buffered parse");
        let mut split_input = Cursor::new(raw);
        let head = parse_head(&mut split_input).expect("head parse");
        let body = read_body(&mut split_input, head.content_length).expect("body parse");
        assert_eq!(head.into_request(body), expected);
    }

    #[test]
    fn head_parse_reports_upload_sized_content_length() {
        let raw = format!(
            "POST /v1/spaces/demo/push?path=/tmp/file HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let head = parse_head(&mut Cursor::new(raw.as_bytes())).expect("uncapped head parse");
        assert_eq!(head.content_length, Some(MAX_BODY_BYTES + 1));
    }

    #[test]
    fn reads_exact_content_length() {
        let mut input = Cursor::new(
            b"POST /v1/spaces HTTP/1.1\r\nContent-Length: 7\r\n\r\npayloadtrailing",
        );
        let request = parse(&mut input).unwrap();
        assert_eq!(request.body, b"payload");
    }

    #[test]
    fn recognizes_mixed_case_header_names() {
        let mut input = Cursor::new(
            b"POST /v1/spaces HTTP/1.1\r\ncontent-length: 3\r\nAUTHORIZATION: Bearer abc\r\n\r\nxyz",
        );
        let request = parse(&mut input).unwrap();
        assert_eq!(request.body, b"xyz");
        assert_eq!(request.token.as_deref(), Some("abc"));
    }

    #[test]
    fn parses_single_cookie() {
        let cookies = parse_cookies("shinu_session=abc123");
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies.get("shinu_session").map(String::as_str),
            Some("abc123")
        );
    }

    #[test]
    fn parses_multiple_cookies() {
        let cookies = parse_cookies("first=one; second=two; third=three");
        assert_eq!(cookies.len(), 3);
        assert_eq!(cookies.get("first").map(String::as_str), Some("one"));
        assert_eq!(cookies.get("second").map(String::as_str), Some("two"));
        assert_eq!(cookies.get("third").map(String::as_str), Some("three"));
    }

    #[test]
    fn trims_cookie_names_and_values() {
        let cookies = parse_cookies("  first = one  ;\tsecond=two\t");
        assert_eq!(cookies.get("first").map(String::as_str), Some("one"));
        assert_eq!(cookies.get("second").map(String::as_str), Some("two"));
    }

    #[test]
    fn parses_empty_cookie_and_preserves_later_equals() {
        let cookies = parse_cookies("empty=; encoded=a=b=c");
        assert_eq!(cookies.get("empty").map(String::as_str), Some(""));
        assert_eq!(
            cookies.get("encoded").map(String::as_str),
            Some("a=b=c")
        );
    }

    #[test]
    fn parses_console_request_metadata_case_insensitively() {
        let mut input = Cursor::new(
            b"GET /app HTTP/1.1\r\nhOsT: console.test:8080\r\noRiGiN: https://console.test\r\nx-fOrWaRdEd-PrOtO: https\r\ncOoKiE: shinu_session=abc123; theme=dark\r\n\r\n",
        );
        let request = parse(&mut input).unwrap();
        assert_eq!(
            request.cookies.get("shinu_session").map(String::as_str),
            Some("abc123")
        );
        assert_eq!(request.cookies.get("theme").map(String::as_str), Some("dark"));
        assert_eq!(request.origin.as_deref(), Some("https://console.test"));
        assert_eq!(request.forwarded_proto.as_deref(), Some("https"));
        assert_eq!(request.host.as_deref(), Some("console.test:8080"));
    }

    #[test]
    fn omits_secure_attribute_for_http_cookie() {
        assert_eq!(
            set_cookie("shinu_session", "abc123", false, 604800),
            "shinu_session=abc123; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800"
        );
    }

    #[test]
    fn adds_secure_attribute_for_https_cookie() {
        let cookie = set_cookie("shinu_session", "abc123", true, 604800);
        assert!(cookie.ends_with("; Secure"));
        assert!(cookie.contains("Max-Age=604800"));
    }

    #[test]
    fn clears_cookie_with_zero_max_age() {
        assert_eq!(
            clear_cookie("shinu_session"),
            "shinu_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
        );
    }

    #[test]
    fn responds_with_asset_mime_types_and_no_cache() {
        let cases = [
            ("app.css", "text/css"),
            ("app.js", "text/javascript"),
            ("page.html", "text/html; charset=utf-8"),
            ("data.bin", "application/octet-stream"),
        ];
        for (path, mime) in cases {
            let mut output = Vec::new();
            respond_asset(&mut output, path, b"asset").unwrap();
            let response = String::from_utf8(output).unwrap();
            assert!(response.contains(format!("Content-Type: {mime}\r\n").as_str()));
            assert!(response.contains("Cache-Control: no-cache\r\n"));
        }
    }

    #[test]
    fn responds_with_html_content_type() {
        let mut output = Vec::new();
        respond_html(&mut output, 200, "<main>ok</main>").unwrap();
        let response = String::from_utf8(output).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(response.ends_with("<main>ok</main>"));
    }

    #[test]
    fn responds_with_redirect_location() {
        let mut output = Vec::new();
        respond_redirect(&mut output, "/login").unwrap();
        let response = String::from_utf8(output).unwrap();
        assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
        assert!(response.contains("Location: /login\r\n"));
    }

    #[test]
    fn responds_with_cookie_and_json_byte_length() {
        let body = json!({"ok": true});
        let serialized = serde_json::to_vec(&body).unwrap();
        let mut output = Vec::new();
        respond_with_cookie(&mut output, 201, &body, "shinu_session=abc123; Path=/").unwrap();
        let response = String::from_utf8_lossy(&output);
        assert!(response.contains("Set-Cookie: shinu_session=abc123; Path=/\r\n"));
        assert!(response.contains(
            format!("Content-Length: {}\r\n", serialized.len()).as_str()
        ));
        assert!(output.ends_with(&serialized));
    }

    #[test]
    fn extracts_case_insensitive_bearer_with_multiple_spaces() {
        let mut input = Cursor::new(
            b"GET / HTTP/1.1\r\naUtHoRiZaTiOn: bEaReR    secret\r\n\r\n",
        );
        let request = parse(&mut input).unwrap();
        assert_eq!(request.token.as_deref(), Some("secret"));
    }

    #[test]
    fn missing_authorization_has_no_token() {
        let mut input = Cursor::new(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(parse(&mut input).unwrap().token, None);
    }

    #[test]
    fn rejects_headers_over_64_kib() {
        let mut input = b"GET / HTTP/1.1\r\nX-Fill: ".to_vec();
        input.extend(std::iter::repeat_n(b'x', MAX_HEADER_BYTES));
        let error = parse(&mut Cursor::new(input)).unwrap_err();
        assert!(matches!(error, shinu_core::Error::Invalid(_)));
    }

    #[test]
    fn rejects_content_length_over_1_mib() {
        let input = b"POST / HTTP/1.1\r\nContent-Length: 1048577\r\n\r\n";
        let error = parse(&mut Cursor::new(input)).unwrap_err();
        assert!(matches!(error, shinu_core::Error::Invalid(_)));
    }

    #[test]
    fn responds_with_status_and_byte_length() {
        let body = json!({"ok": true});
        let serialized = serde_json::to_vec(&body).unwrap();
        let mut output = Vec::new();
        respond(&mut output, 201, &body).unwrap();
        assert!(output.starts_with(b"HTTP/1.1 201 Created\r\n"));
        assert!(output.windows(format!("Content-Length: {}\r\n", serialized.len()).len()).any(
            |window| window == format!("Content-Length: {}\r\n", serialized.len()).as_bytes()
        ));
        assert!(output.ends_with(&serialized));
    }

    #[test]
    fn encodes_chunk_length_and_termination() {
        let line = json!({"stream": "stdout", "data": "ok\n"});
        let mut payload = serde_json::to_vec(&line).unwrap();
        payload.push(b'\n');
        let mut output = Vec::new();
        respond_chunked_start(&mut output).unwrap();
        respond_chunk(&mut output, &line).unwrap();
        respond_chunked_end(&mut output).unwrap();
        assert!(output.windows(b"Transfer-Encoding: chunked\r\n".len()).any(
            |window| window == b"Transfer-Encoding: chunked\r\n"
        ));
        let mut expected_tail = format!("{:x}\r\n", payload.len()).into_bytes();
        expected_tail.extend_from_slice(&payload);
        expected_tail.extend_from_slice(b"\r\n0\r\n\r\n");
        assert!(output.ends_with(&expected_tail));
    }

    #[test]
    fn binary_chunks_preserve_non_utf8_bytes() {
        let payload = [0u8, 0xff, b'\n', 0x80];
        let mut output = Vec::new();
        respond_chunked_binary_start(&mut output).unwrap();
        respond_chunk_bytes(&mut output, &payload).unwrap();
        respond_chunked_end(&mut output).unwrap();
        let frame = b"4\r\n\0\xff\n\x80\r\n";
        assert!(output.windows(frame.len()).any(|window| window == frame));
        assert!(output.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"));
    }

    #[test]
    fn maps_domain_errors_to_statuses() {
        assert_eq!(status_for(&shinu_core::Error::Auth("bad".into())), 401);
        assert_eq!(status_for(&shinu_core::Error::NotFound("gone".into())), 404);
        assert_eq!(status_for(&shinu_core::Error::Invalid("bad".into())), 400);
        assert_eq!(status_for(&shinu_core::Error::Quota("limit".into())), 429);
        assert_eq!(status_for(&shinu_core::Error::Btrfs("bad".into())), 500);
        assert_eq!(
            status_for(&shinu_core::Error::Io(std::io::Error::other("bad"))),
            500
        );
        let json_error = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        assert_eq!(status_for(&shinu_core::Error::Json(json_error)), 500);
        assert_eq!(
            status_for(&shinu_core::Error::Internal("sql: database is locked".into())),
            500
        );
    }

    #[test]
    fn reason_phrase_covers_quota_and_csrf_statuses() {
        assert_eq!(reason_phrase(403), "Forbidden");
        assert_eq!(reason_phrase(429), "Too Many Requests");
    }
}
