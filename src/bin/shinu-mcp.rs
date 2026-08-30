use serde_json::{Map, Value, json};
use shinu::shell_quote_word;
use shinu_client::{Client, Endpoint, Response};
use std::env;
use std::fmt::Write as _;
use std::io::{self, BufRead, BufReader, Write};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "shinu-mcp";

struct Server {
    endpoint: String,
    token: Option<String>,
}

impl Server {
    fn from_env() -> Self {
        let endpoint = shinu_client::endpoint_value_from_env();
        let token = env::var("SHINU_TOKEN")
            .ok()
            .filter(|value| !value.is_empty());
        Self { endpoint, token }
    }

    fn client(&self) -> Result<Client, String> {
        let token = self.token.as_deref().ok_or_else(|| {
            "SHINU_TOKEN is not configured; set SHINU_TOKEN to a Shinu API bearer token before calling a tool"
                .to_string()
        })?;
        if token.bytes().any(|byte| byte == b'\r' || byte == b'\n') {
            return Err("SHINU_TOKEN must not contain carriage returns or newlines".to_string());
        }
        let endpoint =
            Endpoint::parse_environment(&self.endpoint).map_err(|error| error.to_string())?;
        Client::new(endpoint, token.to_owned()).map_err(|error| error.to_string())
    }

    fn execute_tool(&self, name: &str, arguments: &Map<String, Value>) -> Result<String, String> {
        let client = self.client()?;
        match name {
            "shinu_list_spaces" => request_text(&client, "GET", "/v1/spaces", None),
            "shinu_list_images" => request_text(&client, "GET", "/v1/images", None),
            "shinu_create_space" => {
                let name = required_string(arguments, "name")?;
                let body = create_space_body(name, arguments)?;
                request_text(&client, "POST", "/v1/spaces", Some(body))
            }
            "shinu_resize_space" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}", shinu_client::encode_path_segment(space));
                let body = resize_space_body(arguments)?;
                request_text(&client, "PATCH", &path, Some(body))
            }
            "shinu_start" => {
                let space = required_string(arguments, "space")?;
                let path = format!(
                    "/v1/spaces/{}/start",
                    shinu_client::encode_path_segment(space)
                );
                request_text(&client, "POST", &path, None)
            }
            "shinu_stop" => {
                let space = required_string(arguments, "space")?;
                let path = format!(
                    "/v1/spaces/{}/stop",
                    shinu_client::encode_path_segment(space)
                );
                request_text(&client, "POST", &path, None)
            }
            "shinu_write_file" => {
                let space = required_string(arguments, "space")?;
                let path = required_string(arguments, "path")?;
                let content = required_text(arguments, "content")?;
                let command = vec![
                    "sh".to_string(),
                    "-c".to_string(),
                    format!("cat > {}", shell_quote_word(path)),
                ];
                let request_path = format!(
                    "/v1/spaces/{}/exec",
                    shinu_client::encode_path_segment(space)
                );
                let response = request_checked_json(
                    &client,
                    "POST",
                    &request_path,
                    Some(json!({ "cmd": command, "stdin": content })),
                )?;
                aggregate_exec(&response.body)
            }
            "shinu_read_file" => {
                let space = required_string(arguments, "space")?;
                let path = required_string(arguments, "path")?;
                let command = vec!["cat".to_string(), path.to_owned()];
                let request_path = format!(
                    "/v1/spaces/{}/exec",
                    shinu_client::encode_path_segment(space)
                );
                let response = request_checked_json(
                    &client,
                    "POST",
                    &request_path,
                    Some(json!({ "cmd": command })),
                )?;
                aggregate_stdout(&response.body)
            }
            "shinu_exec" => {
                let space = required_string(arguments, "space")?;
                let command = required_command(arguments)?;
                let path = format!(
                    "/v1/spaces/{}/exec",
                    shinu_client::encode_path_segment(space)
                );
                let response =
                    request_checked_json(&client, "POST", &path, Some(json!({ "cmd": command })))?;
                aggregate_exec(&response.body)
            }
            "shinu_commit" => {
                let space = required_string(arguments, "space")?;
                let note = required_string(arguments, "note")?;
                let hot = required_bool(arguments, "hot")?;
                let snapshot = required_snapshot_mode(arguments, "snapshot")?;
                let path = format!(
                    "/v1/spaces/{}/commits",
                    shinu_client::encode_path_segment(space)
                );
                request_text(
                    &client,
                    "POST",
                    &path,
                    Some(json!({ "note": note, "hot": hot, "snapshot": snapshot })),
                )
            }
            "shinu_log" => {
                let space = required_string(arguments, "space")?;
                let path = format!(
                    "/v1/spaces/{}/log",
                    shinu_client::encode_path_segment(space)
                );
                request_text(&client, "GET", &path, None)
            }
            "shinu_reflog" => {
                let space = required_string(arguments, "space")?;
                let path = format!(
                    "/v1/spaces/{}/reflog",
                    shinu_client::encode_path_segment(space)
                );
                request_text(&client, "GET", &path, None)
            }
            "shinu_checkout" => {
                let space = required_string(arguments, "space")?;
                let commit = required_string(arguments, "commit")?;
                let path = format!(
                    "/v1/spaces/{}/checkout",
                    shinu_client::encode_path_segment(space)
                );
                request_text(&client, "POST", &path, Some(json!({ "commit": commit })))
            }
            "shinu_fork" => {
                let commit = required_string(arguments, "commit")?;
                let name = required_string(arguments, "name")?;
                let path = format!(
                    "/v1/commits/{}/fork",
                    shinu_client::encode_path_segment(commit)
                );
                request_text(&client, "POST", &path, Some(json!({ "name": name })))
            }
            "shinu_delete_space" => {
                let space = required_string(arguments, "space")?;
                let path = format!("/v1/spaces/{}", shinu_client::encode_path_segment(space));
                request_text(&client, "DELETE", &path, None)
            }
            _ => Err(format!("unknown Shinu tool {name}")),
        }
    }
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

fn request_checked_json(
    client: &Client,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<Response, String> {
    request_json(client, method, path, body)?
        .into_success()
        .map_err(|error| error.to_string())
}

fn request_text(
    client: &Client,
    method: &str,
    path: &str,
    body: Option<Value>,
) -> Result<String, String> {
    let response = request_checked_json(client, method, path, body)?;
    shinu_client::body_text(&response.body).map_err(|error| error.to_string())
}

fn required_string<'a>(arguments: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    let value = required_text(arguments, field)?;
    if value.trim().is_empty() {
        Err(format!("argument {field} must not be empty"))
    } else {
        Ok(value)
    }
}

fn required_text<'a>(arguments: &'a Map<String, Value>, field: &str) -> Result<&'a str, String> {
    match arguments.get(field) {
        Some(Value::String(value)) => Ok(value),
        Some(_) => Err(format!("argument {field} must be a string")),
        None => Err(format!("missing required argument {field}")),
    }
}

fn required_bool(arguments: &Map<String, Value>, field: &str) -> Result<bool, String> {
    match arguments.get(field) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("argument {field} must be a boolean")),
        None => Err(format!("missing required argument {field}")),
    }
}

fn required_snapshot_mode<'a>(
    arguments: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, String> {
    let value = required_string(arguments, field)?;
    if matches!(value, "none" | "full" | "diff") {
        Ok(value)
    } else {
        Err(format!("argument {field} must be one of: none, full, diff"))
    }
}

fn optional_string<'a>(
    arguments: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    match arguments.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value)),
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

fn optional_positive_u64(
    arguments: &Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    let value = optional_u64(arguments, field)?;
    if value == Some(0) {
        Err(format!("argument {field} must be at least 1"))
    } else {
        Ok(value)
    }
}

fn optional_image<'a>(
    arguments: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    let value = optional_string(arguments, field)?;
    if value.is_some_and(|image| !matches!(image, "void" | "ubuntu" | "arch" | "rocky")) {
        Err(format!(
            "argument {field} must be one of: void, ubuntu, arch, rocky"
        ))
    } else {
        Ok(value)
    }
}

fn optional_network<'a>(
    arguments: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    let value = optional_string(arguments, field)?;
    if let Some(network) = value {
        if network.len() > 32 {
            return Err(format!("argument {field} must be at most 32 characters"));
        }
        if !network
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(format!(
                "argument {field} must contain only lowercase letters, digits, or hyphens"
            ));
        }
    }
    Ok(value)
}

fn create_space_body(name: &str, arguments: &Map<String, Value>) -> Result<Value, String> {
    let mut object = Map::new();
    object.insert("name".to_string(), Value::String(name.to_owned()));
    if let Some(image) = optional_image(arguments, "image")? {
        object.insert("image".to_string(), Value::String(image.to_owned()));
    }
    if let Some(vcpus) = optional_positive_u64(arguments, "vcpus")? {
        object.insert("vcpus".to_string(), Value::from(vcpus));
    }
    if let Some(mem_mib) = optional_positive_u64(arguments, "mem_mib")? {
        object.insert("mem_mib".to_string(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = optional_positive_u64(arguments, "disk_mib")? {
        object.insert("disk_mib".to_string(), Value::from(disk_mib));
    }
    if let Some(network) = optional_network(arguments, "network")? {
        object.insert("network".to_string(), Value::String(network.to_owned()));
    }
    Ok(Value::Object(object))
}

fn resize_space_body(arguments: &Map<String, Value>) -> Result<Value, String> {
    let vcpus = optional_positive_u64(arguments, "vcpus")?;
    let mem_mib = optional_positive_u64(arguments, "mem_mib")?;
    let disk_mib = optional_positive_u64(arguments, "disk_mib")?;
    if vcpus.is_none() && mem_mib.is_none() && disk_mib.is_none() {
        return Err("resize requires at least one of vcpus, mem_mib, or disk_mib".to_string());
    }
    let mut object = Map::new();
    if let Some(vcpus) = vcpus {
        object.insert("vcpus".to_string(), Value::from(vcpus));
    }
    if let Some(mem_mib) = mem_mib {
        object.insert("mem_mib".to_string(), Value::from(mem_mib));
    }
    if let Some(disk_mib) = disk_mib {
        object.insert("disk_mib".to_string(), Value::from(disk_mib));
    }
    Ok(Value::Object(object))
}

fn required_command(arguments: &Map<String, Value>) -> Result<&[Value], String> {
    let value = arguments
        .get("cmd")
        .ok_or_else(|| "missing required argument cmd".to_string())?;
    let values = value
        .as_array()
        .ok_or_else(|| "argument cmd must be an array of strings".to_string())?;
    if values.is_empty() {
        return Err("argument cmd must contain at least one command argument".to_string());
    }
    for (index, value) in values.iter().enumerate() {
        let Some(command) = value.as_str() else {
            return Err(format!("argument cmd[{index}] must be a string"));
        };
        if index == 0 && command.trim().is_empty() {
            return Err("argument cmd[0] must not be empty".to_string());
        }
    }
    Ok(values)
}

fn validate_arguments(name: &str, arguments: &Map<String, Value>) -> Result<(), String> {
    match name {
        "shinu_list_spaces" | "shinu_list_images" => Ok(()),
        "shinu_create_space" => {
            required_string(arguments, "name")?;
            optional_image(arguments, "image")?;
            optional_positive_u64(arguments, "vcpus")?;
            optional_positive_u64(arguments, "mem_mib")?;
            optional_positive_u64(arguments, "disk_mib")?;
            optional_network(arguments, "network")?;
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
            required_snapshot_mode(arguments, "snapshot")?;
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

struct ExecOutput {
    stdout: String,
    stderr: String,
    exit: i64,
}

fn parse_exec_output(body: &[u8]) -> Result<ExecOutput, String> {
    let text = std::str::from_utf8(body)
        .map_err(|error| format!("HTTP response was not valid UTF-8: {error}"))?;
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
            let data = object.get("data").and_then(Value::as_str).ok_or_else(|| {
                format!(
                    "exec stream on NDJSON line {} is missing string data",
                    index + 1
                )
            })?;
            match stream {
                "stdout" => stdout.push_str(data),
                "stderr" => stderr.push_str(data),
                _ => return Err(format!("unknown exec stream {stream:?}")),
            }
        } else if let Some(value) = object.get("exit") {
            let code = value.as_i64().ok_or_else(|| {
                format!("exec exit on NDJSON line {} must be an integer", index + 1)
            })?;
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
    Ok(ExecOutput {
        stdout,
        stderr,
        exit,
    })
}

fn aggregate_exec(body: &[u8]) -> Result<String, String> {
    let ExecOutput {
        stdout,
        stderr,
        exit,
    } = parse_exec_output(body)?;
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
    result.push_str("exit: ");
    let _ = write!(&mut result, "{exit}");
    Ok(result)
}

fn aggregate_stdout(body: &[u8]) -> Result<String, String> {
    let ExecOutput {
        stdout,
        stderr,
        exit,
    } = parse_exec_output(body)?;
    if exit != 0 {
        if stderr.is_empty() {
            return Err(format!("guest command exited with status {exit}"));
        }
        return Err(format!("guest command exited with status {exit}: {stderr}"));
    }
    Ok(stdout)
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
                "disk_mib": {"type": "integer", "minimum": 1, "description": "该 space 的磁盘容量，单位 MiB；省略时使用 daemon 默认值。"},
                "network": {"type": "string", "minLength": 1, "maxLength": 32, "pattern": "^[a-z0-9-]+$", "description": "可选的项目内网络名称；同名 space 才能互相访问。"}
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
            "description": "在需要把当前实验状态存成可回滚的检查点、或在下一轮试错前保留安全副本时使用；hot 与 snapshot 都必须显式选择，snapshot 可为 none、full 或 diff。full 检查点保存 guest 内存与进程状态，diff 检查点保存相对既有 full 基线的脏页。",
            "inputSchema": schema(json!({
                "space": {"type": "string", "minLength": 1, "description": "要存档的 space。"},
                "note": {"type": "string", "minLength": 1, "description": "描述这个存档用途的非空备注。"},
                "hot": {"type": "boolean", "description": "是否创建 hot commit。"},
                "snapshot": {"type": "string", "enum": ["none", "full", "diff"], "description": "内存快照模式；必须显式选择。"}
            }), &["space", "note", "hot", "snapshot"]),
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
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: initialize params must be an object",
                );
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
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/list params must be an object",
                );
            }
            rpc_result(id, json!({"tools": tool_definitions()}))
        }
        "tools/call" => {
            let Some(params) = request.get("params").and_then(Value::as_object) else {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/call params must be an object",
                );
            };
            let Some(name) = params.get("name").and_then(Value::as_str) else {
                return rpc_error(
                    id,
                    -32602,
                    "Invalid params: tools/call requires a string name",
                );
            };
            if !is_known_tool(name) {
                return rpc_error(id, -32602, format!("Invalid params: unknown tool {name}"));
            }
            let empty_arguments = Map::new();
            let arguments = match params.get("arguments") {
                None => &empty_arguments,
                Some(Value::Object(arguments)) => arguments,
                Some(_) => {
                    return rpc_error(
                        id,
                        -32602,
                        "Invalid params: tools/call arguments must be an object",
                    );
                }
            };
            if let Err(error) = validate_arguments(name, arguments) {
                return rpc_error(id, -32602, format!("Invalid params: {error}"));
            }
            match server.execute_tool(name, arguments) {
                Ok(text) => rpc_result(id, tool_result(text, false)),
                Err(error) => rpc_result(id, tool_result(error, true)),
            }
        }
        _ => rpc_error(id, -32601, "Method not found"),
    }
}

fn write_response(output: &mut impl Write, response: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, response).map_err(io::Error::other)?;
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
    let input = BufReader::new(stdin.lock());
    let stdout = io::stdout();
    let mut output = stdout.lock();
    // Keep stdout protocol-only; diagnostics belong on stderr.
    for line in input.lines() {
        match line {
            Ok(line) if !line.trim().is_empty() => {
                if let Err(error) = handle_line(&server, &line, &mut output) {
                    eprintln!("shinu-mcp: could not write JSON-RPC response: {error}");
                    break;
                }
            }
            Ok(_) => {}
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
        assert!(
            validate_arguments(
                "shinu_write_file",
                &arguments(json!({"space": "dev", "path": "/tmp/note", "content": ""}))
            )
            .is_ok()
        );
        assert!(
            validate_arguments(
                "shinu_read_file",
                &arguments(json!({"space": "dev", "path": "/tmp/note"}))
            )
            .is_ok()
        );

        assert!(validate_arguments("shinu_start", &Map::new()).is_err());
        assert!(
            validate_arguments(
                "shinu_write_file",
                &arguments(json!({"space": "dev", "path": "/tmp/note"}))
            )
            .is_err()
        );
        assert!(
            validate_arguments(
                "shinu_read_file",
                &arguments(json!({"space": "dev", "path": 7}))
            )
            .is_err()
        );
    }

    #[test]
    fn validates_image_and_resize_tools() {
        assert!(validate_arguments("shinu_list_images", &Map::new()).is_ok());
        assert!(
            validate_arguments(
                "shinu_resize_space",
                &arguments(json!({"space": "dev", "mem_mib": 2048}))
            )
            .is_ok()
        );
        assert!(
            validate_arguments("shinu_resize_space", &arguments(json!({"space": "dev"}))).is_err()
        );
        assert!(
            validate_arguments(
                "shinu_resize_space",
                &arguments(json!({"space": "dev", "disk_mib": "2048"}))
            )
            .is_err()
        );
    }

    #[test]
    fn validates_all_advertised_resource_and_network_boundaries() {
        for (field, value) in [
            ("vcpus", json!(0)),
            ("mem_mib", json!(0)),
            ("disk_mib", json!(0)),
        ] {
            let mut args = arguments(json!({"name": "dev"}));
            args.insert(field.to_owned(), value);
            assert!(
                validate_arguments("shinu_create_space", &args).is_err(),
                "zero {field} must be rejected"
            );
        }

        for field in ["vcpus", "mem_mib", "disk_mib"] {
            let mut args = arguments(json!({"name": "dev"}));
            args.insert(field.to_owned(), json!(1));
            assert!(
                validate_arguments("shinu_create_space", &args).is_ok(),
                "minimum {field} must be accepted"
            );
        }
        for image in ["void", "ubuntu", "arch", "rocky"] {
            let args = arguments(json!({"name": "dev", "image": image}));
            assert!(validate_arguments("shinu_create_space", &args).is_ok());
        }
        let invalid_image = arguments(json!({"name": "dev", "image": "debian"}));
        assert!(validate_arguments("shinu_create_space", &invalid_image).is_err());

        let too_long_network = "a".repeat(33);
        for network in [
            "",
            "A",
            "network_name",
            "network name",
            too_long_network.as_str(),
        ] {
            let args = arguments(json!({"name": "dev", "network": network}));
            assert!(
                validate_arguments("shinu_create_space", &args).is_err(),
                "invalid network {network:?} must be rejected"
            );
        }
        let boundary_network = "a".repeat(32);
        let args = arguments(json!({"name": "dev", "network": boundary_network}));
        assert!(validate_arguments("shinu_create_space", &args).is_ok());
        for field in ["vcpus", "mem_mib", "disk_mib"] {
            let mut args = arguments(json!({"space": "dev"}));
            args.insert(field.to_owned(), json!(0));
            assert!(
                validate_arguments("shinu_resize_space", &args).is_err(),
                "zero resize {field} must be rejected"
            );
        }
        let mut args = arguments(json!({"space": "dev", "cmd": [""]}));
        assert!(validate_arguments("shinu_exec", &args).is_err());

        for field in ["vcpus", "mem_mib", "disk_mib"] {
            let mut args = arguments(json!({"space": "dev"}));
            args.insert(field.to_owned(), json!(1));
            assert!(
                validate_arguments("shinu_resize_space", &args).is_ok(),
                "minimum resize {field} must be accepted"
            );
        }
        args.insert("cmd".to_owned(), json!(["echo", ""]));
        assert!(validate_arguments("shinu_exec", &args).is_ok());

        for (tool, value) in [
            ("shinu_create_space", json!({"name": "   "})),
            ("shinu_start", json!({"space": "\t"})),
            (
                "shinu_write_file",
                json!({"space": "dev", "path": " ", "content": "ok"}),
            ),
            (
                "shinu_commit",
                json!({"space": "dev", "note": "", "hot": false, "snapshot": "none"}),
            ),
        ] {
            assert!(
                validate_arguments(tool, &arguments(value)).is_err(),
                "trim-empty string for {tool} must be rejected"
            );
        }
    }

    #[test]
    fn invalid_tool_arguments_keep_json_rpc_invalid_params_code() {
        let request = json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "shinu_create_space",
                "arguments": {"name": "dev", "vcpus": 0}
            }
        });
        let request = request.as_object().expect("request object");
        let server = Server {
            endpoint: shinu_client::DEFAULT_ENDPOINT.to_owned(),
            token: None,
        };
        let response = dispatch(&server, request, json!(1));
        assert_eq!(response["error"]["code"], json!(-32602));
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
            assert!(
                is_known_tool(name),
                "tool {name} missing from known-tool match"
            );
        }
    }
}
