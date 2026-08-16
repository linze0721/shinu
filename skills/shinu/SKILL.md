---
name: shinu
description: 需要隔离且可回滚地执行不可信代码、进行实验或并行比较方案时使用 Shinu 沙盒。
---

# Shinu 沙盒

## 何时用

当任务需要隔离执行不可信代码、需要可回滚的实验环境，或需要并行尝试多个方案时使用 Shinu。先判断任务是否真的需要 VM 隔离；普通的短暂本地计算不必创建 space。

- `space` 是一个分支：隔离工作区和 VM 生命周期都归它所有。
- `commit` 和 `checkout` 要求 space 必须处于**停止状态**（STOPPED）。要进行 commit 或 checkout，先调用 `shinu stop` 或 MCP `shinu_stop` 停止 space；如需在运行中快照可显式指定 `--hot`。
- `checkout` 参数必须提供**完整 UUID**，不能使用列表显示的 8 位短 ID。
- `commit` 是一个存档：在危险改动或有价值的中间状态前先创建它。
- `checkout` 前会自动存档当前状态，所以回滚和试错是安全的。
- `reflog` 可以找回被丢弃的状态；找不到预期的 HEAD 时先查 reflog，再决定是否继续改动。

## 数据传输选择

根据 payload 类型与传输方式选择最合适的机制：

1. **粘贴文本 / 脚本**: 使用 `exec` 的 optional `stdin`（或 MCP 工具 `shinu_write_file` / `shinu_read_file`）。受限于 JSON 请求体 1 MiB 上限，适合粘贴脚本、配置文件和小型文本。
2. **二进制单文件 (≤ 256 MiB)**: 使用 CLI `shinu push` 与 `shinu pull` 节点。基于 HTTP 流式传输，不经 JSON 内存缓冲，支持高达 256 MiB 的文件上传与下载。MCP 工具为纯文本格式，传输二进制文件必须使用 CLI 或 REST 接口。
3. **目录或多文件树**: 使用 `exec` 结合 `tar`（例如 `tar -cf - . | shinu exec <space> -- tar -xf - -C /target`）。`push` 和 `pull` 仅支持单文件，对目录会返回 400。

## 典型工作流

创建 space → 执行实验 → commit 存档 → 试错 → checkout 回滚或从 commit fork 出并行方案。

## 配额意识

默认每个项目最多 5 个 space、2 个并发 VM。实验结束后删除不再需要的 space，避免占满配额。

## 反面模式

- 不要把 Shinu 当长期存储：磁盘只增不减，Firecracker 无 TRIM。
- 不要在 space 里存密钥、令牌或其他长期凭据。
- 不要用 space 承载需要持久化、稳定运行的生产负载。
- 不要在运行中的 space 上直接执行 `commit`（非 hot）或 `checkout`，必须先停止 space。
- 不要尝试通过 MCP 工具传输二进制文件，MCP 为 JSON 纯文本格式，二进制传输请使用 CLI `push`/`pull`。
