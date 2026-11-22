# tsudo-mcp Phased Implementation Plan

## 1. Problem & Goal

LLMs reliably invoke first-class MCP tools for privileged Linux commands, whereas prompt/skill rules instructing agents to rewrite `sudo` into `tsudo run --token ...` are occasionally ignored and require pasting sensitive temporary tokens into chat history.

Goal: Build a single, low-RAM static Go binary (`tsudo-mcp`) providing both an interactive CLI (`grant`, `status`, `clear`) and a stdio MCP server (`serve`) backed by `@duyld/tsudo`. The user grants a session once in their terminal (`tsudo-mcp grant 30m`), storing the token only in RAM (`$XDG_RUNTIME_DIR/tsudo-token`, `0600`), while the agent executes audited, policy-checked privileged commands via MCP tools without ever seeing the password or token.

## 2. Design Decisions & Constraints

- **Go stdlib only (0 external dependencies)**: Compiles to a single static binary with ~3–6 MB RSS (suitable for a 7.6 GiB RAM host) and zero third-party supply-chain dependencies.
- **Dynamic per-call token lookup**: Each MCP call reads `$XDG_RUNTIME_DIR/tsudo-token` (or `TSUDO_MCP_TOKEN_FILE`) fresh rather than caching at startup, so `grant`, `clear`, and expiry take effect immediately without restarting MCP clients. Writes use temp-file + `0600` + atomic `rename` on RAM-backed `tmpfs`.
- **Grounded in `@duyld/tsudo` runtime behavior**:
  - `tsudo` prompts `sudo password: ` on stdout without a trailing newline and prints `Temporary tsudo token: <token>` upon success.
  - `tsudo run --token <tok> -- <argv...>` feeds the password to `sudo` and closes `sudo` stdin, logs invocations to `~/.tsudo/logs.jsonl`, and only prints warnings on dangerous commands (it does not block them).
- **Hard policy enforcement, output caps, and redaction**: Because `@duyld/tsudo` only warns, `tsudo-mcp` enforces hard policy blocking in `internal/policy`, caps stdout and stderr at 256 KiB per stream, enforces per-call timeouts (default `60s`, configurable via `TSUDO_MCP_DEFAULT_TIMEOUT`, capped at `600s`), and redacts the active token from all captured output and error strings.

## 3. Component Architecture

All core packages depend on narrow interfaces so every layer can be unit-tested with fakes without invoking real `sudo`:

- `internal/token`:
  - `Store` interface (`Read() (string, error)`, `Write(token string) error`, `Clear() error`, `Stat() (Info, error)`).
  - Parses `Temporary tsudo token: <token>` from `tsudo` output.
  - `FileStore` validates file ownership (`stat.Uid == os.Getuid()`), regular file type, and permissions (`mode & 0o077 == 0`); fails closed on any mismatch.
- `internal/policy`:
  - `Evaluator` interface (`Evaluate(command string, args []string) (Normalized, error)`).
  - Normalizes redundant leading `sudo`, rejects empty/whitespace commands, enforces shell blocker, hard denylist, and optional `TSUDO_MCP_ALLOWLIST`.
- `internal/runner`:
  - `Runner` interface (`Exec(ctx context.Context, tok string, req ExecRequest) (ExecResult, error)`, `Status(ctx context.Context) (string, error)`, `Logs(ctx context.Context, count int, check bool) (string, error)`).
  - Wraps `exec.CommandContext` against `tsudo`, uses bounded 256 KiB ring/prefix buffers, detects missing/expired token errors, and redacts `tok` from all outputs and errors.
- `internal/mcp`:
  - `Server` struct wired with `token.Store`, `policy.Evaluator`, and `runner.Runner`.
  - Reads/writes newline-delimited JSON-RPC 2.0 frames over `io.Reader` / `io.Writer` (strictly keeping diagnostics on `stderr`).

## 4. CLI Specification

- `tsudo-mcp` / `tsudo-mcp serve`: Starts the stdio MCP JSON-RPC 2.0 server until EOF or `SIGINT`/`SIGTERM`.
- `tsudo-mcp grant [duration]`:
  - Validates optional duration against `^\d+[mhd]$` (e.g., `10m`, `30m`, `1h`, `1d`).
  - Spawns `tsudo [duration]` with stdin/stderr attached to the terminal and streams stdout live (byte-by-byte / unbuffered flush so `sudo password: ` renders immediately without newline) while buffering lines to extract the token following `Temporary tsudo token:`.
  - Redacts/replaces raw token echo or confirms storage path (`$XDG_RUNTIME_DIR/tsudo-token`, `0600`) without failing if `tsudo` exits non-zero (returns non-zero without writing token).
- `tsudo-mcp status`: Reports token file existence, mode, owner, and runs `tsudo status`.
- `tsudo-mcp clear`: Deletes `$XDG_RUNTIME_DIR/tsudo-token` (ignoring `ENOENT`) and runs `tsudo clear`.

## 5. MCP Protocol & Tool Contracts

Transport: Newline-delimited JSON-RPC 2.0 over `stdin`/`stdout`. Supported methods:
- `initialize`: Returns `protocolVersion` (`2024-11-05`), `capabilities: { "tools": {} }`, and `serverInfo: { "name": "tsudo-mcp", "version": "..." }`.
- `notifications/initialized`: Accepted with no response (JSON-RPC notification).
- `ping`: Returns `{}`.
- `tools/list`: Returns definitions for `sudo_exec`, `sudo_status`, and `sudo_logs`.
- `tools/call`: Dispatches to the named tool; returns `{ "content": [{ "type": "text", "text": "..." }], "isError": bool }`.

### Tool Schemas & Behavior

1. `sudo_exec`:
   - Inputs: `command` (string, required), `args` (array of strings, optional), `cwd` (string, optional), `timeout_seconds` (integer, optional; default `60` or `TSUDO_MCP_DEFAULT_TIMEOUT`, max `600`).
   - Normalization: Reject empty `command` or whitespace inside `command`. If `command == "sudo"` and `args` starts with a non-flag argument (optionally after `"--"`), strip `"sudo"` (and `"--"`) and promote the next token to `command`; reject if `sudo` flags (e.g., `-u`, `-i`, `-s`) are present.
   - Missing/expired token: Returns `isError: true` with actionable guidance: `"No active tsudo token (or session expired). Ask the user to run: tsudo-mcp grant 30m"`.
   - Success/failure output: Structured text containing `exit_code`, `timed_out`, `truncated`, `stdout`, and `stderr` (token-redacted). Sets `isError: true` on non-zero exit or timeout.
2. `sudo_status`:
   - Inputs: `{}` (none).
   - Output: Token file presence/mode status plus `tsudo status` output (never exposing the token value).
3. `sudo_logs`:
   - Inputs: `count` (integer, optional, default `20`, bounded), `check` (boolean, optional).
   - Output: Runs `tsudo logs` (with count/check options) and returns redacted audit log output.

## 6. Safety Policy Rules (`internal/policy`)

Policy evaluation runs before reading the token or spawning `tsudo`:

- **Shell blocker** (unless `TSUDO_MCP_ALLOW_SHELL=1`): Blocks `filepath.Base(command)` in `{sh, bash, zsh, fish, dash, ksh, csh, tcsh, eval}`.
- **Hard denylist** (always enforced, even if `TSUDO_MCP_ALLOW_SHELL=1` or allowlisted):
  - Recursive `rm` (`-r`, `-R`, `--recursive`, or combined short flags like `-rf`, `-fr`) targeting any sensitive root/prefix normalized via `filepath.Clean`: `/`, `/etc`, `/bin`, `/sbin`, `/usr`, `/var`, `/home`, `/root`, `/boot`, `/dev`, `/proc`, `/sys`.
  - `dd` or any argument matching `of=/dev/...`.
  - Disk/filesystem destruction tools: `mkfs`, `mkfs.*`, `wipefs`, `fdisk`, `parted`, `gdisk`, `shred`.
  - Recursive `chmod`, `chown`, or `chgrp` (`-R`, `--recursive`) targeting any sensitive root/prefix listed above.
  - Privilege/auth/self-recursion tools: `visudo`, `passwd`, `chpasswd`, `sudo` (after normalization), `su`, `tsudo`.
- **Optional `TSUDO_MCP_ALLOWLIST`**: If set and non-empty, splits on `,`, trims whitespace, and requires `filepath.Base(command)` to match an entry.

## 7. Phased TDD Implementation Slices (Atomic Commits)

1. **Phase 1 — Module Scaffold**: Create `go.mod` (`module github.com/0xkhalz/tsudo-mcp`, `go 1.27`), `cmd/tsudo-mcp/main.go` skeleton with `--version` and usage output.
2. **Phase 2 — Token Store (`internal/token`)**: Implement token parser, atomic `0600` writer, fail-closed reader (UID/mode/regular-file checks), `Clear()`, and table-driven unit tests.
3. **Phase 3 — Safety Policy (`internal/policy`)**: Implement command normalizer, shell blocker, hard denylist, `TSUDO_MCP_ALLOWLIST`, and edge-case tests (`-rf`, `--recursive`, `//etc/`, `/usr/bin/rm`, `dd of=/dev/sda`, `sudo -u root`, etc.).
4. **Phase 4 — Execution Runner (`internal/runner`)**: Implement `tsudo` subprocess wrapper with `exec.CommandContext`, timeout handling, 256 KiB bounded output buffers, token redaction, missing/expired token classification, and fake-binary integration tests.
5. **Phase 5 — MCP Stdio Server (`internal/mcp`)**: Implement JSON-RPC 2.0 framing/dispatch (`initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call` for `sudo_exec`, `sudo_status`, `sudo_logs`) and end-to-end stdio pipe tests with mocked runner/store.
6. **Phase 6 — CLI Wiring & Live Verification (`cmd/tsudo-mcp`)**: Wire `serve`, `grant`, `status`, and `clear`; install binary to `~/.local/bin/tsudo-mcp`; register in Antigravity MCP config (and optionally update `~/.gemini/skills/tsudo/SKILL.md`); smoke-test live with `tsudo-mcp grant 10m`, `sudo_status`, and harmless `sudo_exec("id", ["-u"])`.

## 8. Verification & Acceptance Criteria

Every phase must pass the verification pipeline before merge:

```sh
test -z "$(gofmt -l .)"
go vet ./...
go test -race -count=1 ./...
go build -o /tmp/tsudo-mcp ./cmd/tsudo-mcp
```

Acceptance & security checklist:
- Token file created with mode `0600` in `$XDG_RUNTIME_DIR/tsudo-token`; looser permissions (e.g., `0644`) or wrong UID fail closed.
- Token never appears in stdout, stderr, logs, or MCP tool responses (verified by unit/pipe tests injecting known sentinel tokens).
- MCP server writes strictly valid JSON-RPC frames to stdout; no stray print statements.
- Live stdio smoke test verifies `initialize` -> `tools/list` -> `sudo_status` -> `sudo_exec("id", ["-u"])`.

## 9. Pitfalls & Open Decisions for User Review

1. **Default allowlist policy**: Confirm whether `TSUDO_MCP_ALLOWLIST` should default to unset (denylist-only mode for general Arch maintenance) or default to a curated Arch allowlist (e.g., `pacman`, `systemctl`, `journalctl`, `ip`, `wg`, `mount`, `umount`, `btrfs`, `pacman-key`, `id`).
2. **Client registration & remote hosting**: Confirm which agent clients should be registered in Phase 6 (Antigravity CLI, Pi, etc.) and whether to create a GitHub repository via `gh repo create`.
