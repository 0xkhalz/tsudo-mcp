# tsudo-mcp — Agent Instructions

Zero-dependency Go 1.27 Linux CLI and stdio MCP server (JSON-RPC 2.0) that executes privileged commands via `@duyld/tsudo` using a temporary token stored in `$XDG_RUNTIME_DIR/tsudo-token` (`0600`).

## Quick Commands & Verification Pipeline

Run all commands from the repository root.

- **Fast inner loop** (`~0.4s`):
  ```bash
  go test -count=1 ./internal/policy
  go test -count=1 -run TestEvaluate ./internal/policy
  ```
- **Full verification sequence** (`~2s`, matches `.github/workflows/release.yml` plus local binary build):
  ```bash
  test -z "$(gofmt -l .)"
  go vet ./...
  go test -race -count=1 ./...
  go build -o /tmp/tsudo-mcp ./cmd/tsudo-mcp
  ```
- **Static release build** (matches `.github/workflows/release.yml`, targets `amd64` and `arm64`):
  ```bash
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath -ldflags="-s -w -X main.Version=0.1.0" \
    -o /tmp/tsudo-mcp ./cmd/tsudo-mcp
  ```
- **Runner & sandbox caveats**:
  - `go test -race` requires CGO (default on Linux); NEVER combine `CGO_ENABLED=0` with `-race`.
  - Linux-only codebase (`//go:build linux` in `cmd/tsudo-mcp/tty_linux.go`; Linux/POSIX `syscall` usage in `internal/token` and `internal/runner`).
  - PTY tests in `cmd/tsudo-mcp/tty_linux_test.go` skip automatically when `/dev/ptmx` is unavailable in restricted sandboxes.
  - Pushing a `v*` tag triggers `.github/workflows/release.yml`, which publishes GitHub Release artifacts and extracts `## [X.Y.Z]` notes from `CHANGELOG.md`; NEVER push tags without explicit approval.

## Architecture Map & Task Routing

- `cmd/tsudo-mcp/` (`main.go`, `grant.go`, `tty_linux.go`) — CLI dispatch (`serve` [default], `grant`, `status`, `clear`, `version`, `help`), `Version` ldflags var, TTY echo suppression, and concrete wiring. **Must not own**: policy rules, token file validation internals, or JSON-RPC framing.
- `internal/token/` (`store.go`, `parse.go`) — `Store` interface, fail-closed `FileStore`, `DefaultPath()` (`TSUDO_MCP_TOKEN_FILE` or `$XDG_RUNTIME_DIR/tsudo-token`), `ParseToken()`, and `Redact()`. **Must not own**: subprocess execution or MCP framing.
- `internal/policy/` (`policy.go`) — `Evaluator` interface and `Policy`: command/arg validation (reject empty, NUL, whitespace in command), single-level `sudo` unwrapping, hard denylist, shell blocker (`TSUDO_MCP_ALLOW_SHELL=1`), and optional `TSUDO_MCP_ALLOWLIST`. **Must not own**: token reads or subprocess spawning.
- `internal/runner/` (`runner.go`, `buffer.go`) — `Runner` interface and `TsudoRunner`: `tsudo run --token TOKEN -- ARGV...`, `tsudo status`, `tsudo logs`/`check`, process-group isolation (`Setpgid: true`, `SIGKILL` to `-pid`), `LimitedBuffer` (`MaxOutputBytes = 256 KiB`/stream), timeout clamping (`TSUDO_MCP_DEFAULT_TIMEOUT`, default `60s`, max `600s`), token redaction, and expired-token detection (`tokenErrorMarkers`). **Must not own**: policy checks or token file I/O.
- `internal/mcp/` (`protocol.go`, `server.go`, `tools.go`) — newline-delimited JSON-RPC 2.0 stdio loop (`MCPProtocolVersion = "2024-11-05"`, `MaxLineBytes = 4 MiB`) and `sudo_exec`, `sudo_status`, `sudo_logs` handlers. Depends ONLY on `token.Store`, `policy.Evaluator`, and `runner.Runner` interfaces.
- **If changing `@duyld/tsudo` output or error parsing**: inspect `internal/token/parse.go`, `cmd/tsudo-mcp/grant.go`, and `tokenErrorMarkers` in `internal/runner/runner.go` together.
- **If changing CLI subcommands, env vars, or MCP tool schemas**: sync `usageText` in `cmd/tsudo-mcp/main.go`, `toolDefinitions()` in `internal/mcp/tools.go`, and `README.md`.
- **If bumping the version or cutting a release**: keep `Version` in `cmd/tsudo-mcp/main.go`, the `## [X.Y.Z]` heading in `CHANGELOG.md` (parsed by `.github/workflows/release.yml`), and the `vX.Y.Z` tag aligned.

## Non-Negotiable Invariants & Footguns

- **Zero external Go dependencies**: ONLY use the Go standard library (`go.mod` MUST have no `require` blocks and no `go.sum`) to keep binary RSS (~3–6 MB) and supply-chain surface minimal.
- **No raw `sudo` & policy-first execution**: NEVER invoke `sudo` directly; all privileged execution MUST go through `tsudo run --token TOKEN -- ARGV...`. In `sudo_exec`, ALWAYS run `policy.Evaluator.Evaluate` before reading the token store or spawning `tsudo`.
- **Secret handling & defensive redaction**: NEVER print, log, or return the raw `tsudo` token or sudo password in stdout, stderr, errors, or MCP responses. Redact defensively across `runner` (`redact`), `mcp`, and `grant` (`token.Redact`); in `cmd/tsudo-mcp/grant.go`, flush password prompts immediately, suppress token lines, and restore TTY echo idempotently via `disableEchoIfTTY`.
- **Fail-closed token storage**: Token reads MUST reject non-regular files and symlinks (`os.Lstat` + `syscall.O_NOFOLLOW` / `ELOOP`), reject any mode with group/other bits (`perm & 0o077 != 0`), and verify UID equals `os.Getuid()`. Token writes MUST be atomic (`CreateTemp` -> `Chmod(0o600)` -> write -> `Sync` -> `Close` -> `Rename`).
- **MCP stdio wire lock**: `serve` MUST write ONLY single-line newline-delimited JSON-RPC 2.0 frames to stdout; ALL diagnostics go to stderr. NEVER emit responses for `notifications/initialized` or `notifications/*` without an `id`. Keep `readLineBounded` draining oversized lines (`> 4 MiB`) so subsequent frames remain aligned.
- **Bounded subprocesses & process-group cleanup**: Every `tsudo` subprocess MUST use `LimitedBuffer` (256 KiB per stream), `cmd.Stdin = nil`, `Setpgid: true`, and `syscall.Kill(-pid, syscall.SIGKILL)` on context cancellation so timed-out commands cannot orphan children or exhaust RAM.

## Testing & Verification Notes

- **No live `tsudo` or `sudo` in tests**: NEVER invoke the system `tsudo` or `sudo` binary in tests. `internal/mcp/server_test.go` injects in-memory fakes (`fakeStore`, `fakeRunner`); `internal/runner/runner_test.go` and `cmd/tsudo-mcp/main_test.go` generate executable `#!/usr/bin/env sh` fake `tsudo` scripts in `t.TempDir()` and pass them via `runner.New(fakeBin, ...)` or `runWithBinary(...)`.
- **Security regression coverage**: Any edit to token parsing/redaction, `grant` streaming, `FileStore` permission/symlink checks, or `policy` denylists MUST add or update a test proving the sentinel token never leaks (`sentinelToken` pattern in `internal/mcp/server_test.go`) or the forbidden input fails closed.
- **Focused test runs**: Run `go test -race -count=1 ./internal/token` (or any package) and add `-run TestPattern` for a single case.

## Maintained Docs

- `README.md` — installation, CLI usage, MCP tool contracts, environment variables, and client registration.
- `CHANGELOG.md` — Keep a Changelog release history (section headers drive `.github/workflows/release.yml` release notes).
- `.github/workflows/release.yml` — tag-triggered CI verification and static Linux `amd64`/`arm64` release packaging.
