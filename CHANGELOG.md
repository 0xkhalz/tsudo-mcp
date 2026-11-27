# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-27

### Added

- CLI subcommands (`serve`, `grant`, `status`, `clear`, `version`) with idempotent TTY echo cleanup on `grant`
- Fail-closed `internal/token` store with atomic `0600` writes in `$XDG_RUNTIME_DIR` and UID, mode, and symlink validation
- `internal/policy` command normalizer, shell blocker, hard safety denylist, and optional `TSUDO_MCP_ALLOWLIST` enforcement
- `internal/runner` `tsudo` subprocess wrapper with bounded 256 KiB output buffers, configurable timeouts, and defensive token redaction
- `internal/mcp` stdio JSON-RPC 2.0 server exposing `sudo_exec`, `sudo_status`, and `sudo_logs` tools
- Automated GitHub Actions release workflow building static `linux/amd64` and `linux/arm64` tarballs with `SHA256SUMS`

[0.1.0]: https://github.com/0xkhalz/tsudo-mcp/releases/tag/v0.1.0
