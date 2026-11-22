# tsudo-mcp

Zero-dependency Go MCP (Model Context Protocol, stdio JSON-RPC 2.0) server and CLI wrapper that lets AI agents execute privileged GNU/Linux commands through `@duyld/tsudo` using a temporary token stored in RAM-only `$XDG_RUNTIME_DIR/tsudo-token` (`0600`), without exposing the user's sudo password or pasting tokens into chat.

## Prerequisites

- Go 1.27+
- `@duyld/tsudo` (`tsudo` on `PATH`)
- Linux with `$XDG_RUNTIME_DIR` (RAM-backed `tmpfs`)

## CLI Usage

- `tsudo-mcp grant [10m|30m|1h|1d]` — runs `tsudo`, captures the printed token while preserving the interactive password prompt, and writes it atomically (`0600`) to `$XDG_RUNTIME_DIR/tsudo-token`.
- `tsudo-mcp status` — checks active `tsudo` session and token file permissions.
- `tsudo-mcp clear` — clears `tsudo` session and deletes the token file.
- `tsudo-mcp serve` (default when run with no args) — runs the stdio MCP server.

## MCP Tools

- `sudo_exec` (`command`, `args`, `cwd`, `timeout_seconds`) — executes a single privileged command via `tsudo run --token <token> -- <argv...>`.
- `sudo_status` — reports token presence/permissions and `tsudo status`.
- `sudo_logs` (`count`, `check`) — inspects recent `@duyld/tsudo` audit entries (`~/.tsudo/logs.jsonl`).

## Safety & Configuration

- **Argv-only execution**: Commands are executed directly without a shell; shells (`sh`, `bash`, `zsh`, `fish`, `dash`, `ksh`, `csh`, `tcsh`, `eval`) are blocked by default.
- **Hard denylist**: Blocks destructive commands including recursive `rm` on system roots, `dd` (and `of=/dev/...`), `mkfs` / `mkfs.*`, `wipefs`, `fdisk`, `parted`, `gdisk`, `shred`, recursive `chmod`/`chown`/`chgrp` on system roots, `visudo`, `passwd`, `chpasswd`, `sudo`, `su`, and `tsudo`.
- **Optional environment variables**:
  - `TSUDO_MCP_ALLOWLIST` — comma-separated list of allowed executable basenames (e.g., `pacman,systemctl,journalctl`).
  - `TSUDO_MCP_ALLOW_SHELL=1` — permits shell executables (denylist rules still apply).
  - `TSUDO_MCP_TOKEN_FILE` — overrides the default `$XDG_RUNTIME_DIR/tsudo-token` path.
  - `TSUDO_MCP_DEFAULT_TIMEOUT` — default execution timeout in seconds (default `60`, max `600`).
- **Security model**: `@duyld/tsudo` stores the session password in `~/.tsudo/session.json` (`0600`) owned by the current user. `tsudo-mcp` is an ergonomic, audited, policy-enforced guardrail that keeps passwords and tokens out of LLM context—not an OS privilege isolation boundary against local processes running as the same user.

## MCP Client Registration Example

```json
{
  "mcpServers": {
    "tsudo": {
      "command": "/home/khalz/.local/bin/tsudo-mcp",
      "args": ["serve"]
    }
  }
}
```

## Development

See [AGENTS.md](AGENTS.md) for toolchain invariants and verification commands, and [docs/plan.md](docs/plan.md) for the phased implementation plan.
