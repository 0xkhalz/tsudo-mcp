# tsudo-mcp

## Toolchain & Runtime
- Go `go1.27.4+` (`linux/amd64`), standard library only (0 external deps).
- `@duyld/tsudo` (`tsudo` in `PATH`) on Linux with `$XDG_RUNTIME_DIR`.
- Interactive commands must be `fish`-compatible; scripts use `#!/usr/bin/env sh`.

## Verification Pipeline
Run after Phase 1 scaffolds `go.mod`:
1. `test -z "$(gofmt -l .)"`
2. `go vet ./...`
3. `go test -race -count=1 ./...`
4. `go build -o /tmp/tsudo-mcp ./cmd/tsudo-mcp`

## Non-Negotiable Invariants
- Zero external Go dependencies (stdlib only) to minimize RAM (~3–6 MB RSS) and supply-chain surface.
- Never print, log, or return the raw `tsudo` token or sudo password in stdout, stderr, errors, or MCP responses; redact token defensively.
- MCP server writes ONLY JSON-RPC frames to stdout; diagnostics go to stderr.
- Token file must be `0600` owned by current UID in `$XDG_RUNTIME_DIR` (fail closed on looser perms or wrong owner).
- Never invoke raw `sudo` directly; all privileged execution goes through `tsudo run --token <token> -- <argv...>`.
- Atomic commits: one logical change per commit, tests travel with their slice, explicit `git add <paths>`.

## Architecture Map
- `cmd/tsudo-mcp/main.go` — CLI entrypoint (`serve`, `grant`, `status`, `clear`).
- `internal/token` — `$XDG_RUNTIME_DIR/tsudo-token` parsing, atomic `0600` write, owner/mode validation.
- `internal/policy` — command normalization, shell blocker, hard denylist, optional `TSUDO_MCP_ALLOWLIST`.
- `internal/runner` — `tsudo` subprocess wrapper (`exec.CommandContext`, bounded output, token redaction).
- `internal/mcp` — stdio JSON-RPC 2.0 protocol loop and `sudo_exec` / `sudo_status` / `sudo_logs` handlers.
- `docs/plan.md` — phased implementation specification.
