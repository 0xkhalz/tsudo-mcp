package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/0xkhalz/tsudo-mcp/internal/runner"
	"github.com/0xkhalz/tsudo-mcp/internal/token"
)

const (
	toolSudoExec   = "sudo_exec"
	toolSudoStatus = "sudo_status"
	toolSudoLogs   = "sudo_logs"

	missingTokenGuidance = "No active tsudo token (or session expired). Ask the user to run: tsudo-mcp grant 30m"
	defaultLogsCount     = 20
)

type sudoExecArgs struct {
	Command        *string   `json:"command"`
	Args           []*string `json:"args"`
	Cwd            *string   `json:"cwd"`
	TimeoutSeconds *int      `json:"timeout_seconds"`
}

type sudoLogsArgs struct {
	Count *int  `json:"count"`
	Check *bool `json:"check"`
}

func toolDefinitions() []Tool {
	return []Tool{
		{
			Name:        toolSudoExec,
			Description: "Execute a privileged command through tsudo after safety policy checks.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"command": map[string]any{
						"type":        "string",
						"description": "Executable name or path to run with elevated privileges.",
					},
					"args": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Optional command arguments.",
					},
					"cwd": map[string]any{
						"type":        "string",
						"description": "Optional working directory.",
					},
					"timeout_seconds": map[string]any{
						"type":        "integer",
						"minimum":     0,
						"description": "Optional execution timeout in seconds.",
					},
				},
				"required": []string{"command"},
			},
		},
		{
			Name:        toolSudoStatus,
			Description: "Inspect tsudo session status and token file state without exposing secrets.",
			InputSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
		},
		{
			Name:        toolSudoLogs,
			Description: "Fetch recent tsudo logs or run tsudo check.",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"count": map[string]any{
						"type":        "integer",
						"minimum":     1,
						"description": "Number of recent log entries to retrieve (default 20).",
					},
					"check": map[string]any{
						"type":        "boolean",
						"description": "Run tsudo check instead of fetching logs.",
					},
				},
			},
		},
	}
}

func (s *Server) handleToolCall(ctx context.Context, rawParams json.RawMessage) (CallToolResult, *RPCError) {
	var params CallToolParams
	if rpcErr := decodeObjectArgs(rawParams, &params, true); rpcErr != nil {
		return CallToolResult{}, rpcErr
	}

	switch params.Name {
	case toolSudoExec:
		return s.handleSudoExec(ctx, params.Arguments)
	case toolSudoStatus:
		if rpcErr := decodeObjectArgs(params.Arguments, &struct{}{}, false); rpcErr != nil {
			return CallToolResult{}, rpcErr
		}
		return s.handleSudoStatus(ctx), nil
	case toolSudoLogs:
		return s.handleSudoLogs(ctx, params.Arguments)
	default:
		return CallToolResult{}, &RPCError{
			Code:    ErrCodeInvalidParams,
			Message: fmt.Sprintf("unknown tool: %q", params.Name),
		}
	}
}

func (s *Server) handleSudoExec(ctx context.Context, rawArgs json.RawMessage) (CallToolResult, *RPCError) {
	var in sudoExecArgs
	if rpcErr := decodeObjectArgs(rawArgs, &in, true); rpcErr != nil {
		return CallToolResult{}, rpcErr
	}
	if in.Command == nil || *in.Command == "" {
		return CallToolResult{}, &RPCError{
			Code:    ErrCodeInvalidParams,
			Message: "command must be a non-empty string",
		}
	}
	if in.TimeoutSeconds != nil && *in.TimeoutSeconds < 0 {
		return CallToolResult{}, &RPCError{
			Code:    ErrCodeInvalidParams,
			Message: "timeout_seconds must be >= 0",
		}
	}

	args := make([]string, len(in.Args))
	for i, a := range in.Args {
		if a == nil {
			return CallToolResult{}, &RPCError{
				Code:    ErrCodeInvalidParams,
				Message: fmt.Sprintf("args[%d] must be a string", i),
			}
		}
		args[i] = *a
	}

	// Evaluate policy before touching the token store or spawning tsudo.
	norm, err := s.eval.Evaluate(*in.Command, args)
	if err != nil {
		return textResult("Blocked by safety policy: "+err.Error(), true), nil
	}

	tok, err := s.store.Read()
	if err != nil {
		return textResult(formatTokenReadError(err), true), nil
	}

	var cwd string
	if in.Cwd != nil {
		cwd = *in.Cwd
	}
	var timeout time.Duration
	if in.TimeoutSeconds != nil {
		timeout = time.Duration(*in.TimeoutSeconds) * time.Second
	}

	res, err := s.run.Exec(ctx, tok, runner.ExecRequest{
		Command: norm.Command,
		Args:    norm.Args,
		Cwd:     cwd,
		Timeout: timeout,
	})
	if err != nil {
		if errors.Is(err, runner.ErrTokenInvalidOrExpired) {
			return textResult(missingTokenGuidance, true), nil
		}
		return textResult("Execution failed: "+token.Redact(err.Error(), tok), true), nil
	}

	formatted := fmt.Sprintf(
		"exit_code: %d\ntimed_out: %t\ntruncated: %t\nstdout:\n%s\nstderr:\n%s",
		res.ExitCode,
		res.TimedOut,
		res.Truncated,
		res.Stdout,
		res.Stderr,
	)
	return textResult(token.Redact(formatted, tok), res.ExitCode != 0 || res.TimedOut), nil
}

func (s *Server) handleSudoStatus(ctx context.Context) CallToolResult {
	info, statErr := s.store.Stat()
	statusOut, runErr := s.run.Status(ctx)

	path := info.Path
	if path == "" {
		path = s.store.Path()
	}

	var b strings.Builder
	fmt.Fprintf(&b, "token_file: %s\n", path)
	fmt.Fprintf(&b, "token_exists: %t\n", info.Exists)
	fmt.Fprintf(&b, "token_valid: %t\n", info.Valid)
	if info.Exists {
		fmt.Fprintf(&b, "token_mode: %#o\n", info.Mode.Perm())
		fmt.Fprintf(&b, "token_uid: %d\n", info.UID)
		if !info.ModTime.IsZero() {
			fmt.Fprintf(&b, "token_mtime: %s\n", info.ModTime.UTC().Format(time.RFC3339))
		}
	}
	switch {
	case info.Err != nil:
		fmt.Fprintf(&b, "token_error: %s\n", info.Err.Error())
	case statErr != nil:
		fmt.Fprintf(&b, "token_error: %s\n", statErr.Error())
	}

	if strings.TrimSpace(statusOut) != "" {
		fmt.Fprintf(&b, "tsudo_status:\n%s\n", strings.TrimRight(statusOut, "\n"))
	} else {
		b.WriteString("tsudo_status: (empty)\n")
	}
	if runErr != nil {
		fmt.Fprintf(&b, "tsudo_status_error: %s\n", runErr.Error())
	}

	return textResult(strings.TrimRight(b.String(), "\n"), statErr != nil || runErr != nil)
}

func (s *Server) handleSudoLogs(ctx context.Context, rawArgs json.RawMessage) (CallToolResult, *RPCError) {
	var in sudoLogsArgs
	if rpcErr := decodeObjectArgs(rawArgs, &in, false); rpcErr != nil {
		return CallToolResult{}, rpcErr
	}

	count := defaultLogsCount
	if in.Count != nil {
		if *in.Count < 0 {
			return CallToolResult{}, &RPCError{
				Code:    ErrCodeInvalidParams,
				Message: "count must be >= 0",
			}
		}
		if *in.Count > 0 {
			count = *in.Count
		}
	}

	check := false
	if in.Check != nil {
		check = *in.Check
	}

	out, runErr := s.run.Logs(ctx, count, check)

	// Defensively redact active token if one is readable; ignore missing/invalid token errors.
	var tok string
	if t, err := s.store.Read(); err == nil {
		tok = t
	}

	if runErr != nil {
		msg := token.Redact(runErr.Error(), tok)
		if strings.TrimSpace(out) != "" {
			msg = token.Redact(out, tok) + "\n" + msg
		}
		return textResult(msg, true), nil
	}

	return textResult(token.Redact(out, tok), false), nil
}

func formatTokenReadError(err error) string {
	switch {
	case errors.Is(err, token.ErrNotFound), errors.Is(err, token.ErrEmptyToken):
		return missingTokenGuidance
	case errors.Is(err, token.ErrInvalidPermissions), errors.Is(err, token.ErrInvalidOwner):
		return "Token file failed security validation (fail-closed): " + err.Error()
	default:
		return "Failed to read tsudo token: " + err.Error()
	}
}

func decodeObjectArgs(raw json.RawMessage, dst any, required bool) *RPCError {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		if required {
			return &RPCError{
				Code:    ErrCodeInvalidParams,
				Message: "missing required parameters",
			}
		}
		return nil
	}
	if trimmed[0] != '{' {
		return &RPCError{
			Code:    ErrCodeInvalidParams,
			Message: "parameters must be a JSON object",
		}
	}
	if err := json.Unmarshal(trimmed, dst); err != nil {
		return &RPCError{
			Code:    ErrCodeInvalidParams,
			Message: "invalid parameters: " + err.Error(),
		}
	}
	return nil
}

func textResult(text string, isError bool) CallToolResult {
	return CallToolResult{
		Content: []ToolContent{
			{
				Type: "text",
				Text: text,
			},
		},
		IsError: isError,
	}
}
