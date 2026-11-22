package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/0xkhalz/tsudo-mcp/internal/policy"
	"github.com/0xkhalz/tsudo-mcp/internal/runner"
	"github.com/0xkhalz/tsudo-mcp/internal/token"
)

const sentinelToken = "tsudo_tok_SECRET_SENTINEL_9f8e7d6c"

type fakeStore struct {
	mu        sync.Mutex
	path      string
	tok       string
	readErr   error
	statInfo  token.Info
	statErr   error
	readCalls int
	statCalls int
}

func (f *fakeStore) Read() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readCalls++
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.tok, nil
}

func (f *fakeStore) Write(tok string) error { return nil }
func (f *fakeStore) Clear() error           { return nil }

func (f *fakeStore) Stat() (token.Info, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statCalls++
	info := f.statInfo
	if info.Path == "" {
		info.Path = f.path
	}
	return info, f.statErr
}

func (f *fakeStore) Path() string { return f.path }

type fakeRunner struct {
	mu         sync.Mutex
	execCalls  int
	lastTok    string
	lastReq    runner.ExecRequest
	execResult runner.ExecResult
	execErr    error
	statusOut  string
	statusErr  error
	logsCalls  int
	lastCount  int
	lastCheck  bool
	logsOut    string
	logsErr    error
}

func (f *fakeRunner) Exec(_ context.Context, tok string, req runner.ExecRequest) (runner.ExecResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execCalls++
	f.lastTok = tok
	f.lastReq = req
	return f.execResult, f.execErr
}

func (f *fakeRunner) Status(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.statusOut, f.statusErr
}

func (f *fakeRunner) Logs(_ context.Context, count int, check bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logsCalls++
	f.lastCount = count
	f.lastCheck = check
	return f.logsOut, f.logsErr
}

func runBatch(t *testing.T, store token.Store, eval policy.Evaluator, run runner.Runner, requests ...string) ([]Response, string) {
	t.Helper()
	var in bytes.Buffer
	for _, r := range requests {
		in.WriteString(r)
		in.WriteByte('\n')
	}
	var out, errBuf bytes.Buffer
	srv := NewServer("0.1.0-test", store, eval, run, &errBuf)
	if err := srv.Serve(context.Background(), &in, &out); err != nil {
		t.Fatalf("Serve returned unexpected error: %v", err)
	}
	raw := out.String()
	assertValidJSONRPCLines(t, raw, sentinelToken)
	if strings.Contains(errBuf.String(), sentinelToken) {
		t.Fatalf("stderr leaked sentinel token: %s", errBuf.String())
	}
	return decodeResponses(t, raw), raw
}

func decodeResponses(t *testing.T, raw string) []Response {
	t.Helper()
	var resps []Response
	for line := range strings.SplitSeq(raw, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var resp Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("failed to unmarshal response line %q: %v", line, err)
		}
		resps = append(resps, resp)
	}
	return resps
}

func assertValidJSONRPCLines(t *testing.T, raw, secret string) {
	t.Helper()
	if secret != "" && strings.Contains(raw, secret) {
		t.Fatalf("output leaked secret token: %s", raw)
	}
	if raw == "" {
		return
	}
	if !strings.HasSuffix(raw, "\n") {
		t.Fatalf("output does not end with newline: %q", raw)
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	for i, line := range lines {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("line %d is not valid JSON (%v): %q", i, err, line)
		}
		if m["jsonrpc"] != "2.0" {
			t.Fatalf("line %d missing jsonrpc=2.0: %q", i, line)
		}
		if _, hasID := m["id"]; !hasID {
			t.Fatalf("line %d missing id field: %q", i, line)
		}
		_, hasResult := m["result"]
		_, hasError := m["error"]
		if hasResult == hasError {
			t.Fatalf("line %d must have exactly one of result or error: %q", i, line)
		}
	}
}

func decodeToolResult(t *testing.T, resp Response) CallToolResult {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("expected tool result, got JSON-RPC error %+v", resp.Error)
	}
	var res CallToolResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("failed to decode CallToolResult: %v (%s)", err, string(resp.Result))
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected non-empty content in CallToolResult")
	}
	return res
}

func TestServe_HandshakeAndToolsListOverPipe(t *testing.T) {
	prIn, pwIn := io.Pipe()
	prOut, pwOut := io.Pipe()

	store := &fakeStore{path: "/run/user/1000/tsudo-token", tok: sentinelToken}
	eval := policy.New(policy.Config{})
	run := &fakeRunner{}
	var stderr bytes.Buffer

	srv := NewServer("1.2.3", store, eval, run, &stderr)
	serveDone := make(chan error, 1)
	go func() {
		defer pwOut.Close()
		serveDone <- srv.Serve(context.Background(), prIn, pwOut)
	}()

	var outBuf bytes.Buffer
	readDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(&outBuf, prOut)
		readDone <- err
	}()

	msgs := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":null,"method":"notifications/cancelled","params":{"requestId":99}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":"list-1","method":"tools/list"}`,
	}
	for _, m := range msgs {
		if _, err := io.WriteString(pwIn, m+"\n"); err != nil {
			t.Fatalf("write request failed: %v", err)
		}
	}
	_ = pwIn.Close()

	if err := <-serveDone; err != nil {
		t.Fatalf("Serve failed: %v", err)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("reading output failed: %v", err)
	}

	raw := outBuf.String()
	assertValidJSONRPCLines(t, raw, sentinelToken)
	resps := decodeResponses(t, raw)
	if len(resps) != 3 {
		t.Fatalf("expected 3 responses (notifications must emit nothing), got %d: %s", len(resps), raw)
	}

	// 1. initialize
	if string(resps[0].ID) != "1" {
		t.Fatalf("expected id=1, got %s", string(resps[0].ID))
	}
	var initRes InitializeResult
	if err := json.Unmarshal(resps[0].Result, &initRes); err != nil {
		t.Fatalf("unmarshal initialize: %v", err)
	}
	if initRes.ProtocolVersion != "2024-11-05" || initRes.ServerInfo.Name != "tsudo-mcp" || initRes.ServerInfo.Version != "1.2.3" {
		t.Fatalf("unexpected initialize result: %+v", initRes)
	}
	if initRes.Capabilities.Tools == nil {
		t.Fatalf("expected capabilities.tools to be non-nil")
	}

	// 2. ping
	if string(resps[1].ID) != "2" || string(resps[1].Result) != "{}" {
		t.Fatalf("unexpected ping response: id=%s result=%s", string(resps[1].ID), string(resps[1].Result))
	}

	// 3. tools/list
	if string(resps[2].ID) != `"list-1"` {
		t.Fatalf("expected id=%q, got %s", "list-1", string(resps[2].ID))
	}
	var toolsRes ToolsListResult
	if err := json.Unmarshal(resps[2].Result, &toolsRes); err != nil {
		t.Fatalf("unmarshal tools/list: %v", err)
	}
	if len(toolsRes.Tools) != 3 {
		t.Fatalf("expected 3 tools, got %d", len(toolsRes.Tools))
	}
	gotNames := []string{toolsRes.Tools[0].Name, toolsRes.Tools[1].Name, toolsRes.Tools[2].Name}
	wantNames := []string{"sudo_exec", "sudo_status", "sudo_logs"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("tool names = %v, want %v", gotNames, wantNames)
	}
}

func TestServe_EOFWithoutTrailingNewlineAndBlankLines(t *testing.T) {
	input := "\n   \n" + `{"jsonrpc":"2.0","id":7,"method":"ping"}`
	var out bytes.Buffer
	srv := NewServer("0.1.0", &fakeStore{}, policy.New(policy.Config{}), &fakeRunner{}, io.Discard)
	if err := srv.Serve(context.Background(), strings.NewReader(input), &out); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}
	assertValidJSONRPCLines(t, out.String(), "")
	resps := decodeResponses(t, out.String())
	if len(resps) != 1 || string(resps[0].ID) != "7" || string(resps[0].Result) != "{}" {
		t.Fatalf("unexpected responses: %+v", resps)
	}
}

func TestServe_ContextCancellation(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	ctx, cancel := context.WithCancel(context.Background())
	srv := NewServer("0.1.0", &fakeStore{}, policy.New(policy.Config{}), &fakeRunner{}, io.Discard)

	done := make(chan error, 1)
	go func() {
		done <- srv.Serve(ctx, pr, io.Discard)
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected clean nil return on context cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not exit promptly after ctx.Done()")
	}
}

func TestServe_MaxLineExceededRecoversFraming(t *testing.T) {
	oversized := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"` + strings.Repeat("a", MaxLineBytes+64) + `"}}`
	followUp := `{"jsonrpc":"2.0","id":2,"method":"ping"}`

	resps, _ := runBatch(t, &fakeStore{}, policy.New(policy.Config{}), &fakeRunner{}, oversized, followUp)
	if len(resps) != 2 {
		t.Fatalf("expected 2 responses, got %d", len(resps))
	}
	if resps[0].Error == nil || resps[0].Error.Code != ErrCodeInvalidRequest {
		t.Fatalf("expected -32600 for oversized line, got %+v", resps[0].Error)
	}
	if resps[1].Error != nil || string(resps[1].ID) != "2" || string(resps[1].Result) != "{}" {
		t.Fatalf("expected valid ping after oversized line, got %+v", resps[1])
	}
}

func TestServe_JSONRPCErrors(t *testing.T) {
	tests := []struct {
		name     string
		req      string
		wantCode int
		wantID   string
	}{
		{
			name:     "malformed json",
			req:      `{"jsonrpc":"2.0",`,
			wantCode: ErrCodeParse,
			wantID:   "null",
		},
		{
			name:     "invalid jsonrpc version",
			req:      `{"jsonrpc":"1.0","id":1,"method":"ping"}`,
			wantCode: ErrCodeInvalidRequest,
			wantID:   "1",
		},
		{
			name:     "missing method",
			req:      `{"jsonrpc":"2.0","id":2}`,
			wantCode: ErrCodeInvalidRequest,
			wantID:   "2",
		},
		{
			name:     "json array instead of request object",
			req:      `[]`,
			wantCode: ErrCodeInvalidRequest,
			wantID:   "null",
		},
		{
			name:     "invalid id type object",
			req:      `{"jsonrpc":"2.0","id":{},"method":"ping"}`,
			wantCode: ErrCodeInvalidRequest,
			wantID:   "null",
		},
		{
			name:     "unknown method",
			req:      `{"jsonrpc":"2.0","id":"m1","method":"unknown/method"}`,
			wantCode: ErrCodeMethodNotFound,
			wantID:   `"m1"`,
		},
		{
			name:     "unknown tool",
			req:      `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sudo_magic","arguments":{}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "3",
		},
		{
			name:     "sudo_exec missing command",
			req:      `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"sudo_exec","arguments":{}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "4",
		},
		{
			name:     "sudo_exec empty command",
			req:      `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":""}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "5",
		},
		{
			name:     "sudo_exec invalid command type",
			req:      `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":123}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "6",
		},
		{
			name:     "sudo_exec invalid args element type",
			req:      `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"ls","args":["-l",null]}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "7",
		},
		{
			name:     "sudo_exec negative timeout",
			req:      `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"ls","timeout_seconds":-1}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "8",
		},
		{
			name:     "sudo_exec non-integer timeout",
			req:      `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"ls","timeout_seconds":1.5}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "9",
		},
		{
			name:     "sudo_logs invalid count type",
			req:      `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"sudo_logs","arguments":{"count":"20"}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "10",
		},
		{
			name:     "sudo_logs negative count",
			req:      `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"sudo_logs","arguments":{"count":-5}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "11",
		},
		{
			name:     "sudo_logs invalid check type",
			req:      `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"sudo_logs","arguments":{"check":"true"}}}`,
			wantCode: ErrCodeInvalidParams,
			wantID:   "12",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resps, _ := runBatch(t, &fakeStore{}, policy.New(policy.Config{}), &fakeRunner{}, tc.req)
			if len(resps) != 1 {
				t.Fatalf("expected 1 response, got %d", len(resps))
			}
			if resps[0].Error == nil {
				t.Fatalf("expected JSON-RPC error, got result: %s", string(resps[0].Result))
			}
			if resps[0].Error.Code != tc.wantCode {
				t.Fatalf("error code = %d, want %d (msg=%q)", resps[0].Error.Code, tc.wantCode, resps[0].Error.Message)
			}
			if string(resps[0].ID) != tc.wantID {
				t.Fatalf("error id = %s, want %s", string(resps[0].ID), tc.wantID)
			}
		})
	}
}

func TestSudoExec_PolicyDenialSkipsTokenStoreAndRunner(t *testing.T) {
	denied := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"visudo"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"sh","args":["-c","id"]}}}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"sudo","args":["rm","-rf","/"]}}}`,
	}

	for _, req := range denied {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError {
			t.Fatalf("expected isError=true for denied request %s", req)
		}
		if !strings.HasPrefix(res.Content[0].Text, "Blocked by safety policy: ") {
			t.Fatalf("unexpected policy denial message: %q", res.Content[0].Text)
		}
		if store.readCalls != 0 {
			t.Fatalf("expected token store Read() NOT to be called on policy denial, got %d calls", store.readCalls)
		}
		if run.execCalls != 0 {
			t.Fatalf("expected runner Exec() NOT to be called on policy denial, got %d calls", run.execCalls)
		}
	}
}

func TestSudoExec_TokenErrorsAndFailClosedSecurity(t *testing.T) {
	const wantMissingGuidance = "No active tsudo token (or session expired). Ask the user to run: tsudo-mcp grant 30m"
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"id"}}}`

	t.Run("missing token file", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrNotFound}
		run := &fakeRunner{}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || res.Content[0].Text != wantMissingGuidance {
			t.Fatalf("got isError=%v text=%q, want %q", res.IsError, res.Content[0].Text, wantMissingGuidance)
		}
		if run.execCalls != 0 {
			t.Fatalf("runner must not be called when token missing")
		}
	})

	t.Run("empty token file", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrEmptyToken}
		run := &fakeRunner{}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || res.Content[0].Text != wantMissingGuidance {
			t.Fatalf("got isError=%v text=%q, want %q", res.IsError, res.Content[0].Text, wantMissingGuidance)
		}
		if run.execCalls != 0 {
			t.Fatalf("runner must not be called when token empty")
		}
	})

	t.Run("expired token reported by runner", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{execErr: runner.ErrTokenInvalidOrExpired}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || res.Content[0].Text != wantMissingGuidance {
			t.Fatalf("got isError=%v text=%q, want %q", res.IsError, res.Content[0].Text, wantMissingGuidance)
		}
	})

	t.Run("bad permissions fails closed", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrInvalidPermissions}
		run := &fakeRunner{}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || !strings.Contains(res.Content[0].Text, "fail-closed") {
			t.Fatalf("expected fail-closed error, got isError=%v text=%q", res.IsError, res.Content[0].Text)
		}
		if run.execCalls != 0 {
			t.Fatalf("runner must not be called on bad permissions")
		}
	})

	t.Run("wrong owner fails closed", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrInvalidOwner}
		run := &fakeRunner{}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || !strings.Contains(res.Content[0].Text, "fail-closed") {
			t.Fatalf("expected fail-closed error, got isError=%v text=%q", res.IsError, res.Content[0].Text)
		}
		if run.execCalls != 0 {
			t.Fatalf("runner must not be called on wrong owner")
		}
	})
}

func TestSudoExec_ExecutionOutcomesAndTokenRedaction(t *testing.T) {
	t.Run("success with sudo normalization and redaction", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{
			execResult: runner.ExecResult{
				ExitCode:  0,
				TimedOut:  false,
				Truncated: true,
				Stdout:    "ok token=" + sentinelToken,
				Stderr:    "warn token=" + sentinelToken,
			},
		}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"sudo","args":["systemctl","status"],"cwd":"/tmp","timeout_seconds":15}}}`
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sentinel token appeared in raw output: %s", raw)
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError {
			t.Fatalf("expected isError=false, got true: %s", res.Content[0].Text)
		}
		if run.lastReq.Command != "systemctl" || !slices.Equal(run.lastReq.Args, []string{"status"}) {
			t.Fatalf("expected normalized command/args, got %+v", run.lastReq)
		}
		if run.lastReq.Cwd != "/tmp" || run.lastReq.Timeout != 15*time.Second {
			t.Fatalf("unexpected cwd/timeout: %+v", run.lastReq)
		}
		txt := res.Content[0].Text
		for _, want := range []string{"exit_code: 0", "timed_out: false", "truncated: true", "ok token=[REDACTED]", "warn token=[REDACTED]"} {
			if !strings.Contains(txt, want) {
				t.Fatalf("output missing %q in:\n%s", want, txt)
			}
		}
	})

	t.Run("non-zero exit sets isError", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{
			execResult: runner.ExecResult{
				ExitCode: 2,
				Stderr:   "failed",
			},
		}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"ls","args":["/nonexistent"]}}}`
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError {
			t.Fatalf("expected isError=true on non-zero exit code")
		}
		if !strings.Contains(res.Content[0].Text, "exit_code: 2") {
			t.Fatalf("expected exit_code: 2 in %q", res.Content[0].Text)
		}
	})

	t.Run("timed out sets isError", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{
			execResult: runner.ExecResult{
				ExitCode: -1,
				TimedOut: true,
			},
		}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"sleep","args":["10"],"timeout_seconds":1}}}`
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if !res.IsError || !strings.Contains(res.Content[0].Text, "timed_out: true") {
			t.Fatalf("expected isError=true and timed_out: true, got isError=%v text=%q", res.IsError, res.Content[0].Text)
		}
	})

	t.Run("runner error redacts token", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{
			execErr: errors.New("fork failed with --token " + sentinelToken),
		}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_exec","arguments":{"command":"id"}}}`
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sentinel token leaked in error output: %s", raw)
		}
		res := decodeToolResult(t, resps[0])
		if !res.IsError || !strings.Contains(res.Content[0].Text, "[REDACTED]") {
			t.Fatalf("expected redacted error result, got isError=%v text=%q", res.IsError, res.Content[0].Text)
		}
	})
}

func TestSudoStatus(t *testing.T) {
	req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_status","arguments":{}}}`

	t.Run("valid token", func(t *testing.T) {
		store := &fakeStore{
			path: "/run/user/1000/tsudo-token",
			tok:  sentinelToken,
			statInfo: token.Info{
				Path:    "/run/user/1000/tsudo-token",
				Exists:  true,
				Mode:    fs.FileMode(0o600),
				UID:     1000,
				ModTime: time.Date(2026, 11, 22, 19, 0, 0, 0, time.UTC),
				Valid:   true,
			},
		}
		run := &fakeRunner{statusOut: "tsudo session active (expires in 25m)"}
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sudo_status leaked sentinel token: %s", raw)
		}
		if store.readCalls != 0 {
			t.Fatalf("sudo_status must not call store.Read()")
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError {
			t.Fatalf("expected isError=false, got true: %s", res.Content[0].Text)
		}
		for _, want := range []string{"token_valid: true", "token_mode: 0600", "tsudo session active"} {
			if !strings.Contains(res.Content[0].Text, want) {
				t.Fatalf("missing %q in %q", want, res.Content[0].Text)
			}
		}
	})

	t.Run("missing token", func(t *testing.T) {
		store := &fakeStore{
			path: "/run/user/1000/tsudo-token",
			statInfo: token.Info{
				Path:   "/run/user/1000/tsudo-token",
				Exists: false,
				Valid:  false,
				Err:    token.ErrNotFound,
			},
		}
		run := &fakeRunner{statusOut: "no active tsudo session"}
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		res := decodeToolResult(t, resps[0])
		if res.IsError {
			t.Fatalf("expected isError=false for missing status inspection")
		}
		if !strings.Contains(res.Content[0].Text, "token_valid: false") || !strings.Contains(res.Content[0].Text, token.ErrNotFound.Error()) {
			t.Fatalf("unexpected status text: %q", res.Content[0].Text)
		}
	})

	t.Run("bad permissions", func(t *testing.T) {
		store := &fakeStore{
			path: "/run/user/1000/tsudo-token",
			tok:  sentinelToken,
			statInfo: token.Info{
				Path:   "/run/user/1000/tsudo-token",
				Exists: true,
				Mode:   fs.FileMode(0o644),
				UID:    1000,
				Valid:  false,
				Err:    token.ErrInvalidPermissions,
			},
		}
		run := &fakeRunner{statusOut: "no active tsudo session"}
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sudo_status leaked sentinel token")
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError {
			t.Fatalf("expected isError=false for bad-perms status inspection")
		}
		if !strings.Contains(res.Content[0].Text, "token_mode: 0644") || !strings.Contains(res.Content[0].Text, token.ErrInvalidPermissions.Error()) {
			t.Fatalf("unexpected status text: %q", res.Content[0].Text)
		}
	})
}

func TestSudoLogs(t *testing.T) {
	t.Run("default count and token redaction", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{logsOut: "entry1 token=" + sentinelToken}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_logs"}}`
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sudo_logs leaked sentinel token: %s", raw)
		}
		if run.lastCount != 20 || run.lastCheck {
			t.Fatalf("expected default count=20 check=false, got count=%d check=%v", run.lastCount, run.lastCheck)
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError || res.Content[0].Text != "entry1 token=[REDACTED]" {
			t.Fatalf("unexpected logs result: isError=%v text=%q", res.IsError, res.Content[0].Text)
		}
	})

	t.Run("custom count and missing token ignored", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrNotFound}
		run := &fakeRunner{logsOut: "log line"}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_logs","arguments":{"count":50}}}`
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if run.lastCount != 50 || run.lastCheck {
			t.Fatalf("expected count=50 check=false, got count=%d check=%v", run.lastCount, run.lastCheck)
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError || res.Content[0].Text != "log line" {
			t.Fatalf("unexpected logs result: %+v", res)
		}
	})

	t.Run("check mode", func(t *testing.T) {
		store := &fakeStore{readErr: token.ErrNotFound}
		run := &fakeRunner{logsOut: "tsudo check ok"}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_logs","arguments":{"check":true}}}`
		resps, _ := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if !run.lastCheck {
			t.Fatalf("expected check=true")
		}
		res := decodeToolResult(t, resps[0])
		if res.IsError || res.Content[0].Text != "tsudo check ok" {
			t.Fatalf("unexpected check result: %+v", res)
		}
	})

	t.Run("runner error returns isError with redacted output", func(t *testing.T) {
		store := &fakeStore{tok: sentinelToken}
		run := &fakeRunner{
			logsOut: "partial " + sentinelToken,
			logsErr: errors.New("exit 1 " + sentinelToken),
		}
		req := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sudo_logs","arguments":{}}}`
		resps, raw := runBatch(t, store, policy.New(policy.Config{}), run, req)
		if strings.Contains(raw, sentinelToken) {
			t.Fatalf("sentinel token leaked in error output: %s", raw)
		}
		res := decodeToolResult(t, resps[0])
		if !res.IsError || !strings.Contains(res.Content[0].Text, "[REDACTED]") {
			t.Fatalf("expected redacted error result, got %+v", res)
		}
	})
}
