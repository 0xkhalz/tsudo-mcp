package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFakeTsudoScript(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tsudo")
	if err := os.WriteFile(path, []byte("#!/usr/bin/env sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake tsudo: %v", err)
	}
	return path
}

func TestRunVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long flag", args: []string{"--version"}},
		{name: "short flag", args: []string{"-v"}},
		{name: "subcommand", args: []string{"version"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(tc.args, strings.NewReader(""), &stdout, &stderr)

			if code != 0 {
				t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
			}
			want := "tsudo-mcp " + Version + "\n"
			if stdout.String() != want {
				t.Fatalf("expected stdout %q, got %q", want, stdout.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected empty stderr, got %q", stderr.String())
			}
		})
	}
}

func TestRunHelp(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long flag", args: []string{"--help"}},
		{name: "short flag", args: []string{"-h"}},
		{name: "subcommand", args: []string{"help"}},
	}

	requiredSubcommands := []string{
		"serve",
		"grant [duration]",
		"status",
		"clear",
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(tc.args, strings.NewReader(""), &stdout, &stderr)

			if code != 0 {
				t.Fatalf("expected exit code 0, got %d (stderr=%q)", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("expected empty stderr, got %q", stderr.String())
			}
			out := stdout.String()
			for _, sub := range requiredSubcommands {
				if !strings.Contains(out, sub) {
					t.Errorf("expected help output to contain %q, got:\n%s", sub, out)
				}
			}
		})
	}
}

func TestRunUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer

	code := run([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr)

	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected empty stdout, got %q", stdout.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, `unknown command "bogus"`) {
		t.Errorf("expected unknown command message, got %q", errOut)
	}
	if !strings.Contains(errOut, "Usage:") {
		t.Errorf("expected usage text, got %q", errOut)
	}
}

func TestGrantSuccessNextLineAndSameLine(t *testing.T) {
	const secretToken = "tok_secret_9876543210"

	tests := []struct {
		name         string
		args         []string
		tsudoOutput  string
		expectPrompt bool
	}{
		{
			name: "next-line token with duration",
			args: []string{"grant", "30m"},
			tsudoOutput: `printf 'sudo password: '
read -r _pw || true
printf '\nTemporary tsudo token:\n` + secretToken + `\nExpires at: 2026-11-22T20:00:00Z\nGive this temporary token to the AI agent instead of your sudo password.\n'`,
			expectPrompt: true,
		},
		{
			name: "same-line token without duration",
			args: []string{"grant"},
			tsudoOutput: `printf 'sudo password: \n'
printf 'Temporary tsudo token: ` + secretToken + `\nExpires at: 2026-11-22T20:10:00Z\nGive this temporary token to the AI agent.\n'`,
			expectPrompt: true,
		},
		{
			name:         "token on first line without prompt",
			args:         []string{"grant", "1h"},
			tsudoOutput:  `printf 'Temporary tsudo token: ` + secretToken + `\nExpires at: 2026-11-22T21:00:00Z\n'`,
			expectPrompt: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokPath := filepath.Join(t.TempDir(), "tsudo-token")
			t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

			argLog := filepath.Join(t.TempDir(), "args.txt")
			script := "printf '%s\\n' \"$*\" > " + argLog + "\n" + tc.tsudoOutput + "\n"
			fakeTsudo := writeFakeTsudoScript(t, script)

			var stdout, stderr bytes.Buffer
			code := runWithBinary(tc.args, fakeTsudo, strings.NewReader("hunter2\n"), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
			}

			out := stdout.String()
			errOut := stderr.String()
			if strings.Contains(out, secretToken) || strings.Contains(errOut, secretToken) {
				t.Fatalf("raw token leaked in output: stdout=%q stderr=%q", out, errOut)
			}
			if strings.Contains(out, "Temporary tsudo token:") {
				t.Fatalf("token header should be suppressed, got stdout=%q", out)
			}
			if strings.Contains(out, "Give this temporary token") {
				t.Fatalf("instruction line should be suppressed, got stdout=%q", out)
			}
			if tc.expectPrompt && !strings.Contains(out, "sudo password: ") {
				t.Errorf("expected prompt in stdout, got %q", out)
			}
			if !strings.Contains(out, "Expires at: ") {
				t.Errorf("expected expiry line in stdout, got %q", out)
			}
			if !strings.Contains(out, "Token saved to "+tokPath+" (mode 0600).") {
				t.Errorf("expected saved confirmation in stdout, got %q", out)
			}

			data, err := os.ReadFile(tokPath)
			if err != nil {
				t.Fatalf("read token file: %v", err)
			}
			if strings.TrimSpace(string(data)) != secretToken {
				t.Fatalf("token file content = %q, want %q", strings.TrimSpace(string(data)), secretToken)
			}
			info, err := os.Stat(tokPath)
			if err != nil {
				t.Fatalf("stat token file: %v", err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("token file mode = %04o, want 0600", info.Mode().Perm())
			}

			loggedArgs, err := os.ReadFile(argLog)
			if err != nil {
				t.Fatalf("read arg log: %v", err)
			}
			wantArg := ""
			if len(tc.args) > 1 {
				wantArg = tc.args[1]
			}
			if strings.TrimSpace(string(loggedArgs)) != wantArg {
				t.Fatalf("tsudo received args %q, want %q", strings.TrimSpace(string(loggedArgs)), wantArg)
			}
		})
	}
}

func TestGrantValidationErrorsDoNotSpawnTsudo(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "invalid duration", args: []string{"grant", "5x"}},
		{name: "extra arguments", args: []string{"grant", "10m", "extra"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tokPath := filepath.Join(t.TempDir(), "tsudo-token")
			t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

			marker := filepath.Join(t.TempDir(), "spawned")
			fakeTsudo := writeFakeTsudoScript(t, "touch "+marker+"\n")

			var stdout, stderr bytes.Buffer
			code := runWithBinary(tc.args, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
			if code == 0 {
				t.Fatalf("expected non-zero exit code, got 0")
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("fake tsudo should not have been spawned")
			}
		})
	}
}

func TestGrantMissingEnvDoesNotSpawnTsudo(t *testing.T) {
	t.Setenv("TSUDO_MCP_TOKEN_FILE", "")
	t.Setenv("XDG_RUNTIME_DIR", "")

	marker := filepath.Join(t.TempDir(), "spawned")
	fakeTsudo := writeFakeTsudoScript(t, "touch "+marker+"\n")

	var stdout, stderr bytes.Buffer
	code := runWithBinary([]string{"grant", "10m"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit code")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("fake tsudo should not have been spawned when token path env is unset")
	}
}

func TestGrantFailureDoesNotWriteToken(t *testing.T) {
	tokPath := filepath.Join(t.TempDir(), "tsudo-token")
	t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

	fakeTsudo := writeFakeTsudoScript(t, "printf 'sudo password: '\nexit 1\n")

	var stdout, stderr bytes.Buffer
	code := runWithBinary([]string{"grant", "15m"}, fakeTsudo, strings.NewReader("wrong\n"), &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
	if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
		t.Fatalf("token file must not be written when tsudo fails")
	}
}

func TestStatus(t *testing.T) {
	const secretToken = "tok_status_never_expose_12345"

	t.Run("active session and valid token file", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "tsudo-token")
		if err := os.WriteFile(tokPath, []byte(secretToken+"\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "printf 'Active tsudo session expires at 2026-11-22T20:00:00Z.\n'\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"status"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String(), secretToken) || strings.Contains(stderr.String(), secretToken) {
			t.Fatalf("status leaked raw token")
		}
		if !strings.Contains(stdout.String(), "Active tsudo session") {
			t.Errorf("expected tsudo status output, got %q", stdout.String())
		}
	})

	t.Run("missing token file returns 1", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "missing-token")
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "printf 'Active tsudo session expires at 2026-11-22T20:00:00Z.\n'\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"status"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit 1 when token missing, got %d", code)
		}
	})

	t.Run("invalid permissions returns 1", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "bad-perms-token")
		if err := os.WriteFile(tokPath, []byte(secretToken+"\n"), 0o644); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "printf 'Active tsudo session expires at 2026-11-22T20:00:00Z.\n'\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"status"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit 1 on 0644 token file, got %d", code)
		}
	})

	t.Run("no active tsudo session returns 1", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "tsudo-token")
		if err := os.WriteFile(tokPath, []byte(secretToken+"\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "printf 'No active tsudo session.\n'; exit 1\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"status"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit 1 when no active session, got %d", code)
		}
	})

	t.Run("expired tsudo session returns 1", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "tsudo-token")
		if err := os.WriteFile(tokPath, []byte(secretToken+"\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "printf 'Session expired.\n'; exit 1\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"status"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit 1 when session expired, got %d", code)
		}
	})
}

func TestClear(t *testing.T) {
	t.Run("removes token file and invokes tsudo clear", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "tsudo-token")
		if err := os.WriteFile(tokPath, []byte("tok_12345678\n"), 0o600); err != nil {
			t.Fatalf("write token file: %v", err)
		}
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		invoked := filepath.Join(t.TempDir(), "invoked")
		fakeTsudo := writeFakeTsudoScript(t, "printf '%s' \"$*\" > "+invoked+"\nprintf 'Session cleared.\n'\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"clear"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
		}
		if _, err := os.Stat(tokPath); !os.IsNotExist(err) {
			t.Fatalf("expected token file to be removed")
		}
		gotArgs, err := os.ReadFile(invoked)
		if err != nil {
			t.Fatalf("read invoked args: %v", err)
		}
		if string(gotArgs) != "clear" {
			t.Fatalf("expected tsudo invoked with 'clear', got %q", string(gotArgs))
		}
		if !strings.Contains(stdout.String(), "Cleared token file") {
			t.Errorf("expected confirmation in stdout, got %q", stdout.String())
		}
	})

	t.Run("ignores ENOENT on missing token file", func(t *testing.T) {
		tokPath := filepath.Join(t.TempDir(), "nonexistent-token")
		t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

		fakeTsudo := writeFakeTsudoScript(t, "exit 0\n")

		var stdout, stderr bytes.Buffer
		code := runWithBinary([]string{"clear"}, fakeTsudo, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
		}
	})
}

func TestServeInitializeAndPing(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "explicit serve", args: []string{"serve"}},
		{name: "default empty args", args: nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokPath := filepath.Join(t.TempDir(), "tsudo-token")
			t.Setenv("TSUDO_MCP_TOKEN_FILE", tokPath)

			fakeTsudo := writeFakeTsudoScript(t, "exit 0\n")
			input := strings.Join([]string{
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
				`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
				`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
			}, "\n") + "\n"

			var stdout, stderr bytes.Buffer
			code := runWithBinary(tc.args, fakeTsudo, strings.NewReader(input), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("expected exit 0, got %d (stderr=%q)", code, stderr.String())
			}

			lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
			if len(lines) != 2 {
				t.Fatalf("expected 2 JSON-RPC response lines, got %d: %q", len(lines), stdout.String())
			}

			var initResp map[string]any
			if err := json.Unmarshal([]byte(lines[0]), &initResp); err != nil {
				t.Fatalf("unmarshal initialize response: %v (line=%q)", err, lines[0])
			}
			result, ok := initResp["result"].(map[string]any)
			if !ok {
				t.Fatalf("expected result object in initialize response, got %v", initResp)
			}
			serverInfo, ok := result["serverInfo"].(map[string]any)
			if !ok || serverInfo["name"] != "tsudo-mcp" {
				t.Fatalf("unexpected serverInfo: %v", result["serverInfo"])
			}

			var pingResp map[string]any
			if err := json.Unmarshal([]byte(lines[1]), &pingResp); err != nil {
				t.Fatalf("unmarshal ping response: %v (line=%q)", err, lines[1])
			}
			if id, ok := pingResp["id"].(float64); !ok || id != 2 {
				t.Fatalf("expected ping id 2, got %v", pingResp["id"])
			}
		})
	}
}
