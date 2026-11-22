package main

import (
	"bytes"
	"strings"
	"testing"
)

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

func TestRunInvalidOrUnimplementedCommands(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCode    int
		wantStderr  string
		expectUsage bool
	}{
		{
			name:        "no arguments",
			args:        nil,
			wantCode:    2,
			wantStderr:  "missing command",
			expectUsage: true,
		},
		{
			name:        "unknown subcommand",
			args:        []string{"bogus"},
			wantCode:    2,
			wantStderr:  `unknown command "bogus"`,
			expectUsage: true,
		},
		{
			name:       "serve stub",
			args:       []string{"serve"},
			wantCode:   1,
			wantStderr: "not implemented yet",
		},
		{
			name:       "grant stub",
			args:       []string{"grant", "10m"},
			wantCode:   1,
			wantStderr: "not implemented yet",
		},
		{
			name:       "status stub",
			args:       []string{"status"},
			wantCode:   1,
			wantStderr: "not implemented yet",
		},
		{
			name:       "clear stub",
			args:       []string{"clear"},
			wantCode:   1,
			wantStderr: "not implemented yet",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer

			code := run(tc.args, strings.NewReader(""), &stdout, &stderr)

			if code != tc.wantCode {
				t.Fatalf("expected exit code %d, got %d", tc.wantCode, code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("expected empty stdout, got %q", stdout.String())
			}
			errOut := stderr.String()
			if !strings.Contains(errOut, tc.wantStderr) {
				t.Errorf("expected stderr to contain %q, got %q", tc.wantStderr, errOut)
			}
			if tc.expectUsage && !strings.Contains(errOut, "Usage:") {
				t.Errorf("expected stderr to contain usage text, got %q", errOut)
			}
		})
	}
}
