package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func writeFakeScript(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "tsudo")
	content := "#!/usr/bin/env sh\n" + body
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatalf("write fake script: %v", err)
	}
	return path
}

func TestLimitedBuffer(t *testing.T) {
	t.Run("within and over limit", func(t *testing.T) {
		buf := NewLimitedBuffer(10)
		n, err := buf.Write([]byte("hello"))
		if err != nil || n != 5 {
			t.Fatalf("first write got (%d, %v), want (5, nil)", n, err)
		}
		if buf.Truncated() {
			t.Fatal("expected Truncated()=false after 5 bytes")
		}

		n, err = buf.Write([]byte(" world!"))
		if err != nil || n != 7 {
			t.Fatalf("second write got (%d, %v), want (7, nil)", n, err)
		}
		if !buf.Truncated() {
			t.Fatal("expected Truncated()=true after exceeding limit")
		}
		if got := buf.String(); got != "hello worl" {
			t.Fatalf("got %q, want %q", got, "hello worl")
		}

		// Subsequent writes when already full still return len(p), nil.
		n, err = buf.Write([]byte("more"))
		if err != nil || n != 4 {
			t.Fatalf("third write got (%d, %v), want (4, nil)", n, err)
		}
		if got := buf.String(); got != "hello worl" {
			t.Fatalf("got %q, want %q", got, "hello worl")
		}
	})

	t.Run("zero limit discards all", func(t *testing.T) {
		buf := NewLimitedBuffer(0)
		n, err := buf.Write([]byte("abc"))
		if err != nil || n != 3 {
			t.Fatalf("got (%d, %v), want (3, nil)", n, err)
		}
		if !buf.Truncated() {
			t.Fatal("expected Truncated()=true")
		}
		if buf.String() != "" {
			t.Fatalf("got %q, want empty", buf.String())
		}
	})

	t.Run("concurrent writes", func(t *testing.T) {
		buf := NewLimitedBuffer(128)
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 20; j++ {
					_, _ = buf.Write([]byte("0123456789"))
				}
			}()
		}
		wg.Wait()
		if !buf.Truncated() {
			t.Fatal("expected Truncated()=true")
		}
		if len(buf.String()) != 128 {
			t.Fatalf("len=%d, want 128", len(buf.String()))
		}
	})
}

func TestDefaultTimeoutFromEnv(t *testing.T) {
	tests := []struct {
		name  string
		value string
		set   bool
		want  time.Duration
	}{
		{name: "unset", set: false, want: DefaultTimeout},
		{name: "empty", value: "", set: true, want: DefaultTimeout},
		{name: "invalid", value: "abc", set: true, want: DefaultTimeout},
		{name: "float", value: "12.5", set: true, want: DefaultTimeout},
		{name: "zero clamped to 1s", value: "0", set: true, want: 1 * time.Second},
		{name: "negative clamped to 1s", value: "-10", set: true, want: 1 * time.Second},
		{name: "valid 45s", value: "45", set: true, want: 45 * time.Second},
		{name: "over max clamped", value: "9999", set: true, want: MaxTimeout},
		{name: "overflow clamped", value: "999999999999999999", set: true, want: MaxTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set {
				t.Setenv("TSUDO_MCP_DEFAULT_TIMEOUT", tc.value)
			} else {
				t.Setenv("TSUDO_MCP_DEFAULT_TIMEOUT", "")
				_ = os.Unsetenv("TSUDO_MCP_DEFAULT_TIMEOUT")
			}
			if got := DefaultTimeoutFromEnv(); got != tc.want {
				t.Fatalf("DefaultTimeoutFromEnv() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExecArgvAndCwdForwarding(t *testing.T) {
	workDir := t.TempDir()
	bin := writeFakeScript(t, `
printf 'argv:'
for a in "$@"; do
  printf '[%s]' "$a"
done
printf '\ncwd:%s\n' "$(pwd -P)"
if cat >/dev/null 2>&1; then
  printf 'stdin:closed\n'
fi
`)

	r := New(bin, 5*time.Second)
	res, err := r.Exec(context.Background(), "tok-secret-123", ExecRequest{
		Command: "/usr/bin/echo",
		Args:    []string{"hello", "world"},
		Cwd:     workDir,
	})
	if err != nil {
		t.Fatalf("Exec returned unexpected error: %v", err)
	}
	if res.ExitCode != 0 || res.TimedOut || res.Truncated {
		t.Fatalf("unexpected result flags: %+v", res)
	}

	// Token in stdout is redacted!
	wantArgv := "argv:[run][--token][[REDACTED]][--][/usr/bin/echo][hello][world]"
	if !strings.Contains(res.Stdout, wantArgv) {
		t.Fatalf("stdout missing expected argv %q, got:\n%s", wantArgv, res.Stdout)
	}
	resolvedWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		resolvedWorkDir = workDir
	}
	if !strings.Contains(res.Stdout, "cwd:"+resolvedWorkDir) {
		t.Fatalf("stdout missing expected cwd %q, got:\n%s", resolvedWorkDir, res.Stdout)
	}
	if !strings.Contains(res.Stdout, "stdin:closed") {
		t.Fatalf("expected stdin to be closed/EOF, got:\n%s", res.Stdout)
	}
}

func TestExecNonZeroExitCode(t *testing.T) {
	bin := writeFakeScript(t, `
echo "out-line"
echo "err-line" >&2
exit 42
`)
	r := New(bin, 5*time.Second)
	res, err := r.Exec(context.Background(), "tok", ExecRequest{Command: "false"})
	if err != nil {
		t.Fatalf("expected nil error on normal non-zero exit, got %v", err)
	}
	if res.ExitCode != 42 {
		t.Fatalf("ExitCode = %d, want 42", res.ExitCode)
	}
	if strings.TrimSpace(res.Stdout) != "out-line" {
		t.Fatalf("Stdout = %q, want %q", res.Stdout, "out-line\n")
	}
	if strings.TrimSpace(res.Stderr) != "err-line" {
		t.Fatalf("Stderr = %q, want %q", res.Stderr, "err-line\n")
	}
}

func TestExecTimeoutKillsProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	bin := writeFakeScript(t, fmt.Sprintf(`
sleep 30 &
child=$!
echo "$child" > %q
wait
`, pidFile))

	r := New(bin, 5*time.Second)
	start := time.Now()
	res, err := r.Exec(context.Background(), "tok", ExecRequest{
		Command: "sleep",
		Args:    []string{"30"},
		Timeout: 120 * time.Millisecond,
	})
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected nil error on timeout, got %v", err)
	}
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got %+v", res)
	}
	if res.ExitCode != -1 {
		t.Fatalf("ExitCode = %d, want -1", res.ExitCode)
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Exec took too long (%v); background child may have held pipes open", elapsed)
	}

	rawPID, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("read child pid file: %v", readErr)
	}
	pid, convErr := strconv.Atoi(strings.TrimSpace(string(rawPID)))
	if convErr != nil || pid <= 0 {
		t.Fatalf("invalid child pid %q: %v", string(rawPID), convErr)
	}

	// Process group kill sends SIGKILL to the grandchild; poll briefly for init to reap it.
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		killErr := syscall.Kill(pid, 0)
		if errors.Is(killErr, syscall.ESRCH) {
			break
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("expected background child pid %d to be dead, Kill(0) = %v", pid, killErr)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestExecOutputTruncation(t *testing.T) {
	bin := writeFakeScript(t, `
head -c 300000 /dev/zero | tr '\0' 'A'
head -c 300000 /dev/zero | tr '\0' 'B' >&2
`)
	r := New(bin, 10*time.Second)
	res, err := r.Exec(context.Background(), "tok", ExecRequest{Command: "spam"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Truncated {
		t.Fatal("expected Truncated=true")
	}
	if len(res.Stdout) != MaxOutputBytes {
		t.Fatalf("len(Stdout) = %d, want %d", len(res.Stdout), MaxOutputBytes)
	}
	if len(res.Stderr) != MaxOutputBytes {
		t.Fatalf("len(Stderr) = %d, want %d", len(res.Stderr), MaxOutputBytes)
	}
	if !bytes.Equal([]byte(res.Stdout), bytes.Repeat([]byte("A"), MaxOutputBytes)) {
		t.Fatal("unexpected stdout content")
	}
}

func TestExecTokenRedaction(t *testing.T) {
	const secretTok = "super-secret-tsudo-token-xyz"

	t.Run("redacts from stdout and stderr", func(t *testing.T) {
		bin := writeFakeScript(t, `
echo "stdout leaked: $3"
echo "stderr leaked: $3" >&2
exit 1
`)
		r := New(bin, 5*time.Second)
		res, err := r.Exec(context.Background(), secretTok, ExecRequest{Command: "id"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(res.Stdout, secretTok) {
			t.Fatalf("Stdout leaked raw token: %q", res.Stdout)
		}
		if strings.Contains(res.Stderr, secretTok) {
			t.Fatalf("Stderr leaked raw token: %q", res.Stderr)
		}
		if !strings.Contains(res.Stdout, "[REDACTED]") || !strings.Contains(res.Stderr, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] marker in outputs: stdout=%q stderr=%q", res.Stdout, res.Stderr)
		}
	})

	t.Run("redacts from launch error", func(t *testing.T) {
		missingBin := filepath.Join(t.TempDir(), "dir-"+secretTok, "tsudo")
		r := New(missingBin, 5*time.Second)
		_, err := r.Exec(context.Background(), secretTok, ExecRequest{Command: "id"})
		if err == nil {
			t.Fatal("expected error for missing binary")
		}
		if strings.Contains(err.Error(), secretTok) {
			t.Fatalf("error leaked raw token: %q", err.Error())
		}
	})
}

func TestExecTokenInvalidOrExpiredClassification(t *testing.T) {
	const secretTok = "tok-classify-999"
	cases := []struct {
		name   string
		stderr string
		stdout string
	}{
		{name: "no session", stderr: "Error: No tsudo session exists for token " + secretTok},
		{name: "token expired", stderr: "Temporary token has expired"},
		{name: "invalid token", stderr: "Invalid tsudo temporary token"},
		{name: "session expired on stdout", stdout: "Session has expired"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := writeFakeScript(t, fmt.Sprintf(`
if [ -n %q ]; then printf '%%s\n' %q; fi
if [ -n %q ]; then printf '%%s\n' %q >&2; fi
exit 1
`, tc.stdout, tc.stdout, tc.stderr, tc.stderr))

			r := New(bin, 5*time.Second)
			res, err := r.Exec(context.Background(), secretTok, ExecRequest{Command: "id"})
			if !errors.Is(err, ErrTokenInvalidOrExpired) {
				t.Fatalf("expected ErrTokenInvalidOrExpired, got %v", err)
			}
			if res.ExitCode != 1 {
				t.Fatalf("ExitCode = %d, want 1", res.ExitCode)
			}
			if strings.Contains(err.Error(), secretTok) {
				t.Fatalf("error leaked token: %v", err)
			}
		})
	}
}

func TestStatus(t *testing.T) {
	t.Run("exit 0 active session", func(t *testing.T) {
		bin := writeFakeScript(t, `
if [ "$1" != "status" ]; then exit 99; fi
echo "active: 120s remaining"
`)
		r := New(bin, 5*time.Second)
		out, err := r.Status(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "active: 120s remaining" {
			t.Fatalf("got %q, want %q", out, "active: 120s remaining")
		}
	})

	t.Run("exit 1 no session", func(t *testing.T) {
		bin := writeFakeScript(t, `
echo "no tsudo session exists" >&2
exit 1
`)
		r := New(bin, 5*time.Second)
		out, err := r.Status(context.Background())
		if err != nil {
			t.Fatalf("expected nil error on exit 1, got %v", err)
		}
		if out != "no tsudo session exists" {
			t.Fatalf("got %q, want %q", out, "no tsudo session exists")
		}
	})

	t.Run("timeout returns error", func(t *testing.T) {
		bin := writeFakeScript(t, `sleep 10`)
		r := New(bin, 5*time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		defer cancel()
		_, err := r.Status(ctx)
		if err == nil {
			t.Fatal("expected error on Status timeout")
		}
	})
}

func TestLogs(t *testing.T) {
	t.Run("default and clamped counts", func(t *testing.T) {
		bin := writeFakeScript(t, `printf '%s:%s\n' "$1" "$2"`)
		r := New(bin, 5*time.Second)

		out, err := r.Logs(context.Background(), 0, false)
		if err != nil || out != "logs:20" {
			t.Fatalf("default count got (%q, %v), want (%q, nil)", out, err, "logs:20")
		}

		out, err = r.Logs(context.Background(), 50, false)
		if err != nil || out != "logs:50" {
			t.Fatalf("custom count got (%q, %v), want (%q, nil)", out, err, "logs:50")
		}

		out, err = r.Logs(context.Background(), 1000, false)
		if err != nil || out != "logs:500" {
			t.Fatalf("clamped count got (%q, %v), want (%q, nil)", out, err, "logs:500")
		}
	})

	t.Run("check exit 0 and exit 2 valid", func(t *testing.T) {
		binClean := writeFakeScript(t, `
if [ "$1" != "check" ]; then exit 99; fi
echo "clean"
exit 0
`)
		out, err := New(binClean, 5*time.Second).Logs(context.Background(), 0, true)
		if err != nil || out != "clean" {
			t.Fatalf("check clean got (%q, %v), want (%q, nil)", out, err, "clean")
		}

		binSuspicious := writeFakeScript(t, `
if [ "$1" != "check" ]; then exit 99; fi
echo "suspicious finding"
exit 2
`)
		out, err = New(binSuspicious, 5*time.Second).Logs(context.Background(), 0, true)
		if err != nil || out != "suspicious finding" {
			t.Fatalf("check exit 2 got (%q, %v), want (%q, nil)", out, err, "suspicious finding")
		}

		binFail := writeFakeScript(t, `
echo "check failed" >&2
exit 1
`)
		_, err = New(binFail, 5*time.Second).Logs(context.Background(), 0, true)
		if err == nil {
			t.Fatal("expected error for check exit 1")
		}
	})
}
