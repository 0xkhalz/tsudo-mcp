package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// MaxOutputBytes is the per-stream (stdout/stderr) capture limit.
	MaxOutputBytes = 256 * 1024
	// DefaultTimeout is the fallback execution timeout when none is configured.
	DefaultTimeout = 60 * time.Second
	// MaxTimeout is the upper bound enforced on any execution timeout.
	MaxTimeout = 600 * time.Second
)

// ErrTokenInvalidOrExpired indicates tsudo rejected the session or temporary token.
var ErrTokenInvalidOrExpired = errors.New("tsudo token missing, invalid, or expired")

var tokenErrorMarkers = []string{
	"no tsudo session exists",
	"temporary token has expired",
	"invalid tsudo temporary token",
	"session has expired",
}

// ExecRequest describes a privileged command invocation via tsudo.
type ExecRequest struct {
	Command string
	Args    []string
	Cwd     string
	Timeout time.Duration
}

// ExecResult captures the bounded outcome of an Exec invocation.
type ExecResult struct {
	ExitCode  int
	TimedOut  bool
	Truncated bool
	Stdout    string
	Stderr    string
}

// Runner executes privileged commands and queries tsudo session status/logs.
type Runner interface {
	Exec(ctx context.Context, tok string, req ExecRequest) (ExecResult, error)
	Status(ctx context.Context) (string, error)
	Logs(ctx context.Context, count int, check bool) (string, error)
}

// TsudoRunner implements Runner by invoking the tsudo CLI binary.
type TsudoRunner struct {
	binary         string
	defaultTimeout time.Duration
}

// DefaultTimeoutFromEnv parses TSUDO_MCP_DEFAULT_TIMEOUT (integer seconds),
// defaulting to DefaultTimeout on unset/invalid input and clamping to [1s, MaxTimeout].
func DefaultTimeoutFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv("TSUDO_MCP_DEFAULT_TIMEOUT"))
	if raw == "" {
		return DefaultTimeout
	}
	secs, err := strconv.Atoi(raw)
	if err != nil {
		return DefaultTimeout
	}
	if secs <= 0 {
		return time.Second
	}
	maxSecs := int(MaxTimeout / time.Second)
	if secs >= maxSecs {
		return MaxTimeout
	}
	return time.Duration(secs) * time.Second
}

// New constructs a TsudoRunner with default binary "tsudo" and clamped timeout.
func New(binary string, defaultTimeout time.Duration) *TsudoRunner {
	if binary == "" {
		binary = "tsudo"
	}
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultTimeout
	} else if defaultTimeout > MaxTimeout {
		defaultTimeout = MaxTimeout
	}
	return &TsudoRunner{
		binary:         binary,
		defaultTimeout: defaultTimeout,
	}
}

// Exec runs `tsudo run --token <tok> -- <Command> <Args...>` with process-group
// isolation, bounded output capture, and defensive token redaction.
func (r *TsudoRunner) Exec(ctx context.Context, tok string, req ExecRequest) (ExecResult, error) {
	timeout := r.defaultTimeout
	if req.Timeout > 0 {
		timeout = req.Timeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args := make([]string, 0, 4+len(req.Args)+1)
	args = append(args, "run", "--token", tok, "--", req.Command)
	args = append(args, req.Args...)

	cmd, stdoutBuf, stderrBuf := r.newCommand(execCtx, args...)
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}

	err := cmd.Run()

	res := ExecResult{
		Stdout:    redact(stdoutBuf.String(), tok),
		Stderr:    redact(stderrBuf.String(), tok),
		Truncated: stdoutBuf.Truncated() || stderrBuf.Truncated(),
	}

	if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
		res.ExitCode = -1
		return res, nil
	}
	if err == nil {
		res.ExitCode = 0
		return res, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		res.ExitCode = exitErr.ExitCode()
		if isTokenInvalidOrExpired(res.Stdout + "\n" + res.Stderr) {
			return res, fmt.Errorf("%w: %s", ErrTokenInvalidOrExpired, strings.TrimSpace(res.Stderr))
		}
		return res, nil
	}

	return res, errors.New(redact(err.Error(), tok))
}

// Status runs `tsudo status`, treating exit code 1 (no active/expired session)
// as a valid status output.
func (r *TsudoRunner) Status(ctx context.Context) (string, error) {
	runCtx, cancel := withFallbackTimeout(ctx, 10*time.Second)
	defer cancel()

	cmd, stdoutBuf, stderrBuf := r.newCommand(runCtx, "status")
	err := cmd.Run()
	combined := combineOutput(stdoutBuf.String(), stderrBuf.String())

	if runCtx.Err() != nil {
		return combined, runCtx.Err()
	}
	if err == nil {
		return combined, nil
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return combined, nil
	}
	return combined, err
}

// Logs runs either `tsudo check` (accepting exit codes 0 and 2) or `tsudo logs <count>`.
func (r *TsudoRunner) Logs(ctx context.Context, count int, check bool) (string, error) {
	runCtx, cancel := withFallbackTimeout(ctx, 15*time.Second)
	defer cancel()

	var args []string
	if check {
		args = []string{"check"}
	} else {
		if count <= 0 {
			count = 20
		} else if count > 500 {
			count = 500
		}
		args = []string{"logs", strconv.Itoa(count)}
	}

	cmd, stdoutBuf, stderrBuf := r.newCommand(runCtx, args...)
	err := cmd.Run()
	combined := combineOutput(stdoutBuf.String(), stderrBuf.String())

	if runCtx.Err() != nil {
		return combined, runCtx.Err()
	}
	if err == nil {
		return combined, nil
	}

	if check {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 {
			return combined, nil
		}
	}
	return combined, err
}

func (r *TsudoRunner) newCommand(ctx context.Context, args ...string) (*exec.Cmd, *LimitedBuffer, *LimitedBuffer) {
	cmd := exec.CommandContext(ctx, r.binary, args...)
	cmd.Stdin = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 2 * time.Second

	stdoutBuf := NewLimitedBuffer(MaxOutputBytes)
	stderrBuf := NewLimitedBuffer(MaxOutputBytes)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf
	return cmd, stdoutBuf, stderrBuf
}

func withFallbackTimeout(ctx context.Context, fallback time.Duration) (context.Context, context.CancelFunc) {
	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, fallback)
}

func isTokenInvalidOrExpired(combined string) bool {
	lower := strings.ToLower(combined)
	for _, marker := range tokenErrorMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func redact(s, tok string) string {
	if tok == "" || s == "" {
		return s
	}
	return strings.ReplaceAll(s, tok, "[REDACTED]")
}

func combineOutput(stdout, stderr string) string {
	out := strings.TrimSpace(stdout)
	errOut := strings.TrimSpace(stderr)
	switch {
	case out != "" && errOut != "":
		return out + "\n" + errOut
	case out != "":
		return out
	default:
		return errOut
	}
}
