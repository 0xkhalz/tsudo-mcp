package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/0xkhalz/tsudo-mcp/internal/mcp"
	"github.com/0xkhalz/tsudo-mcp/internal/policy"
	"github.com/0xkhalz/tsudo-mcp/internal/runner"
	"github.com/0xkhalz/tsudo-mcp/internal/token"
)

// Version is the semantic version of tsudo-mcp, overridable via -ldflags.
var Version = "0.1.0"

const usageText = `Usage: tsudo-mcp [command] [args]

Commands:
  serve             Start the MCP server over stdio (default)
  grant [duration]  Acquire and store a tsudo token (default: 10m)
  status            Show current tsudo token and session status
  clear             Revoke and remove the stored tsudo token
  version           Print version information
  help              Show this help message

Flags:
  -h, --help        Show this help message
  -v, --version     Print version information
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWithBinary(args, "tsudo", stdin, stdout, stderr)
}

func runWithBinary(args []string, tsudoBin string, stdin io.Reader, stdout, stderr io.Writer) int {
	if tsudoBin == "" {
		tsudoBin = "tsudo"
	}
	if len(args) == 0 {
		return runServe(tsudoBin, stdin, stdout, stderr)
	}

	switch args[0] {
	case "--version", "-v", "version":
		fmt.Fprintf(stdout, "tsudo-mcp %s\n", Version)
		return 0
	case "--help", "-h", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "serve":
		if len(args) > 1 {
			fmt.Fprint(stderr, "tsudo-mcp: serve does not accept positional arguments\n")
			return 2
		}
		return runServe(tsudoBin, stdin, stdout, stderr)
	case "grant":
		return runGrant(args[1:], tsudoBin, stdin, stdout, stderr)
	case "status":
		if len(args) > 1 {
			fmt.Fprint(stderr, "tsudo-mcp: status does not accept positional arguments\n")
			return 2
		}
		return runStatus(tsudoBin, stdout, stderr)
	case "clear":
		if len(args) > 1 {
			fmt.Fprint(stderr, "tsudo-mcp: clear does not accept positional arguments\n")
			return 2
		}
		return runClear(tsudoBin, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "tsudo-mcp: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}

func runServe(tsudoBin string, stdin io.Reader, stdout, stderr io.Writer) int {
	tokenPath, err := token.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}

	store := token.NewFileStore(tokenPath)
	eval := policy.New(policy.ConfigFromEnv())
	run := runner.New(tsudoBin, runner.DefaultTimeoutFromEnv())
	srv := mcp.NewServer(Version, store, eval, run, stderr)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := srv.Serve(ctx, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}
	return 0
}

func runStatus(tsudoBin string, stdout, stderr io.Writer) int {
	tokenPath, err := token.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}

	store := token.NewFileStore(tokenPath)
	info, statErr := store.Stat()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	run := runner.New(tsudoBin, runner.DefaultTimeoutFromEnv())
	tsudoOut, runnerErr := run.Status(ctx)

	fmt.Fprintf(stdout, "Token file: %s\n", info.Path)
	fmt.Fprintf(stdout, "  exists: %t\n", info.Exists)
	if info.Exists {
		fmt.Fprintf(stdout, "  mode:   %04o\n", info.Mode.Perm())
		fmt.Fprintf(stdout, "  uid:    %d\n", info.UID)
	}
	if info.Err != nil {
		fmt.Fprintf(stdout, "  valid:  %t (%v)\n", info.Valid, info.Err)
	} else {
		fmt.Fprintf(stdout, "  valid:  %t\n", info.Valid)
	}

	fmt.Fprintln(stdout, "tsudo status:")
	if strings.TrimSpace(tsudoOut) != "" {
		fmt.Fprintf(stdout, "  %s\n", strings.TrimSpace(tsudoOut))
	} else {
		fmt.Fprintln(stdout, "  (no output)")
	}

	if statErr != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: stat token file: %v\n", statErr)
	}
	if runnerErr != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: tsudo status: %v\n", runnerErr)
	}

	if statErr == nil && info.Valid && runnerErr == nil && isSessionActive(tsudoOut) {
		return 0
	}
	return 1
}

func isSessionActive(output string) bool {
	lower := strings.ToLower(strings.TrimSpace(output))
	if lower == "" {
		return false
	}
	return !strings.Contains(lower, "no active") &&
		!strings.Contains(lower, "expired") &&
		!strings.Contains(lower, "no tsudo session")
}

func runClear(tsudoBin string, stdout, stderr io.Writer) int {
	tokenPath, err := token.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}

	store := token.NewFileStore(tokenPath)
	clearErr := store.Clear()
	if clearErr != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: clear token file: %v\n", clearErr)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, tsudoBin, "clear")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmdErr := cmd.Run()
	if cmdErr != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: tsudo clear: %v\n", cmdErr)
	}

	if clearErr != nil || cmdErr != nil {
		return 1
	}

	fmt.Fprintf(stdout, "Cleared token file %s and tsudo session.\n", tokenPath)
	return 0
}
