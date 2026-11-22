package main

import (
	"fmt"
	"io"
	"os"
)

// Version is the semantic version of tsudo-mcp, overridable via -ldflags.
var Version = "0.1.0"

const usageText = `Usage: tsudo-mcp <command> [args]

Commands:
  serve             Start the MCP server over stdio
  grant [duration]  Acquire and store a tsudo token (default: 15m)
  status            Show current tsudo token status
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

func run(args []string, _ io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "tsudo-mcp: missing command\n\n")
		fmt.Fprint(stderr, usageText)
		return 2
	}

	switch args[0] {
	case "--version", "-v", "version":
		fmt.Fprintf(stdout, "tsudo-mcp %s\n", Version)
		return 0
	case "--help", "-h", "help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "serve", "grant", "status", "clear":
		fmt.Fprintf(stderr, "tsudo-mcp: %s is not implemented yet\n", args[0])
		return 1
	default:
		fmt.Fprintf(stderr, "tsudo-mcp: unknown command %q\n\n", args[0])
		fmt.Fprint(stderr, usageText)
		return 2
	}
}
