package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/0xkhalz/tsudo-mcp/internal/token"
)

var validDurationRe = regexp.MustCompile(`^[0-9]+[mhd]$`)

const (
	tokenHeaderPrefix    = "temporary tsudo token:"
	giveTokenLinePrefix  = "give this temporary token"
	expiresAtLinePrefix  = "expires at:"
	promptChunkReadBytes = 256
)

func runGrant(args []string, tsudoBin string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		fmt.Fprint(stderr, "tsudo-mcp: grant accepts at most one duration argument\n")
		return 2
	}
	if len(args) == 1 && !validDurationRe.MatchString(args[0]) {
		fmt.Fprintf(stderr, "tsudo-mcp: invalid duration %q (expected <number>[m|h|d], e.g. 15m, 1h, 1d)\n", args[0])
		return 2
	}

	tokenPath, err := token.DefaultPath()
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}
	store := token.NewFileStore(tokenPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cmd := exec.CommandContext(ctx, tsudoBin, args...)
	cmd.Stdin = stdin
	cmd.Stderr = stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: failed to attach tsudo stdout: %v\n", err)
		return 1
	}

	restoreTTY := disableEchoIfTTY(stdin)
	defer restoreTTY()

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: failed to start tsudo: %v\n", err)
		return 1
	}

	rawOutput, readErr := streamGrantOutput(pipe, stdout)
	waitErr := cmd.Wait()
	restoreTTY()

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && exitErr.ExitCode() > 0 {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(stderr, "tsudo-mcp: tsudo exited with error: %v\n", waitErr)
		return 1
	}
	if readErr != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: failed reading tsudo output: %v\n", readErr)
		return 1
	}

	tok, err := token.ParseToken(rawOutput)
	if err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: %v\n", err)
		return 1
	}
	if err := store.Write(tok); err != nil {
		fmt.Fprintf(stderr, "tsudo-mcp: failed to store token: %s\n", token.Redact(err.Error(), tok))
		return 1
	}

	fmt.Fprintf(stdout, "Token saved to %s (mode 0600).\n", store.Path())
	return 0
}

// streamGrantOutput flushes bytes before the first newline immediately so prompts
// like "sudo password: " render without delay, then filters subsequent lines to
// suppress the temporary token while forwarding expiry details.
func streamGrantOutput(r io.Reader, stdout io.Writer) (string, error) {
	var raw strings.Builder
	buf := make([]byte, promptChunkReadBytes)
	var remainder []byte
	skipNextTokenLine := false
	var capturedToken string

	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if nlIdx := bytes.IndexByte(chunk, '\n'); nlIdx >= 0 {
				head := chunk[:nlIdx+1]
				firstLine := raw.Len() == 0
				raw.Write(head)

				if firstLine {
					suppress, nextSkip, tok := classifyGrantLine(string(head), false)
					skipNextTokenLine = nextSkip
					if tok != "" {
						capturedToken = tok
					}
					if !suppress {
						if _, wErr := stdout.Write(head); wErr != nil {
							return raw.String(), wErr
						}
					}
				} else {
					if _, wErr := stdout.Write(head); wErr != nil {
						return raw.String(), wErr
					}
				}
				remainder = append([]byte(nil), chunk[nlIdx+1:]...)
				break
			}
			raw.Write(chunk)
			if _, wErr := stdout.Write(chunk); wErr != nil {
				return raw.String(), wErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return raw.String(), nil
			}
			return raw.String(), err
		}
	}

	br := bufio.NewReader(io.MultiReader(bytes.NewReader(remainder), r))

	for {
		line, err := br.ReadString('\n')
		if len(line) > 0 {
			raw.WriteString(line)

			suppress, nextSkip, tok := classifyGrantLine(line, skipNextTokenLine)
			skipNextTokenLine = nextSkip
			if tok != "" {
				capturedToken = tok
			}

			if !suppress {
				outLine := token.Redact(line, capturedToken)
				if _, wErr := io.WriteString(stdout, outLine); wErr != nil {
					return raw.String(), wErr
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return raw.String(), nil
			}
			return raw.String(), err
		}
	}
}

func classifyGrantLine(line string, skipNext bool) (suppress bool, nextSkip bool, tok string) {
	if skipNext {
		candidate := strings.TrimSpace(line)
		return true, false, candidate
	}

	trimmed := strings.TrimSpace(line)
	lower := strings.ToLower(trimmed)

	if strings.HasPrefix(lower, tokenHeaderPrefix) {
		after := strings.TrimSpace(trimmed[len(tokenHeaderPrefix):])
		if after == "" {
			return true, true, ""
		}
		return true, false, after
	}

	if strings.HasPrefix(lower, giveTokenLinePrefix) {
		return true, false, ""
	}

	if strings.HasPrefix(lower, expiresAtLinePrefix) {
		return false, false, ""
	}

	return false, false, ""
}
