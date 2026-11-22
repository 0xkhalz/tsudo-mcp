package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/0xkhalz/tsudo-mcp/internal/policy"
	"github.com/0xkhalz/tsudo-mcp/internal/runner"
	"github.com/0xkhalz/tsudo-mcp/internal/token"
)

var errLineTooLong = errors.New("json-rpc line exceeds maximum size")

// Server implements a stdio newline-delimited JSON-RPC 2.0 MCP server.
type Server struct {
	version string
	store   token.Store
	eval    policy.Evaluator
	run     runner.Runner
	stderr  io.Writer
}

// NewServer constructs an MCP Server wired to the given store, policy evaluator, and runner.
func NewServer(version string, store token.Store, eval policy.Evaluator, run runner.Runner, stderr io.Writer) *Server {
	if stderr == nil {
		stderr = io.Discard
	}
	return &Server{
		version: version,
		store:   store,
		eval:    eval,
		run:     run,
		stderr:  stderr,
	}
}

type readResult struct {
	line []byte
	err  error
}

// Serve processes newline-delimited JSON-RPC 2.0 requests from r and writes
// single-line JSON-RPC 2.0 responses to w until io.EOF or ctx.Done().
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	lines := make(chan readResult, 1)

	go func() {
		for {
			line, err := readLineBounded(br, MaxLineBytes)
			select {
			case lines <- readResult{line: line, err: err}:
			case <-ctx.Done():
				return
			}
			if err != nil && !errors.Is(err, errLineTooLong) {
				return
			}
		}
	}()

	for {
		if ctx.Err() != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case res := <-lines:
			if errors.Is(res.err, errLineTooLong) {
				s.logf("request exceeded %d bytes", MaxLineBytes)
				if err := writeResponse(w, newErrorResponse(nil, ErrCodeInvalidRequest, "request exceeds maximum line size")); err != nil {
					return err
				}
				continue
			}

			if len(res.line) > 0 {
				trimmed := bytes.TrimSpace(res.line)
				if len(trimmed) > 0 {
					if resp, ok := s.processLine(ctx, trimmed); ok {
						if err := writeResponse(w, resp); err != nil {
							return err
						}
					}
				}
			}

			if res.err != nil {
				if errors.Is(res.err, io.EOF) {
					return nil
				}
				return res.err
			}
		}
	}
}

// readLineBounded reads up to maxBytes of a single newline-delimited line from br.
// If a line exceeds maxBytes, the remainder of that line is drained and errLineTooLong is returned.
func readLineBounded(br *bufio.Reader, maxBytes int) ([]byte, error) {
	var buf []byte
	for {
		frag, err := br.ReadSlice('\n')
		if len(buf)+len(frag) > maxBytes {
			// Drain until the next newline or EOF so subsequent frames stay aligned.
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, err
			}
			return nil, errLineTooLong
		}
		buf = append(buf, frag...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return buf, err
		}
	}
}

func (s *Server) processLine(ctx context.Context, line []byte) (Response, bool) {
	if !json.Valid(line) {
		s.logf("parse error: invalid json")
		return newErrorResponse(nil, ErrCodeParse, "parse error"), true
	}

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		s.logf("invalid request: %v", err)
		return newErrorResponse(nil, ErrCodeInvalidRequest, "invalid request"), true
	}

	idValid := isValidID(req.ID)
	var respID json.RawMessage
	if idValid && hasID(req.ID) {
		respID = bytes.TrimSpace(req.ID)
	}

	if !idValid || req.JSONRPC != JSONRPCVersion || req.Method == "" {
		return newErrorResponse(respID, ErrCodeInvalidRequest, "invalid request"), true
	}

	if req.Method == "notifications/initialized" || (!hasID(req.ID) && strings.HasPrefix(req.Method, "notifications/")) {
		return Response{}, false
	}

	switch req.Method {
	case "initialize":
		return newResultResponse(respID, InitializeResult{
			ProtocolVersion: MCPProtocolVersion,
			Capabilities: Capabilities{
				Tools: &ToolsCapability{},
			},
			ServerInfo: ServerInfo{
				Name:    "tsudo-mcp",
				Version: s.version,
			},
		}), true

	case "ping":
		return newResultResponse(respID, map[string]any{}), true

	case "tools/list":
		return newResultResponse(respID, ToolsListResult{
			Tools: toolDefinitions(),
		}), true

	case "tools/call":
		res, rpcErr := s.handleToolCall(ctx, req.Params)
		if rpcErr != nil {
			return newErrorResponse(respID, rpcErr.Code, rpcErr.Message), true
		}
		return newResultResponse(respID, res), true

	default:
		return newErrorResponse(respID, ErrCodeMethodNotFound, fmt.Sprintf("method not found: %q", req.Method)), true
	}
}

func isValidID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return true
	}
	switch trimmed[0] {
	case '"', '-':
		return true
	default:
		return trimmed[0] >= '0' && trimmed[0] <= '9'
	}
}

func hasID(id json.RawMessage) bool {
	trimmed := bytes.TrimSpace(id)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func writeResponse(w io.Writer, resp Response) error {
	payload, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	_, err = w.Write(payload)
	return err
}

func (s *Server) logf(format string, args ...any) {
	if s.stderr == nil {
		return
	}
	_, _ = fmt.Fprintf(s.stderr, "tsudo-mcp: "+format+"\n", args...)
}
