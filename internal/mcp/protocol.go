package mcp

import "encoding/json"

const (
	// JSONRPCVersion is the supported JSON-RPC protocol version.
	JSONRPCVersion = "2.0"
	// MCPProtocolVersion is the supported Model Context Protocol revision.
	MCPProtocolVersion = "2024-11-05"
	// MaxLineBytes caps a single newline-delimited JSON-RPC frame at 4 MiB.
	MaxLineBytes = 4 * 1024 * 1024

	// ErrCodeParse indicates malformed JSON was received.
	ErrCodeParse = -32700
	// ErrCodeInvalidRequest indicates the JSON is not a valid JSON-RPC 2.0 request.
	ErrCodeInvalidRequest = -32600
	// ErrCodeMethodNotFound indicates the requested method does not exist.
	ErrCodeMethodNotFound = -32601
	// ErrCodeInvalidParams indicates invalid method or tool parameters.
	ErrCodeInvalidParams = -32602
	// ErrCodeInternal indicates an internal server error.
	ErrCodeInternal = -32603
)

// Request represents an incoming JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents an outgoing JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// InitializeResult is returned by the MCP initialize handshake.
type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

// Capabilities advertises supported MCP server features.
type Capabilities struct {
	Tools *ToolsCapability `json:"tools,omitempty"`
}

// ToolsCapability indicates the server exposes MCP tools.
type ToolsCapability struct{}

// ServerInfo identifies the MCP server implementation.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Tool describes an MCP tool exposed by tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolsListResult is the response payload for tools/list.
type ToolsListResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is the request payload for tools/call.
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolContent represents a single content block returned by a tool.
type ToolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is the response payload for tools/call.
type CallToolResult struct {
	Content []ToolContent `json:"content"`
	IsError bool          `json:"isError"`
}

func newResultResponse(id json.RawMessage, result any) Response {
	raw, err := json.Marshal(result)
	if err != nil {
		return newErrorResponse(id, ErrCodeInternal, "failed to encode response")
	}
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      normalizeResponseID(id),
		Result:  raw,
	}
}

func newErrorResponse(id json.RawMessage, code int, message string) Response {
	return Response{
		JSONRPC: JSONRPCVersion,
		ID:      normalizeResponseID(id),
		Error: &RPCError{
			Code:    code,
			Message: message,
		},
	}
}

func normalizeResponseID(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}
