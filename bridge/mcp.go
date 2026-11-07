package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type MCPTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema,omitempty"`
	Annotations struct {
		ReadOnlyHint bool `json:"readOnlyHint"`
	} `json:"annotations,omitempty"`
}

type MCPEnvelope struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Method  string `json:"method,omitempty"`
	Params  any    `json:"params,omitempty"`
	Result  struct {
		ProtocolVersion string `json:"protocolVersion,omitempty"`
		Tools           []MCPTool `json:"tools,omitempty"`
		NextCursor      string `json:"nextCursor,omitempty"`
		Content         []any `json:"content,omitempty"`
		IsError         bool `json:"isError,omitempty"`
	} `json:"result,omitempty"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type MCPClient struct {
	endpoint string
	token    string
	session  string
	protocol string
	http     *http.Client
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// MCP endpoints are executed by the enrolled bridge, so remote endpoints must
// use TLS. Plain HTTP is permitted only for a service on this bridge machine.
func validateMCPEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("MCP server URL must be a valid endpoint without embedded credentials, query or fragment")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("MCP server URL must use HTTPS (HTTP is allowed only for localhost)")
	}
	if u.Scheme == "http" && !loopbackHost(u.Hostname()) {
		return nil, errors.New("MCP server must use HTTPS; plain HTTP is allowed only for localhost on the bridge machine")
	}
	if u.Hostname() == "" {
		return nil, errors.New("MCP server hostname is required")
	}
	if ip := net.ParseIP(strings.Trim(u.Hostname(), "[]")); ip != nil && !loopbackHost(u.Hostname()) && !publicMCPIP(ip) {
		return nil, errors.New("MCP server address resolves to a private or reserved network")
	}
	return u, nil
}

func publicMCPIP(ip net.IP) bool {
	return ip != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() &&
		!ip.IsMulticast()
}

func mcpHTTPClient(u *url.URL) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	allowLoopback := loopbackHost(u.Hostname())
	transport := &http.Transport{
		Proxy:                 nil, // Never inherit proxy routing for a user-supplied MCP endpoint.
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 8 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, errors.New("MCP hostname did not resolve")
			}
			for _, candidate := range ips {
				if allowLoopback {
					if !candidate.IP.IsLoopback() {
						return nil, errors.New("localhost MCP endpoint resolved outside loopback")
					}
				} else if !publicMCPIP(candidate.IP) {
					return nil, errors.New("MCP hostname resolved to a private or reserved network")
				}
			}
			var lastErr error
			for _, candidate := range ips {
				conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
				if dialErr == nil {
					return conn, nil
				}
				lastErr = dialErr
			}
			return nil, lastErr
		},
	}
	return &http.Client{
		Timeout: 12 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func newMCPClient(cfg map[string]string) (*MCPClient, error) {
	u, err := validateMCPEndpoint(cfg["serverUrl"])
	if err != nil {
		return nil, err
	}
	return &MCPClient{
		endpoint: u.String(),
		token:    cfg["bearerToken"],
		http:     mcpHTTPClient(u),
	}, nil
}

func (c *MCPClient) post(ctx context.Context, payload any) (MCPEnvelope, error) {
	var out MCPEnvelope
	raw, err := json.Marshal(payload)
	if err != nil {
		return out, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return out, fmt.Errorf("MCP server returned HTTP %d", resp.StatusCode)
	}
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		c.session = sid
	}
	// Keep bridge results comfortably below the Worker result endpoint's 1 MiB
	// request limit, including JSON framing and encryption overhead.
	const maxMCPResponseBytes = 512 << 10
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMCPResponseBytes+1))
	if err != nil {
		return out, err
	}
	if len(body) > maxMCPResponseBytes {
		return out, errors.New("MCP server response exceeds the 512 KB safety limit")
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "data:") {
				candidate := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
				if json.Unmarshal([]byte(candidate), &out) == nil && out.ID != nil {
					return out, nil
				}
			}
		}
		return out, errors.New("MCP event stream contained no JSON-RPC response")
	}
	if len(body) == 0 {
		return out, errors.New("MCP server returned an empty JSON-RPC response")
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, errors.New("MCP server returned an invalid JSON-RPC response")
	}
	if out.Error != nil {
		return out, fmt.Errorf("MCP server returned JSON-RPC error %d", out.Error.Code)
	}
	return out, nil
}

func (c *MCPClient) initialize(ctx context.Context) error {
	response, err := c.post(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "SentinelX Local Bridge", "version": "0.2.0"},
		},
	})
	if err != nil {
		return err
	}
	if response.Result.ProtocolVersion != "" {
		c.protocol = response.Result.ProtocolVersion
	} else {
		c.protocol = "2025-06-18"
	}
	// Streamable HTTP notifications may return 202 or 204 with no body.
	req, err := http.NewRequestWithContext(ctx, "POST", c.endpoint, strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", c.protocol)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("MCP initialization notification returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (c *MCPClient) listTools(ctx context.Context) ([]MCPTool, error) {
	const maxPages = 100
	const maxTools = 1000
	cursor := ""
	seenCursors := make(map[string]struct{})
	tools := make([]MCPTool, 0)
	for page := 0; page < maxPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		response, err := c.post(ctx, map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": params})
		if err != nil {
			return nil, err
		}
		tools = append(tools, response.Result.Tools...)
		if len(tools) > maxTools {
			return nil, errors.New("MCP server exposed more than the 1000-tool safety limit")
		}
		next := response.Result.NextCursor
		if next == "" {
			return tools, nil
		}
		if _, exists := seenCursors[next]; exists {
			return nil, errors.New("MCP server returned a repeated pagination cursor")
		}
		seenCursors[next] = struct{}{}
		cursor = next
	}
	return nil, errors.New("MCP tools/list exceeded the 100-page safety limit")
}

func executeMCP(task Task) Result {
	c, err := newMCPClient(task.Config)
	if err != nil {
		return Result{OK: false, Message: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err = c.initialize(ctx); err != nil {
		return Result{OK: false, Message: "MCP initialize failed: " + err.Error()}
	}
	tools, err := c.listTools(ctx)
	if err != nil {
		return Result{OK: false, Message: "MCP tools/list failed: " + err.Error()}
	}
	if task.Operation == "test" || task.Input["action"] == "list" {
		safe := make([]map[string]any, 0, len(tools))
		for _, tool := range tools {
			safe = append(safe, map[string]any{
				"name": tool.Name, "description": tool.Description,
				"inputSchema": tool.InputSchema, "readOnly": tool.Annotations.ReadOnlyHint,
			})
		}
		return Result{OK: true, Message: fmt.Sprintf("MCP server discovered %d tools.", len(tools)), Data: map[string]any{
			"tools": safe, "total": len(tools), "readOnlyTools": countReadOnly(tools),
		}}
	}
	if task.Operation != "query" || task.Input["action"] != "call" {
		return Result{OK: false, Message: "Unsupported MCP operation"}
	}
	name, _ := task.Input["toolName"].(string)
	if name == "" || len(name) > 128 {
		return Result{OK: false, Message: "A valid MCP tool name is required"}
	}
	var selected *MCPTool
	for i := range tools {
		if tools[i].Name == name {
			selected = &tools[i]
			break
		}
	}
	if selected == nil {
		return Result{OK: false, Message: "MCP tool was not found; refresh the discovered tool list"}
	}
	if !selected.Annotations.ReadOnlyHint {
		return Result{OK: false, Message: "Blocked: SentinelX only executes MCP tools explicitly annotated readOnlyHint=true"}
	}
	args, ok := task.Input["arguments"].(map[string]any)
	if !ok {
		args = map[string]any{}
	}
	response, err := c.post(ctx, map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call",
		"params": map[string]any{"name": name, "arguments": args},
	})
	if err != nil {
		return Result{OK: false, Message: "MCP tool call failed: " + err.Error()}
	}
	if response.Result.IsError {
		return Result{OK: false, Message: "MCP server reported a tool execution error", Data: response.Result.Content}
	}
	return Result{OK: true, Message: "Read-only MCP tool executed.", Data: map[string]any{"tool": name, "content": response.Result.Content}}
}

func countReadOnly(tools []MCPTool) int {
	n := 0
	for _, tool := range tools {
		if tool.Annotations.ReadOnlyHint {
			n++
		}
	}
	return n
}
