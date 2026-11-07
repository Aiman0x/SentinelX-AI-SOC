package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateMCPEndpoint(t *testing.T) {
	tests := []struct {
		name string
		url  string
		ok   bool
	}{
		{name: "remote HTTPS", url: "https://mcp.example.com/mcp", ok: true},
		{name: "localhost HTTP", url: "http://localhost:8080/mcp", ok: true},
		{name: "IPv4 loopback HTTP", url: "http://127.0.0.1:3333/mcp", ok: true},
		{name: "IPv6 loopback HTTP", url: "http://[::1]:3333/mcp", ok: true},
		{name: "remote HTTP", url: "http://mcp.example.com/mcp", ok: false},
		{name: "private IPv4", url: "https://192.168.1.10/mcp", ok: false},
		{name: "link local metadata", url: "http://169.254.169.254/latest/meta-data", ok: false},
		{name: "embedded credentials", url: "https://user:pass@mcp.example.com/mcp", ok: false},
		{name: "query string", url: "https://mcp.example.com/mcp?token=x", ok: false},
		{name: "unsupported scheme", url: "file:///etc/passwd", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateMCPEndpoint(tt.url)
			if (err == nil) != tt.ok {
				t.Fatalf("validateMCPEndpoint(%q) error = %v, want success=%v", tt.url, err, tt.ok)
			}
		})
	}
}

func TestPublicMCPIP(t *testing.T) {
	tests := []struct {
		ip string
		ok bool
	}{
		{ip: "1.1.1.1", ok: true},
		{ip: "2606:4700:4700::1111", ok: true},
		{ip: "10.0.0.1", ok: false},
		{ip: "172.16.0.1", ok: false},
		{ip: "192.168.0.1", ok: false},
		{ip: "127.0.0.1", ok: false},
		{ip: "169.254.169.254", ok: false},
		{ip: "224.0.0.1", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := publicMCPIP(net.ParseIP(tt.ip)); got != tt.ok {
				t.Fatalf("publicMCPIP(%s) = %v, want %v", tt.ip, got, tt.ok)
			}
		})
	}
}


func TestMCPListToolsPaginates(t *testing.T) {
	listCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var request struct {
			ID     any            `json:"id"`
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			listCalls++
			if request.Params["cursor"] == nil {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"first"}],"nextCursor":"page-2"}}`))
			} else if request.Params["cursor"] == "page-2" {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"second"}]}}`))
			} else {
				t.Errorf("unexpected cursor: %v", request.Params["cursor"])
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected MCP method: %s", request.Method)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer server.Close()

	client, err := newMCPClient(map[string]string{"serverUrl": server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.initialize(ctx); err != nil {
		t.Fatal(err)
	}
	tools, err := client.listTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if listCalls != 2 || len(tools) != 2 || tools[0].Name != "first" || tools[1].Name != "second" {
		t.Fatalf("unexpected paginated tools: calls=%d tools=%+v", listCalls, tools)
	}
}

func TestMCPResponseSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"%s"}]}}`, strings.Repeat("x", (512<<10)+1))
	}))
	defer server.Close()
	client, err := newMCPClient(map[string]string{"serverUrl": server.URL})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = client.post(ctx, map[string]any{"jsonrpc":"2.0","id":1,"method":"tools/list","params":map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), "512 KB safety limit") {
		t.Fatalf("expected response size limit error, got %v", err)
	}
}
