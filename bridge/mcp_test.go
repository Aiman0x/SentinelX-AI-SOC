package main

import (
	"net"
	"testing"
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
