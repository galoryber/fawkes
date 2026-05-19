package http

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDetectAuthScheme(t *testing.T) {
	tests := []struct {
		header string
		want   string
	}{
		{"NTLM", "NTLM"},
		{"Negotiate", "Negotiate"},
		{"Basic realm=\"proxy\"", "basic"},
		{"Negotiate, NTLM", "NTLM"},
		{"", ""},
		{"Digest realm=\"test\"", ""},
	}
	for _, tt := range tests {
		got := detectAuthScheme(tt.header)
		if got != tt.want {
			t.Errorf("detectAuthScheme(%q) = %q, want %q", tt.header, got, tt.want)
		}
	}
}

func TestExtractAuthToken(t *testing.T) {
	tests := []struct {
		header string
		scheme string
		want   string
	}{
		{"NTLM TlRMTVNTUAAC", "NTLM", "TlRMTVNTUAAC"},
		{"Negotiate TlRMTVNTUAAC", "Negotiate", "TlRMTVNTUAAC"},
		{"NTLM TlRMTVNTUAAC, Basic realm=\"test\"", "NTLM", "TlRMTVNTUAAC"},
		{"Basic realm=\"test\"", "NTLM", ""},
		{"", "NTLM", ""},
	}
	for _, tt := range tests {
		got := extractAuthToken(tt.header, tt.scheme)
		if got != tt.want {
			t.Errorf("extractAuthToken(%q, %q) = %q, want %q", tt.header, tt.scheme, got, tt.want)
		}
	}
}

func TestWriteConnect(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		writeConnect(client, "target.com:443", "Basic dGVzdDp0ZXN0")
	}()

	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	got := string(buf[:n])
	if !strings.Contains(got, "CONNECT target.com:443 HTTP/1.1") {
		t.Errorf("Missing CONNECT line in: %s", got)
	}
	if !strings.Contains(got, "Proxy-Authorization: Basic dGVzdDp0ZXN0") {
		t.Errorf("Missing Proxy-Authorization header in: %s", got)
	}
	if !strings.Contains(got, "Host: target.com:443") {
		t.Errorf("Missing Host header in: %s", got)
	}
}

func TestWriteConnect_NoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		writeConnect(client, "target.com:443", "")
	}()

	buf := make([]byte, 1024)
	n, _ := server.Read(buf)
	got := string(buf[:n])
	if strings.Contains(got, "Proxy-Authorization") {
		t.Errorf("Should not have Proxy-Authorization header: %s", got)
	}
}

func TestProxyBasicAuth_Success(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		br := bufio.NewReader(server)
		req, _ := http.ReadRequest(br)
		if req != nil {
			auth := req.Header.Get("Proxy-Authorization")
			if strings.HasPrefix(auth, "Basic ") {
				decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
				if string(decoded) == "user:pass" {
					io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\n")
					return
				}
			}
			io.WriteString(server, "HTTP/1.1 403 Forbidden\r\n\r\n")
		}
	}()

	br := bufio.NewReader(client)
	err := proxyBasicAuth(client, br, "target.com:443", "user", "pass")
	if err != nil {
		t.Fatalf("proxyBasicAuth failed: %v", err)
	}
}

func TestProxyBasicAuth_Failure(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		br := bufio.NewReader(server)
		http.ReadRequest(br)
		io.WriteString(server, "HTTP/1.1 403 Forbidden\r\n\r\n")
	}()

	br := bufio.NewReader(client)
	err := proxyBasicAuth(client, br, "target.com:443", "user", "wrong")
	if err == nil {
		t.Error("expected error for failed auth")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Errorf("error should mention 403: %v", err)
	}
}

func TestProxyConnectNTLM_NoAuthRequired(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		br := bufio.NewReader(server)
		http.ReadRequest(br)
		io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\n")
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	err := proxyConnectNTLM(client, "target.com:443", "CORP", "user", "pass")
	if err != nil {
		t.Fatalf("proxyConnectNTLM failed: %v", err)
	}
}

func TestProxyConnectNTLM_BasicFallback(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		br := bufio.NewReader(server)
		// First request — no auth
		http.ReadRequest(br)
		io.WriteString(server, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n")
		// Second request — should have Basic auth
		req, _ := http.ReadRequest(br)
		if req != nil {
			auth := req.Header.Get("Proxy-Authorization")
			if strings.HasPrefix(auth, "Basic ") {
				io.WriteString(server, "HTTP/1.1 200 Connection established\r\n\r\n")
				return
			}
		}
		io.WriteString(server, "HTTP/1.1 403 Forbidden\r\n\r\n")
	}()

	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	err := proxyConnectNTLM(client, "target.com:443", "CORP", "user", "pass")
	if err != nil {
		t.Fatalf("proxyConnectNTLM with Basic fallback failed: %v", err)
	}
}

func TestNewHTTPProfile_NTLMProxy(t *testing.T) {
	p := NewHTTPProfile(
		"https://c2.example.com",
		"TestAgent/1.0",
		"",
		10, 5, 10, false,
		"/get", "/post", "",
		"http://proxy.corp.com:8080",
		"corpuser",
		"corppass",
		"CORP",
		"none", "", "", "",
		nil, nil, 0)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil with NTLM proxy config")
	}
	if p.client == nil {
		t.Fatal("HTTP client not initialized with NTLM proxy config")
	}
	transport := p.client.Transport.(*http.Transport)
	if transport.Proxy != nil {
		t.Error("Proxy should be nil when NTLM proxy is configured (handled by DialTLSContext)")
	}
	if transport.DialTLSContext == nil {
		t.Error("DialTLSContext should be set for NTLM proxy")
	}
}

func TestNewHTTPProfile_NTLMProxyNoDomain(t *testing.T) {
	p := NewHTTPProfile(
		"https://c2.example.com",
		"TestAgent/1.0",
		"",
		10, 5, 10, false,
		"/get", "/post", "",
		"http://proxy.corp.com:8080",
		"corpuser",
		"corppass",
		"",
		"none", "", "", "",
		nil, nil, 0)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
	transport := p.client.Transport.(*http.Transport)
	if transport.Proxy == nil {
		t.Error("Proxy should be set when proxyDomain is empty (Basic auth mode)")
	}
}
