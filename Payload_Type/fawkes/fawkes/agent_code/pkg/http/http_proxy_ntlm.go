package http

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

// ntlmProxyTLSDialer returns a DialTLSContext function that establishes HTTPS
// connections through an NTLM-authenticating proxy. It handles:
//  1. TCP connection to proxy
//  2. HTTP CONNECT tunnel with NTLM authentication
//  3. TLS handshake (standard or uTLS fingerprint) over the tunnel
func ntlmProxyTLSDialer(proxyAddr, domain, username, password string, tlsConfig *tls.Config, fingerprint string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 30 * time.Second}
		rawConn, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, fmt.Errorf("proxy TCP connect: %w", err)
		}

		if err := proxyConnectNTLM(rawConn, addr, domain, username, password); err != nil {
			_ = rawConn.Close()
			return nil, err
		}

		tlsConn, err := upgradeTunnelToTLS(ctx, rawConn, addr, tlsConfig, fingerprint)
		if err != nil {
			_ = rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
}

// upgradeTunnelToTLS performs a TLS handshake over an existing tunnel connection,
// using either uTLS fingerprinting or standard Go TLS.
func upgradeTunnelToTLS(ctx context.Context, tunnel net.Conn, addr string, tlsConfig *tls.Config, fingerprint string) (net.Conn, error) {
	if isRotateFingerprint(fingerprint) {
		var b [4]byte
		_, _ = rand.Read(b[:])
		idx := int(binary.LittleEndian.Uint32(b[:])) % len(rotationPool)
		return upgradeToUTLS(ctx, tunnel, addr, rotationPool[idx], tlsConfig)
	}
	if helloID, ok := tlsFingerprintID(fingerprint); ok {
		return upgradeToUTLS(ctx, tunnel, addr, *helloID, tlsConfig)
	}
	return upgradeToStdTLS(ctx, tunnel, addr, tlsConfig)
}

// proxyConnectNTLM performs an HTTP CONNECT through the proxy with NTLM auth.
// Uses a shared bufio.Reader across the handshake to avoid losing buffered data.
func proxyConnectNTLM(conn net.Conn, targetAddr, domain, username, password string) error {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	br := bufio.NewReader(conn)

	// Step 1: Try CONNECT without auth — proxy may not require it
	if err := writeConnect(conn, targetAddr, ""); err != nil {
		return err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("proxy response: %w", err)
	}
	drainBody(resp)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return fmt.Errorf("proxy returned %d", resp.StatusCode)
	}

	authScheme := detectAuthScheme(resp.Header.Get("Proxy-Authenticate"))
	if authScheme == "basic" {
		return proxyBasicAuth(conn, br, targetAddr, username, password)
	}
	if authScheme != "ntlm" && authScheme != "negotiate" {
		return fmt.Errorf("proxy requires unsupported auth: %s", resp.Header.Get("Proxy-Authenticate"))
	}

	// Step 2: Send NTLM Type 1 (Negotiate)
	negotiateMsg, err := ntlmssp.NewNegotiateMessage(domain, "")
	if err != nil {
		return fmt.Errorf("ntlm negotiate: %w", err)
	}
	authHeader := authScheme + " " + base64.StdEncoding.EncodeToString(negotiateMsg)

	if err := writeConnect(conn, targetAddr, authHeader); err != nil {
		return err
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("proxy negotiate response: %w", err)
	}
	challengeHeader := resp.Header.Get("Proxy-Authenticate")
	drainBody(resp)
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		return fmt.Errorf("proxy returned %d during NTLM negotiate", resp.StatusCode)
	}

	// Step 3: Extract Type 2 (Challenge) from response
	challengeB64 := extractAuthToken(challengeHeader, authScheme)
	if challengeB64 == "" {
		return fmt.Errorf("no NTLM challenge in proxy response")
	}
	challengeBytes, err := base64.StdEncoding.DecodeString(challengeB64)
	if err != nil {
		return fmt.Errorf("decode ntlm challenge: %w", err)
	}

	// Step 4: Send Type 3 (Authenticate)
	authMsg, err := ntlmssp.NewAuthenticateMessage(challengeBytes, username, password, nil)
	if err != nil {
		return fmt.Errorf("ntlm authenticate: %w", err)
	}
	authHeader = authScheme + " " + base64.StdEncoding.EncodeToString(authMsg)

	if err := writeConnect(conn, targetAddr, authHeader); err != nil {
		return err
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("proxy auth response: %w", err)
	}
	drainBody(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy NTLM auth failed: %d", resp.StatusCode)
	}
	return nil
}

func proxyBasicAuth(conn net.Conn, br *bufio.Reader, targetAddr, username, password string) error {
	creds := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	if err := writeConnect(conn, targetAddr, "Basic "+creds); err != nil {
		return err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return fmt.Errorf("proxy basic auth response: %w", err)
	}
	drainBody(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy basic auth failed: %d", resp.StatusCode)
	}
	return nil
}

func writeConnect(conn net.Conn, targetAddr, authHeader string) error {
	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if authHeader != "" {
		req += "Proxy-Authorization: " + authHeader + "\r\n"
	}
	req += "\r\n"
	_, err := io.WriteString(conn, req)
	return err
}

func drainBody(resp *http.Response) {
	if resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func detectAuthScheme(header string) string {
	lower := strings.ToLower(header)
	if strings.Contains(lower, "ntlm") {
		return "NTLM"
	}
	if strings.Contains(lower, "negotiate") {
		return "Negotiate"
	}
	if strings.Contains(lower, "basic") {
		return "basic"
	}
	return ""
}

func extractAuthToken(header, scheme string) string {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		lowerPart := strings.ToLower(part)
		prefix := strings.ToLower(scheme) + " "
		if strings.HasPrefix(lowerPart, prefix) {
			return strings.TrimSpace(part[len(prefix):])
		}
	}
	return ""
}
