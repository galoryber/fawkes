package http

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var rotationPool = []utls.ClientHelloID{
	utls.HelloChrome_Auto,
	utls.HelloFirefox_Auto,
	utls.HelloSafari_Auto,
	utls.HelloEdge_Auto,
}

// tlsFingerprintID maps a fingerprint name to a uTLS ClientHelloID.
// Returns nil for "rotate" mode — caller should use buildRotatingDialer instead.
func tlsFingerprintID(name string) (*utls.ClientHelloID, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "chrome":
		return &utls.HelloChrome_Auto, true
	case "firefox":
		return &utls.HelloFirefox_Auto, true
	case "safari":
		return &utls.HelloSafari_Auto, true
	case "edge":
		return &utls.HelloEdge_Auto, true
	case "random", "randomized":
		return &utls.HelloRandomized, true
	case "rotate":
		return nil, false
	default:
		return nil, false
	}
}

// isRotateFingerprint returns true when the fingerprint mode is "rotate".
func isRotateFingerprint(name string) bool {
	return strings.ToLower(strings.TrimSpace(name)) == "rotate"
}

// buildUTLSTransportDialer returns a DialTLSContext function that uses uTLS
// to spoof the TLS ClientHello fingerprint while preserving TLS verification settings.
func buildUTLSTransportDialer(helloID *utls.ClientHelloID, stdConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialUTLS(ctx, network, addr, *helloID, stdConfig)
	}
}

// buildRotatingDialer returns a DialTLSContext function that randomly selects
// a different browser fingerprint (Chrome, Firefox, Safari, Edge) for each
// connection. Each individual handshake matches a real browser; over time the
// varying JA3 hashes prevent fingerprint-based correlation.
func buildRotatingDialer(stdConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		var b [4]byte
		_, _ = rand.Read(b[:])
		idx := int(binary.LittleEndian.Uint32(b[:])) % len(rotationPool)
		return dialUTLS(ctx, network, addr, rotationPool[idx], stdConfig)
	}
}

func dialUTLS(ctx context.Context, network, addr string, helloID utls.ClientHelloID, stdConfig *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("TCP dial failed: %w", err)
	}

	tlsConn, err := upgradeToUTLS(ctx, rawConn, addr, helloID, stdConfig)
	if err != nil {
		rawConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// upgradeToUTLS wraps an existing connection with a uTLS handshake.
func upgradeToUTLS(ctx context.Context, rawConn net.Conn, addr string, helloID utls.ClientHelloID, stdConfig *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	utlsConfig := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: stdConfig.InsecureSkipVerify,
		MinVersion:         stdConfig.MinVersion,
	}

	if stdConfig.RootCAs != nil {
		utlsConfig.RootCAs = stdConfig.RootCAs
	}

	if stdConfig.VerifyPeerCertificate != nil {
		stdVerify := stdConfig.VerifyPeerCertificate
		utlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			return stdVerify(rawCerts, chains)
		}
	}

	tlsConn := utls.UClient(rawConn, utlsConfig, helloID)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// upgradeToStdTLS wraps an existing connection with a standard Go TLS handshake.
func upgradeToStdTLS(ctx context.Context, rawConn net.Conn, addr string, tlsConfig *tls.Config) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	cfg := tlsConfig.Clone()
	cfg.ServerName = host
	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}
