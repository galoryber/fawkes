package http

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// tlsFingerprintID maps a fingerprint name to a uTLS ClientHelloID.
// Supported values: "chrome", "firefox", "safari", "edge", "go" (default/no spoofing).
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
	default:
		return nil, false
	}
}

// buildUTLSTransportDialer returns a DialTLSContext function that uses uTLS
// to spoof the TLS ClientHello fingerprint while preserving TLS verification settings.
func buildUTLSTransportDialer(helloID *utls.ClientHelloID, stdConfig *tls.Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Extract hostname for SNI
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		// Dial TCP connection
		dialer := &net.Dialer{}
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("TCP dial failed: %w", err)
		}

		// Build uTLS config from the standard tls.Config
		utlsConfig := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: stdConfig.InsecureSkipVerify,
			MinVersion:         stdConfig.MinVersion,
		}

		// Carry over root CA pool if set
		if stdConfig.RootCAs != nil {
			utlsConfig.RootCAs = stdConfig.RootCAs
		}

		// Carry over VerifyPeerCertificate for cert pinning
		if stdConfig.VerifyPeerCertificate != nil {
			stdVerify := stdConfig.VerifyPeerCertificate
			utlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
				return stdVerify(rawCerts, chains)
			}
		}

		// Create uTLS connection with the specified fingerprint
		tlsConn := utls.UClient(rawConn, utlsConfig, *helloID)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		return tlsConn, nil
	}
}
