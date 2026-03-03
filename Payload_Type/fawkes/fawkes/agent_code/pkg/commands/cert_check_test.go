package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

// --- Command metadata ---

func TestCertCheckName(t *testing.T) {
	cmd := &CertCheckCommand{}
	if cmd.Name() != "cert-check" {
		t.Errorf("expected 'cert-check', got %q", cmd.Name())
	}
}

func TestCertCheckDescription(t *testing.T) {
	cmd := &CertCheckCommand{}
	if cmd.Description() == "" {
		t.Error("description should not be empty")
	}
}

// --- Parameter validation ---

func TestCertCheckEmptyParams(t *testing.T) {
	cmd := &CertCheckCommand{}
	result := cmd.Execute(structs.Task{})
	if result.Status != "error" {
		t.Errorf("expected error for empty params, got %q", result.Status)
	}
}

func TestCertCheckInvalidJSON(t *testing.T) {
	cmd := &CertCheckCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestCertCheckMissingHost(t *testing.T) {
	params, _ := json.Marshal(certCheckArgs{Port: 443})
	cmd := &CertCheckCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing host, got %q", result.Status)
	}
}

func TestCertCheckUnreachable(t *testing.T) {
	params, _ := json.Marshal(certCheckArgs{Host: "192.0.2.1", Port: 443, Timeout: 1})
	cmd := &CertCheckCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unreachable host, got %q", result.Status)
	}
}

// --- certTLSVersionName ---

func TestCertTLSVersionName_TLS10(t *testing.T) {
	if certTLSVersionName(tls.VersionTLS10) != "TLS 1.0" {
		t.Error("expected 'TLS 1.0'")
	}
}

func TestCertTLSVersionName_TLS11(t *testing.T) {
	if certTLSVersionName(tls.VersionTLS11) != "TLS 1.1" {
		t.Error("expected 'TLS 1.1'")
	}
}

func TestCertTLSVersionName_TLS12(t *testing.T) {
	if certTLSVersionName(tls.VersionTLS12) != "TLS 1.2" {
		t.Error("expected 'TLS 1.2'")
	}
}

func TestCertTLSVersionName_TLS13(t *testing.T) {
	if certTLSVersionName(tls.VersionTLS13) != "TLS 1.3" {
		t.Error("expected 'TLS 1.3'")
	}
}

func TestCertTLSVersionName_Unknown(t *testing.T) {
	name := certTLSVersionName(0x0000)
	if !strings.Contains(name, "Unknown") {
		t.Errorf("expected 'Unknown' for 0x0000, got %q", name)
	}
}

// --- certFormatCert ---

func TestCertFormatCert_SelfSigned(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "test.local"},
		Issuer:             pkix.Name{CommonName: "test.local"},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SerialNumber:       big.NewInt(1),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	output := certFormatCert(cert, "test.local")
	if !strings.Contains(output, "Self-Signed: YES") {
		t.Error("expected self-signed detection")
	}
	if !strings.Contains(output, "test.local") {
		t.Error("expected subject in output")
	}
}

func TestCertFormatCert_Expired(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "expired.local"},
		Issuer:             pkix.Name{CommonName: "CA"},
		NotBefore:          time.Now().Add(-730 * 24 * time.Hour),
		NotAfter:           time.Now().Add(-365 * 24 * time.Hour),
		SerialNumber:       big.NewInt(2),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	output := certFormatCert(cert, "expired.local")
	if !strings.Contains(output, "EXPIRED") {
		t.Error("expected EXPIRED in output")
	}
}

func TestCertFormatCert_NotYetValid(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "future.local"},
		Issuer:             pkix.Name{CommonName: "CA"},
		NotBefore:          time.Now().Add(365 * 24 * time.Hour),
		NotAfter:           time.Now().Add(730 * 24 * time.Hour),
		SerialNumber:       big.NewInt(3),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	output := certFormatCert(cert, "future.local")
	if !strings.Contains(output, "NOT YET VALID") {
		t.Error("expected NOT YET VALID in output")
	}
}

func TestCertFormatCert_SANs(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "multi.local"},
		Issuer:             pkix.Name{CommonName: "CA"},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SerialNumber:       big.NewInt(4),
		SignatureAlgorithm: x509.SHA256WithRSA,
		DNSNames:           []string{"multi.local", "*.multi.local"},
		IPAddresses:        []net.IP{net.ParseIP("10.0.0.1")},
	}
	output := certFormatCert(cert, "multi.local")
	if !strings.Contains(output, "DNS: multi.local") {
		t.Error("expected DNS SAN in output")
	}
	if !strings.Contains(output, "*.multi.local") {
		t.Error("expected wildcard SAN in output")
	}
	if !strings.Contains(output, "IP:  10.0.0.1") {
		t.Error("expected IP SAN in output")
	}
}

func TestCertFormatCert_CA(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "Root CA"},
		Issuer:             pkix.Name{CommonName: "Root CA"},
		IsCA:               true,
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(3650 * 24 * time.Hour),
		SerialNumber:       big.NewInt(5),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	output := certFormatCert(cert, "")
	if !strings.Contains(output, "CA:          YES") {
		t.Error("expected CA flag in output")
	}
}

func TestCertFormatCert_ValidDaysRemaining(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "valid.local"},
		Issuer:             pkix.Name{CommonName: "CA"},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(30 * 24 * time.Hour),
		SerialNumber:       big.NewInt(6),
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	output := certFormatCert(cert, "valid.local")
	if !strings.Contains(output, "days remaining") {
		t.Error("expected days remaining in output")
	}
}

func TestCertFormatCert_SHA256Fingerprint(t *testing.T) {
	cert := &x509.Certificate{
		Subject:            pkix.Name{CommonName: "fp.local"},
		Issuer:             pkix.Name{CommonName: "CA"},
		NotBefore:          time.Now().Add(-24 * time.Hour),
		NotAfter:           time.Now().Add(365 * 24 * time.Hour),
		SerialNumber:       big.NewInt(7),
		SignatureAlgorithm: x509.SHA256WithRSA,
		Raw:                []byte("test cert raw bytes"),
	}
	output := certFormatCert(cert, "")
	if !strings.Contains(output, "SHA256:") {
		t.Error("expected SHA256 fingerprint in output")
	}
}

// --- Live TLS test with local server ---

func TestCertCheckLiveServer(t *testing.T) {
	// Generate a self-signed cert for testing
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	})
	if err != nil {
		t.Fatalf("failed to start TLS listener: %v", err)
	}
	defer listener.Close()

	// Accept connections in background — must complete TLS handshake before closing
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if tlsConn, ok := conn.(*tls.Conn); ok {
				tlsConn.Handshake()
			}
			conn.Close()
		}
	}()

	// Get the port
	_, portStr, _ := net.SplitHostPort(listener.Addr().String())

	port, _ := strconv.Atoi(portStr)
	params, _ := json.Marshal(certCheckArgs{Host: "127.0.0.1", Port: port, Timeout: 5})

	cmd := &CertCheckCommand{}
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Verify output contains expected fields
	if !strings.Contains(result.Output, "TLS Version:") {
		t.Error("expected TLS Version in output")
	}
	if !strings.Contains(result.Output, "Cipher Suite:") {
		t.Error("expected Cipher Suite in output")
	}
	if !strings.Contains(result.Output, "Self-Signed: YES") {
		t.Error("expected self-signed detection")
	}
	if !strings.Contains(result.Output, "localhost") {
		t.Error("expected 'localhost' in certificate output")
	}
	if !strings.Contains(result.Output, "SHA256:") {
		t.Error("expected SHA256 fingerprint")
	}
}

func TestCertCheckRegistration(t *testing.T) {
	Initialize()
	cmd := GetCommand("cert-check")
	if cmd == nil {
		t.Fatal("cert-check command not registered")
	}
	if cmd.Name() != "cert-check" {
		t.Errorf("expected name 'cert-check', got %q", cmd.Name())
	}
}
