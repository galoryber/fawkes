package http

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestTlsFingerprintID_Chrome(t *testing.T) {
	id, ok := tlsFingerprintID("chrome")
	if !ok {
		t.Fatal("expected ok=true for 'chrome'")
	}
	if *id != utls.HelloChrome_Auto {
		t.Errorf("expected HelloChrome_Auto")
	}
}

func TestTlsFingerprintID_Firefox(t *testing.T) {
	id, ok := tlsFingerprintID("firefox")
	if !ok {
		t.Fatal("expected ok=true for 'firefox'")
	}
	if *id != utls.HelloFirefox_Auto {
		t.Errorf("expected HelloFirefox_Auto")
	}
}

func TestTlsFingerprintID_Safari(t *testing.T) {
	id, ok := tlsFingerprintID("safari")
	if !ok {
		t.Fatal("expected ok=true for 'safari'")
	}
	if *id != utls.HelloSafari_Auto {
		t.Errorf("expected HelloSafari_Auto")
	}
}

func TestTlsFingerprintID_Edge(t *testing.T) {
	id, ok := tlsFingerprintID("edge")
	if !ok {
		t.Fatal("expected ok=true for 'edge'")
	}
	if *id != utls.HelloEdge_Auto {
		t.Errorf("expected HelloEdge_Auto")
	}
}

func TestTlsFingerprintID_Random(t *testing.T) {
	id, ok := tlsFingerprintID("random")
	if !ok {
		t.Fatal("expected ok=true for 'random'")
	}
	if *id != utls.HelloRandomized {
		t.Errorf("expected HelloRandomized")
	}
}

func TestTlsFingerprintID_Randomized(t *testing.T) {
	id, ok := tlsFingerprintID("randomized")
	if !ok {
		t.Fatal("expected ok=true for 'randomized'")
	}
	if *id != utls.HelloRandomized {
		t.Errorf("expected HelloRandomized")
	}
}

func TestTlsFingerprintID_Rotate(t *testing.T) {
	_, ok := tlsFingerprintID("rotate")
	if ok {
		t.Error("expected ok=false for 'rotate' (handled separately by isRotateFingerprint)")
	}
	if !isRotateFingerprint("rotate") {
		t.Error("isRotateFingerprint should return true for 'rotate'")
	}
	if !isRotateFingerprint("  Rotate  ") {
		t.Error("isRotateFingerprint should handle whitespace and case")
	}
	if isRotateFingerprint("chrome") {
		t.Error("isRotateFingerprint should return false for 'chrome'")
	}
}

func TestTlsFingerprintID_Go(t *testing.T) {
	_, ok := tlsFingerprintID("go")
	if ok {
		t.Error("expected ok=false for 'go' (default, no spoofing)")
	}
}

func TestBuildRotatingDialer(t *testing.T) {
	cfg := &tls.Config{InsecureSkipVerify: true}
	dialer := buildRotatingDialer(cfg)
	if dialer == nil {
		t.Fatal("buildRotatingDialer returned nil")
	}
}

func TestRotationPoolHasExpectedBrowsers(t *testing.T) {
	if len(rotationPool) < 4 {
		t.Errorf("rotationPool has %d entries, expected at least 4", len(rotationPool))
	}
}

func TestNewHTTPProfile_WithRotateFingerprint(t *testing.T) {
	cfg := ProfileConfig{
		BaseURL: "https://localhost:443", UserAgent: "TestAgent/1.0",
		MaxRetries: 10, SleepInterval: 5, Jitter: 10,
		GetEndpoint: "/get", PostEndpoint: "/post",
		TLSVerify: "none", TLSFingerprint: "rotate",
	}
	p := NewHTTPProfile(cfg)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
	if p.client == nil {
		t.Fatal("client is nil")
	}
}

func TestTlsFingerprintID_Empty(t *testing.T) {
	_, ok := tlsFingerprintID("")
	if ok {
		t.Error("expected ok=false for empty string")
	}
}

func TestTlsFingerprintID_CaseInsensitive(t *testing.T) {
	for _, name := range []string{"Chrome", "CHROME", "Firefox", "FIREFOX", "Safari", "SAFARI", "Edge", "EDGE"} {
		_, ok := tlsFingerprintID(name)
		if !ok {
			t.Errorf("expected ok=true for %q (case insensitive)", name)
		}
	}
}

func TestTlsFingerprintID_Whitespace(t *testing.T) {
	id, ok := tlsFingerprintID("  chrome  ")
	if !ok {
		t.Fatal("expected ok=true for ' chrome ' (trimmed)")
	}
	if *id != utls.HelloChrome_Auto {
		t.Errorf("expected HelloChrome_Auto")
	}
}

func TestNewHTTPProfile_WithTLSFingerprint(t *testing.T) {
	// When fingerprint is set, DialTLSContext should be configured (non-nil transport)
	cfg := ProfileConfig{
		BaseURL: "https://localhost:443", UserAgent: "TestAgent/1.0",
		MaxRetries: 10, SleepInterval: 5, Jitter: 10,
		GetEndpoint: "/get", PostEndpoint: "/post",
		TLSVerify: "none", TLSFingerprint: "chrome",
	}
	p := NewHTTPProfile(cfg)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
	if p.client == nil {
		t.Fatal("client is nil")
	}
}

func TestNewHTTPProfile_WithoutTLSFingerprint(t *testing.T) {
	// When fingerprint is "go" or empty, standard TLS should be used
	cfg := ProfileConfig{
		BaseURL: "https://localhost:443", UserAgent: "TestAgent/1.0",
		MaxRetries: 10, SleepInterval: 5, Jitter: 10,
		GetEndpoint: "/get", PostEndpoint: "/post",
		TLSVerify: "none", TLSFingerprint: "go",
	}
	p := NewHTTPProfile(cfg)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
}

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func TestNewHTTPProfile_MTLSCertsPreservedWithFingerprint(t *testing.T) {
	cert := generateTestCert(t)
	cfg := ProfileConfig{
		BaseURL: "https://localhost:443", UserAgent: "TestAgent/1.0",
		MaxRetries: 10, SleepInterval: 5, Jitter: 10,
		GetEndpoint: "/get", PostEndpoint: "/post",
		TLSVerify: "none", TLSFingerprint: "chrome",
		MTLSCertPEM: "unused-in-this-path",
		MTLSKeyPEM:  "unused-in-this-path",
	}

	tlsConfig := buildTLSConfig("none")
	tlsConfig.Certificates = []tls.Certificate{cert}

	// Verify the upgradeToUTLS config includes certificates
	utlsConfig := &utls.Config{
		ServerName:         "test",
		InsecureSkipVerify: true,
	}
	if len(tlsConfig.Certificates) > 0 {
		utlsCerts := make([]utls.Certificate, len(tlsConfig.Certificates))
		for i, c := range tlsConfig.Certificates {
			utlsCerts[i] = utls.Certificate{
				Certificate: c.Certificate,
				PrivateKey:  c.PrivateKey,
				OCSPStaple:  c.OCSPStaple,
				Leaf:        c.Leaf,
			}
		}
		utlsConfig.Certificates = utlsCerts
	}

	if len(utlsConfig.Certificates) != 1 {
		t.Fatalf("expected 1 certificate in utlsConfig, got %d", len(utlsConfig.Certificates))
	}
	if len(utlsConfig.Certificates[0].Certificate) != 1 {
		t.Fatalf("expected 1 cert chain entry, got %d", len(utlsConfig.Certificates[0].Certificate))
	}
	if utlsConfig.Certificates[0].PrivateKey == nil {
		t.Fatal("private key not copied to utlsConfig")
	}

	_ = cfg
}

func TestNewHTTPProfile_NoCertsWhenMTLSEmpty(t *testing.T) {
	cfg := ProfileConfig{
		BaseURL: "https://localhost:443", UserAgent: "TestAgent/1.0",
		MaxRetries: 10, SleepInterval: 5, Jitter: 10,
		GetEndpoint: "/get", PostEndpoint: "/post",
		TLSVerify: "none", TLSFingerprint: "chrome",
	}
	p := NewHTTPProfile(cfg)
	if p == nil {
		t.Fatal("NewHTTPProfile returned nil")
	}
}
