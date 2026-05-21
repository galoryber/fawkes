package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func generateTestCertKeyPEM(t *testing.T) (certB64, keyB64, caB64 string) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-user"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	clientDER, err := x509.CreateCertificate(rand.Reader, clientTemplate, caTemplate, &clientKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientDER})
	keyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return base64.StdEncoding.EncodeToString(clientCertPEM),
		base64.StdEncoding.EncodeToString(clientKeyPEM),
		base64.StdEncoding.EncodeToString(caPEMBytes)
}

func TestParseKubeconfig_TokenAuth(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: test-ctx
clusters:
- name: test-cluster
  cluster:
    server: https://k8s.example.com:6443
    insecure-skip-tls-verify: true
contexts:
- name: test-ctx
  context:
    cluster: test-cluster
    user: test-user
    namespace: prod
users:
- name: test-user
  user:
    token: eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.test.sig
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatalf("parseKubeconfig: %v", err)
	}
	if kc.CurrentContext != "test-ctx" {
		t.Errorf("current-context = %q, want test-ctx", kc.CurrentContext)
	}

	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatalf("resolveKubeconfigAuth: %v", err)
	}
	if auth.APIServer != "https://k8s.example.com:6443" {
		t.Errorf("APIServer = %q", auth.APIServer)
	}
	if auth.Namespace != "prod" {
		t.Errorf("Namespace = %q, want prod", auth.Namespace)
	}
	if !strings.HasPrefix(auth.Token, "eyJhbGci") {
		t.Errorf("Token doesn't start with expected JWT prefix")
	}
	if !auth.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if auth.HasClientCert {
		t.Error("HasClientCert should be false for token auth")
	}
}

func TestParseKubeconfig_ClientCertAuth(t *testing.T) {
	certB64, keyB64, caB64 := generateTestCertKeyPEM(t)

	yaml := "apiVersion: v1\nkind: Config\ncurrent-context: cert-ctx\n" +
		"clusters:\n- name: cert-cluster\n  cluster:\n    server: https://k8s.internal:6443\n" +
		"    certificate-authority-data: " + caB64 + "\n" +
		"contexts:\n- name: cert-ctx\n  context:\n    cluster: cert-cluster\n    user: cert-user\n    namespace: kube-system\n" +
		"users:\n- name: cert-user\n  user:\n" +
		"    client-certificate-data: " + certB64 + "\n" +
		"    client-key-data: " + keyB64 + "\n"

	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatalf("parseKubeconfig: %v", err)
	}

	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatalf("resolveKubeconfigAuth: %v", err)
	}
	if auth.APIServer != "https://k8s.internal:6443" {
		t.Errorf("APIServer = %q", auth.APIServer)
	}
	if auth.Namespace != "kube-system" {
		t.Errorf("Namespace = %q", auth.Namespace)
	}
	if !auth.HasClientCert {
		t.Error("HasClientCert should be true")
	}
	if auth.Token != "" {
		t.Error("Token should be empty for cert auth")
	}
	if len(auth.CACert) == 0 {
		t.Error("CACert should be populated")
	}

	tlsConfig := auth.buildTLSConfig()
	if tlsConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when CA is provided")
	}
	if tlsConfig.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Certificates count = %d, want 1", len(tlsConfig.Certificates))
	}
}

func TestParseKubeconfig_DefaultNamespace(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://k8s:6443
    insecure-skip-tls-verify: true
contexts:
- name: ctx
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Namespace != "default" {
		t.Errorf("Namespace = %q, want 'default' when not specified", auth.Namespace)
	}
}

func TestParseKubeconfig_TrailingSlashStripped(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://k8s:6443/
    insecure-skip-tls-verify: true
contexts:
- name: ctx
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(auth.APIServer, "/") {
		t.Errorf("APIServer should not have trailing slash: %q", auth.APIServer)
	}
}

func TestParseKubeconfig_ContextNotFound(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: nonexistent
clusters:
- name: c
  cluster:
    server: https://k8s:6443
contexts:
- name: other
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveKubeconfigAuth(kc, "")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' error, got: %v", err)
	}
}

func TestParseKubeconfig_ClusterNotFound(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: other-cluster
  cluster:
    server: https://k8s:6443
contexts:
- name: ctx
  context:
    cluster: missing-cluster
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveKubeconfigAuth(kc, "")
	if err == nil || !strings.Contains(err.Error(), "cluster") {
		t.Errorf("expected cluster error, got: %v", err)
	}
}

func TestParseKubeconfig_UserNotFound(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://k8s:6443
contexts:
- name: ctx
  context:
    cluster: c
    user: missing-user
users:
- name: other-user
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveKubeconfigAuth(kc, "")
	if err == nil || !strings.Contains(err.Error(), "user") {
		t.Errorf("expected user error, got: %v", err)
	}
}

func TestParseKubeconfig_NoAuth(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://k8s:6443
contexts:
- name: ctx
  context:
    cluster: c
    user: u
users:
- name: u
  user: {}
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveKubeconfigAuth(kc, "")
	if err == nil || !strings.Contains(err.Error(), "no token or client certificate") {
		t.Errorf("expected no-auth error, got: %v", err)
	}
}

func TestParseKubeconfig_EmptyContexts(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
`
	_, err := parseKubeconfig([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "no contexts") {
		t.Errorf("expected no-contexts error, got: %v", err)
	}
}

func TestParseKubeconfig_InvalidYAML(t *testing.T) {
	_, err := parseKubeconfig([]byte("not: [yaml: {broken"))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestParseKubeconfig_ExplicitContextOverride(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: default-ctx
clusters:
- name: c1
  cluster:
    server: https://default:6443
    insecure-skip-tls-verify: true
- name: c2
  cluster:
    server: https://override:6443
    insecure-skip-tls-verify: true
contexts:
- name: default-ctx
  context:
    cluster: c1
    user: u
- name: other-ctx
  context:
    cluster: c2
    user: u
    namespace: staging
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}

	auth, err := resolveKubeconfigAuth(kc, "other-ctx")
	if err != nil {
		t.Fatal(err)
	}
	if auth.APIServer != "https://override:6443" {
		t.Errorf("APIServer = %q, want override server", auth.APIServer)
	}
	if auth.Namespace != "staging" {
		t.Errorf("Namespace = %q, want staging", auth.Namespace)
	}
}

func TestParseKubeconfig_NoServer(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster: {}
contexts:
- name: ctx
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolveKubeconfigAuth(kc, "")
	if err == nil || !strings.Contains(err.Error(), "no server URL") {
		t.Errorf("expected no-server error, got: %v", err)
	}
}

func TestParseKubeconfig_FileBasedCerts(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	os.WriteFile(caFile, []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"), 0600)

	yaml := "apiVersion: v1\nkind: Config\ncurrent-context: ctx\n" +
		"clusters:\n- name: c\n  cluster:\n    server: https://k8s:6443\n" +
		"    certificate-authority: " + caFile + "\n" +
		"contexts:\n- name: ctx\n  context:\n    cluster: c\n    user: u\n" +
		"users:\n- name: u\n  user:\n    token: tok\n"

	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(auth.CACert) == 0 {
		t.Error("CACert should be populated from file")
	}
}

func TestLoadPEMData_InlineOverFile(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "cert.pem")
	os.WriteFile(filePath, []byte("file-data"), 0600)

	data, err := loadPEMData("ZmlsZS1kYXRh", filePath) // "file-data" in base64
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "file-data" {
		t.Errorf("expected decoded inline data, got %q", data)
	}
}

func TestLoadPEMData_EmptyReturnsNil(t *testing.T) {
	data, err := loadPEMData("", "")
	if err != nil {
		t.Fatal(err)
	}
	if data != nil {
		t.Errorf("expected nil, got %v", data)
	}
}

func TestLoadPEMData_FileNotFound(t *testing.T) {
	_, err := loadPEMData("", "/nonexistent/path")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBuildTLSConfig_InsecureSkipVerify(t *testing.T) {
	auth := &kubeconfigAuth{InsecureSkipVerify: true}
	cfg := auth.buildTLSConfig()
	if !cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be true")
	}
	if cfg.MinVersion != 0x0303 { // tls.VersionTLS12
		t.Errorf("MinVersion = %x, want TLS 1.2", cfg.MinVersion)
	}
}

func TestBuildTLSConfig_WithCA(t *testing.T) {
	auth := &kubeconfigAuth{
		CACert: []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n"),
	}
	cfg := auth.buildTLSConfig()
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify should be false when CA is provided")
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
}

func TestParseKubeconfig_MultipleUsers(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
current-context: ctx
clusters:
- name: c
  cluster:
    server: https://k8s:6443
    insecure-skip-tls-verify: true
contexts:
- name: ctx
  context:
    cluster: c
    user: user2
users:
- name: user1
  user:
    token: token1
- name: user2
  user:
    token: token2
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if auth.Token != "token2" {
		t.Errorf("Token = %q, want token2", auth.Token)
	}
}

func TestParseKubeconfig_FallbackFirstContext(t *testing.T) {
	yaml := `apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: https://k8s:6443
    insecure-skip-tls-verify: true
contexts:
- name: fallback
  context:
    cluster: c
    user: u
users:
- name: u
  user:
    token: tok
`
	kc, err := parseKubeconfig([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	auth, err := resolveKubeconfigAuth(kc, "")
	if err != nil {
		t.Fatal(err)
	}
	if auth.APIServer != "https://k8s:6443" {
		t.Errorf("APIServer = %q, expected fallback to first context", auth.APIServer)
	}
}
