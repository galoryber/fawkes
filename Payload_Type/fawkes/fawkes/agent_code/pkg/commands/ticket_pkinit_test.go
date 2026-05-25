package commands

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"

	gokrb5asn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/types"
)

// Legacy (SHA-1/3DES) PFX with no password, CN=testuser@TEST.LOCAL
const testLegacyPFXNoPass = "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"

func generateTestCertKey(t *testing.T) (certPEM, keyPEM string, certDER []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "testuser@TEST.LOCAL"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDERBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes}
	keyBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}

	return string(pem.EncodeToMemory(certBlock)), string(pem.EncodeToMemory(keyBlock)), certDERBytes
}

func generateTestECCertKey(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ecuser@TEST.LOCAL"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	ecDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC key: %v", err)
	}

	certBlock := &pem.Block{Type: "CERTIFICATE", Bytes: certDER}
	keyBlock := &pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}

	return string(pem.EncodeToMemory(certBlock)), string(pem.EncodeToMemory(keyBlock))
}

func TestParsePEMCertKey_RSA(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCertKey(t)
	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsePEMCertKey failed: %v", err)
	}
	if ck.Cert == nil {
		t.Fatal("certificate is nil")
	}
	if ck.Key == nil {
		t.Fatal("private key is nil")
	}
	if _, ok := ck.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected RSA key, got %T", ck.Key)
	}
	if ck.Cert.Subject.CommonName != "testuser@TEST.LOCAL" {
		t.Fatalf("expected CN=testuser@TEST.LOCAL, got %s", ck.Cert.Subject.CommonName)
	}
}

func TestParsePEMCertKey_EC(t *testing.T) {
	certPEM, keyPEM := generateTestECCertKey(t)
	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsePEMCertKey failed: %v", err)
	}
	if _, ok := ck.Key.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("expected EC key, got %T", ck.Key)
	}
}

func TestParsePEMCertKey_PKCS8(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "pkcs8test"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	pkcs8DER, _ := x509.MarshalPKCS8PrivateKey(key)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))

	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsePEMCertKey PKCS#8 failed: %v", err)
	}
	if ck.Cert == nil || ck.Key == nil {
		t.Fatal("cert or key is nil")
	}
}

func TestParsePEMCertKey_InvalidCert(t *testing.T) {
	_, keyPEM, _ := generateTestCertKey(t)
	_, err := parsePEMCertKey("not a pem", keyPEM)
	if err == nil {
		t.Fatal("expected error for invalid cert PEM")
	}
	if !strings.Contains(err.Error(), "decode certificate PEM") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePEMCertKey_InvalidKey(t *testing.T) {
	certPEM, _, _ := generateTestCertKey(t)
	_, err := parsePEMCertKey(certPEM, "not a pem")
	if err == nil {
		t.Fatal("expected error for invalid key PEM")
	}
	if !strings.Contains(err.Error(), "decode private key PEM") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePEMCertKey_UnsupportedKeyType(t *testing.T) {
	certPEM, _, _ := generateTestCertKey(t)
	fakeKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{1, 2, 3}}))
	_, err := parsePEMCertKey(certPEM, fakeKeyPEM)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePFXCertKey_Base64(t *testing.T) {
	// Legacy (SHA-1/3DES) PFX with no password, compatible with Go's x/crypto/pkcs12
	pfxB64 := "MIIJYQIBAzCCCScGCSqGSIb3DQEHAaCCCRgEggkUMIIJEDCCA8cGCSqGSIb3DQEHBqCCA7gwggO0AgEAMIIDrQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIGDj36vjEoZECAggAgIIDgH9HZaLxB0ZqEdsH1eVKDoW+ry826woJETd+x65zAIHmhWEgYg+Y8TFpy4bzeskHbsMhbBD0uU9pp2OPW4pQz7pJmgoKM0wubtjC8dAgh0TjgXYLXrpcfzjo4va5mxBdz5dgP2nFSHGRCTpkJNg7e4ipMdJBd9nLf+xFUxF9+AAfQ6bHmGGCyXSsVVr+JdG9KVsxJM37BHGx9hSTPAfmesbFPN0hGD+8V5ZigUxqE5zOswAkQvwmQcavwBSYLV0lpPzRBte8KjynK3RWssE+yD4Y+rm048TZQin3H2v4QuOncVA9cYLlC8QquM3bnRMeR0AysYKKrFzbf64P3G+O4ZMjvly+iCmarXdp4KO9tFiQTyGSvMEHBJaeJPL2tCxdRvHc+M5kfiIuwMajqQtk0GyqguBHee4k/at2dBg8Au4QKU+esBo9ZVjQ4md2Tao+6WFHXcFAJNoVVVefWLBn6uJny+XPOx+N6AQW3jXiORcQ7qNPSJAdBAzE2uRqYssvU3WtzYCR0NA+04njXULs6VzddYTzRC+LX9wuriJIqCCkRzUuzeyqwTPzUUjOAZYFWZeW0mSlTMxdCZkiIs8r5aM1TQVx8V/jNQaklSa9rt9dA3qgW8KsDvEpB+cAbjEIZ7oufW0WCuCRHzw0IrC121/W+9IfoO2S5B6SL2qQvFtY2CCUj3z+LFB97TqP+J42Bwuo+EZlKX2bCknVzwmZ9zc8NcEo/F32zeEElJzmEJed3BWSDLL9NSVc4yT0z3Jv4UaAq4rxCkgcB+J/DR9SL2F4dZThaHt/USOrVAcGO2sEirywWoUu1I6EIJZVi+QXCmTTJe9zX3OwIR/PIZNN0Vr7EsFjqzYjA+n/4GwAo/eToEBShunZEqFluJCRF22NpTTuPP8eCWyUAd+d1KWGNqXAnv9qPMm7a2LcAZo9CRXzkQ7tedYpEq6uoAjwfoBkvDUDqYlyflurS+iJH5erX+T6Nc0wlgb+ZUVrp6u2c2zXn7cEDqw6yNu6EqR8IKSYt6SSpS13cYE9Pkq5H/0xkPXBiyHu7gXiUvdVTEWCrVWvCpOFz4kPfn3L0Iiuy+Pauc9FZE87s9G5wOzAA1gbyXpSMXjF9rS4roKcLsXofzMEPLA8+v692BH7xNqZPolJ4lfwZhogcEf5AlNtxka1o4D+/MvummxISI6JdEQ6BazyMIIFQQYJKoZIhvcNAQcBoIIFMgSCBS4wggUqMIIFJgYLKoZIhvcNAQwKAQKgggTuMIIE6jAcBgoqhkiG9w0BDAEDMA4ECIs5wSb58dqrAgIIAASCBMiTDkfx59ZcNa0338C+nUtOEyDf+dzgykbart0/DxriRSzvSyMEuH1Esrxs4nUAoWDBg6rlysYHIq0dc4cspwKZrckXZYxvtgakzty2zlPY+dggliSjk6dhbNIp5PHFzTOWb4OycHqmkFW56g32cRTrymUi7xPumJ5GPzqkZnpwtXPFbI6AJAWHT8QCM0hiI9e0bsq+drWKdiKdOIAKOoCvmjB+jWJZ8Izu2XyRsr+ihrAcVdIPxtrOZ34jO/t77FcovQV/wN9ilITQDsPCEGeT7NGSmH8G9lx9sWn2QXVNyXwgA2hvI94A+Qnn1hTqSa2FTnYkLHIUVJYpiwIePRhxxpddFsen19Wqv5zDPvKDc0lH+oe9J3xvV9BpkIobuTj2yRt5fqwigeiaYichFwfEizeeCihbTLpVv7fHG+3/uu2tlqoh+KDApFvqHeZqHIfvubXz3OOh8xWqZfdGLGZYM3RLw+Nq6bcMOI0OAtnvKa2XKBHBl6fJNUQ2Ccf9ELnIr9d5suTkR/SyGDNsQuJUSaMD8kt0w42Dakd5DnBLlVt69fkL1ea4b7h2OeGhk4nChxd0UVQ6UpuwKG8VVZ20q6UJyXiLzXYmx0Dp5lR8OCd4qlevEZjOr2CkWjYWqUtJTYlOSs+X2bKaKBRursw6+K8fHBweQ1bLIcuMgDF4EQqmQgytuqpNB6jjec6kE1R0UCe3RqIOKusa0saZU9DPsRRv54A7Cb4Qg48pMWzldMK56TO6+sREqvrr0kaaClwnWhmZGQJhyOrVYoTKhlm9ARNosIACJuBKAU0Eotov5D2oHMyhgQcidBS2/YLFyMPCJvPnYSBWqnU+VDGgXzmJiqz4b0/8zDSoNeQl1RUsUZSSezV0e6OIEcUxsPKgPZRV7bOMW6axXsteivGZlvAMoCU0x5vK0j2ebL0bQZohjrG5RJWrBXKdkP/+t63inXYz0MykS69vfFHkX3xPGX1oi++DvtegHMqmXdmRoCwudHUbpCMEiFZ6wLy0zgzN5kyCWiNyztGLnFPExy6liQWO3+9XzBLkTyw2uDqcTB02bYTFyur3lCTHCO6K66r0u7GeIMSpbN4UiGWCi6q00MOV9quQaHkMJj1bNMKLDLkxZMVQZ7gEGkQ7zOUaxVSY4EtZ3xMaNwcyEsyWxiByFMf4M7mfdx95CUqBt8s9A39dtPxak4/QbZFwcOstnEFrFBcAt9GIt7AlQDVC8qaMiK9J58F6Jh894deIz5mQXem0gx5Na820XClS59taHpdWcPEqiz8h4u9teH76tOr1VF7lIxUhV+ggNM++LbHbWa6nyY8osEiR8/fpZ4S37jgbJhsmRaNNexLpwbJ26Sg1d3OMSOBjwy1L14HD6Zse46G3hIIL7/rnI+3V5ItVnF5z3UKJrsKeC2tKXKNgsM7/NLCNwmN8c4jmv/T3mZFvmNzr25X3OY1DVgTwaePDpXFpvJXe0QC/b0yfRMESUoB8Jb1txxxvpMMtbiWl0ji0fufquCd40VT/woojBqGxN1GrH2v95lWoyGRjWlefWGHlD1bawBBb12V6AGmVafZgIqVshXkg3q7ZEUV8Mj84H0s++nOe6eLniH66zoVLAkIdu0MdIjoywRbC3gIxJTAjBgkqhkiG9w0BCRUxFgQUOphvXnwKOFtbOEAclMFUQbFuMTMwMTAhMAkGBSsOAwIaBQAEFJVxXGINi9QIfuexEtCCg7TmAHGXBAis3LUQg6HQCAICCAA="

	ck, err := parsePFXCertKey(pfxB64, "")
	if err != nil {
		t.Fatalf("parsePFXCertKey failed: %v", err)
	}
	if ck.Cert == nil {
		t.Fatal("certificate is nil")
	}
	if ck.Key == nil {
		t.Fatal("private key is nil")
	}
	if ck.Cert.Subject.CommonName != "testuser@TEST.LOCAL" {
		t.Fatalf("expected CN=testuser@TEST.LOCAL, got %s", ck.Cert.Subject.CommonName)
	}
}

func TestParsePFXCertKey_WithPassword(t *testing.T) {
	// Legacy (SHA-1/3DES) PFX with password "testpw"
	pfxB64 := "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"

	ck, err := parsePFXCertKey(pfxB64, "testpw")
	if err != nil {
		t.Fatalf("parsePFXCertKey with password failed: %v", err)
	}
	if ck.Cert == nil || ck.Key == nil {
		t.Fatal("cert or key is nil")
	}
	if ck.Cert.Subject.CommonName != "testuser@TEST.LOCAL" {
		t.Fatalf("expected CN=testuser@TEST.LOCAL, got %s", ck.Cert.Subject.CommonName)
	}
}

func TestParsePFXCertKey_WrongPassword(t *testing.T) {
	// Password-protected legacy PFX (password is "testpw")
	pfxB64 := "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"

	_, err := parsePFXCertKey(pfxB64, "wrongpassword")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestParsePFXCertKey_InvalidBase64(t *testing.T) {
	_, err := parsePFXCertKey("not-valid-base64-!!!@@@", "")
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !strings.Contains(err.Error(), "not a valid file path or base64 data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParsePFXCertKey_FilePath(t *testing.T) {
	pfxData, _ := base64.StdEncoding.DecodeString(testLegacyPFXNoPass)
	tmpDir := t.TempDir()
	pfxPath := filepath.Join(tmpDir, "test.pfx")
	if err := os.WriteFile(pfxPath, pfxData, 0600); err != nil {
		t.Fatalf("failed to write PFX file: %v", err)
	}

	ck, err := parsePFXCertKey(pfxPath, "")
	if err != nil {
		t.Fatalf("parsePFXCertKey from file failed: %v", err)
	}
	if ck.Cert.Subject.CommonName != "testuser@TEST.LOCAL" {
		t.Fatalf("expected CN=testuser@TEST.LOCAL, got %s", ck.Cert.Subject.CommonName)
	}
}

func TestParsePFXCertKey_NonexistentFile(t *testing.T) {
	_, err := parsePFXCertKey("/tmp/nonexistent_pfx_file_12345.pfx", "")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
	if !strings.Contains(err.Error(), "failed to read PFX file") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateDHKeyPair(t *testing.T) {
	priv, pubBytes, clientNonce, err := generateDHKeyPair()
	if err != nil {
		t.Fatalf("generateDHKeyPair failed: %v", err)
	}
	if priv == nil || priv.Sign() <= 0 {
		t.Fatal("private key is nil or zero")
	}
	if len(pubBytes) != 128 {
		t.Fatalf("expected 128-byte public key, got %d bytes", len(pubBytes))
	}
	if len(clientNonce) != 32 {
		t.Fatalf("expected 32-byte client nonce, got %d bytes", len(clientNonce))
	}

	pub := new(big.Int).SetBytes(pubBytes)
	expected := new(big.Int).Exp(dhGroupG, priv, dhGroupP)
	if pub.Cmp(expected) != 0 {
		t.Fatal("public key does not match g^priv mod p")
	}
}

func TestGenerateDHKeyPair_Uniqueness(t *testing.T) {
	_, pub1, nonce1, _ := generateDHKeyPair()
	_, pub2, nonce2, _ := generateDHKeyPair()

	if string(pub1) == string(pub2) {
		t.Fatal("two DH key pairs should have different public keys")
	}
	if string(nonce1) == string(nonce2) {
		t.Fatal("two DH nonces should be different")
	}
}

func TestBuildDHSubjectPublicKeyInfo(t *testing.T) {
	_, pubBytes, _, err := generateDHKeyPair()
	if err != nil {
		t.Fatalf("generateDHKeyPair failed: %v", err)
	}

	spki, err := buildDHSubjectPublicKeyInfo(pubBytes)
	if err != nil {
		t.Fatalf("buildDHSubjectPublicKeyInfo failed: %v", err)
	}
	if len(spki) == 0 {
		t.Fatal("SPKI is empty")
	}

	var parsed pkinitSPKI
	rest, err := gokrb5asn1.Unmarshal(spki, &parsed)
	if err != nil {
		t.Fatalf("failed to unmarshal SPKI: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after SPKI: %d", len(rest))
	}
	if !parsed.Algorithm.Algorithm.Equal(gokrb5asn1.ObjectIdentifier(oidDHPublicNumber)) {
		t.Fatalf("wrong algorithm OID: %v", parsed.Algorithm.Algorithm)
	}
}

func TestPkinitOctetstring2Key_AES256(t *testing.T) {
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i)
	}

	key := pkinitOctetstring2Key(input, 32)
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	key2 := pkinitOctetstring2Key(input, 32)
	if string(key) != string(key2) {
		t.Fatal("deterministic: same input should produce same key")
	}
}

func TestPkinitOctetstring2Key_AES128(t *testing.T) {
	input := make([]byte, 64)
	for i := range input {
		input[i] = byte(i + 42)
	}

	key := pkinitOctetstring2Key(input, 16)
	if len(key) != 16 {
		t.Fatalf("expected 16-byte key, got %d", len(key))
	}
}

func TestPkinitOctetstring2Key_ShortInput(t *testing.T) {
	input := []byte{0x01, 0x02, 0x03}
	key := pkinitOctetstring2Key(input, 32)
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key even with short input, got %d", len(key))
	}
}

func TestPkinitOctetstring2Key_DifferentInputsDifferentKeys(t *testing.T) {
	input1 := make([]byte, 64)
	input2 := make([]byte, 64)
	input2[0] = 1

	key1 := pkinitOctetstring2Key(input1, 32)
	key2 := pkinitOctetstring2Key(input2, 32)
	if string(key1) == string(key2) {
		t.Fatal("different inputs should produce different keys")
	}
}

func TestBuildCMSSignedData_RSA(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCertKey(t)
	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsePEMCertKey failed: %v", err)
	}

	authPackBytes := []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	cms, err := buildCMSSignedData(authPackBytes, ck)
	if err != nil {
		t.Fatalf("buildCMSSignedData failed: %v", err)
	}
	if len(cms) == 0 {
		t.Fatal("CMS is empty")
	}

	var ci contentInfo
	rest, err := gokrb5asn1.Unmarshal(cms, &ci)
	if err != nil {
		t.Fatalf("failed to unmarshal CMS ContentInfo: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	if !ci.ContentType.Equal(gokrb5asn1.ObjectIdentifier(oidSignedData)) {
		t.Fatalf("wrong content type: %v", ci.ContentType)
	}
}

func TestBuildCMSSignedData_EC(t *testing.T) {
	certPEM, keyPEM := generateTestECCertKey(t)
	ck, err := parsePEMCertKey(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("parsePEMCertKey failed: %v", err)
	}

	authPackBytes := []byte{0x30, 0x03, 0x01, 0x01, 0xFF}
	cms, err := buildCMSSignedData(authPackBytes, ck)
	if err != nil {
		t.Fatalf("buildCMSSignedData EC failed: %v", err)
	}
	if len(cms) == 0 {
		t.Fatal("CMS is empty")
	}
}

func TestReadIfPath_PlainString(t *testing.T) {
	result := readIfPath("just a plain string")
	if result != "just a plain string" {
		t.Fatalf("expected unchanged string, got %q", result)
	}
}

func TestReadIfPath_NonexistentPath(t *testing.T) {
	result := readIfPath("/tmp/nonexistent_file_xyz_12345.pem")
	if result != "/tmp/nonexistent_file_xyz_12345.pem" {
		t.Fatalf("expected unchanged path for nonexistent file, got %q", result)
	}
}

func TestReadIfPath_ValidFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.pem")
	if err := os.WriteFile(path, []byte("file content here"), 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	result := readIfPath(path)
	if result != "file content here" {
		t.Fatalf("expected file content, got %q", result)
	}
}

func TestReadIfPath_WindowsPath(t *testing.T) {
	result := readIfPath(`C:\Users\test\cert.pem`)
	if result != `C:\Users\test\cert.pem` {
		t.Fatalf("expected unchanged Windows path (file doesn't exist), got %q", result)
	}
}

func TestReadIfPath_TrimWhitespace(t *testing.T) {
	result := readIfPath("  some value  ")
	if result != "some value" {
		t.Fatalf("expected trimmed string, got %q", result)
	}
}

func TestTicketPKINIT_MissingParams(t *testing.T) {
	tests := []struct {
		name string
		args ticketArgs
		want string
	}{
		{
			"missing realm",
			ticketArgs{Action: "pkinit", Username: "admin", Server: "dc.test.local"},
			"realm and server",
		},
		{
			"missing server",
			ticketArgs{Action: "pkinit", Username: "admin", Realm: "TEST.LOCAL"},
			"realm and server",
		},
		{
			"missing username",
			ticketArgs{Action: "pkinit", Realm: "TEST.LOCAL", Server: "dc.test.local"},
			"username is required",
		},
		{
			"missing cert and pfx",
			ticketArgs{Action: "pkinit", Realm: "TEST.LOCAL", Server: "dc.test.local", Username: "admin"},
			"certificate+private_key or pfx is required",
		},
		{
			"missing key (cert provided)",
			ticketArgs{Action: "pkinit", Realm: "TEST.LOCAL", Server: "dc.test.local", Username: "admin",
				Certificate: "-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----"},
			"certificate+private_key or pfx is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ticketPKINIT(tt.args)
			if result.Status != "error" {
				t.Fatalf("expected error, got %q", result.Status)
			}
			if !strings.Contains(result.Output, tt.want) {
				t.Fatalf("expected %q in output, got %q", tt.want, result.Output)
			}
		})
	}
}

func TestTicketPKINIT_InvalidPEM(t *testing.T) {
	args := ticketArgs{
		Action:      "pkinit",
		Realm:       "TEST.LOCAL",
		Server:      "dc.test.local",
		Username:    "admin",
		Certificate: "not a cert",
		PrivateKey:  "not a key",
	}
	result := ticketPKINIT(args)
	if result.Status != "error" {
		t.Fatalf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error loading certificate/key") {
		t.Fatalf("expected cert/key error, got %q", result.Output)
	}
}

func TestTicketPKINIT_InvalidPFX(t *testing.T) {
	args := ticketArgs{
		Action:   "pkinit",
		Realm:    "TEST.LOCAL",
		Server:   "dc.test.local",
		Username: "admin",
		PFX:      base64.StdEncoding.EncodeToString([]byte("not a pfx")),
	}
	result := ticketPKINIT(args)
	if result.Status != "error" {
		t.Fatalf("expected error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Error loading PFX") {
		t.Fatalf("expected PFX error, got %q", result.Output)
	}
}

func TestTicketPKINIT_PFXTakesPrecedence(t *testing.T) {
	args := ticketArgs{
		Action:      "pkinit",
		Realm:       "TEST.LOCAL",
		Server:      "dc.test.local",
		Username:    "admin",
		Certificate: "some bogus cert",
		PrivateKey:  "some bogus key",
		PFX:         testLegacyPFXNoPass,
	}
	result := ticketPKINIT(args)
	if result.Status == "error" && strings.Contains(result.Output, "Error loading certificate/key") {
		t.Fatal("PFX should take precedence over PEM — got PEM parsing error instead of PFX/KDC error")
	}
}

func TestTicketPKINIT_ViaExecute(t *testing.T) {
	args := ticketArgs{
		Action:   "pkinit",
		Realm:    "TEST.LOCAL",
		Server:   "dc.test.local",
		Username: "admin",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error (no cert), got %q", result.Status)
	}
	if !strings.Contains(result.Output, "certificate+private_key or pfx") {
		t.Fatalf("expected cert/pfx error, got %q", result.Output)
	}
}

func TestDerHelpers(t *testing.T) {
	t.Run("derSequence", func(t *testing.T) {
		seq := derSequence([]byte{0x02, 0x01, 0x01}, []byte{0x02, 0x01, 0x02})
		if seq[0] != 0x30 {
			t.Fatalf("expected SEQUENCE tag 0x30, got 0x%02x", seq[0])
		}
	})

	t.Run("derSet", func(t *testing.T) {
		set := derSet([]byte{0x02, 0x01, 0x01})
		if set[0] != 0x31 {
			t.Fatalf("expected SET tag 0x31, got 0x%02x", set[0])
		}
	})

	t.Run("derOctetString", func(t *testing.T) {
		os := derOctetString([]byte{0x01, 0x02, 0x03})
		if os[0] != 0x04 {
			t.Fatalf("expected OCTET STRING tag 0x04, got 0x%02x", os[0])
		}
		if os[1] != 3 {
			t.Fatalf("expected length 3, got %d", os[1])
		}
	})

	t.Run("derWrap", func(t *testing.T) {
		w := derWrap(0xA0, []byte{0x01, 0x02})
		if w[0] != 0xA0 {
			t.Fatalf("expected tag 0xA0, got 0x%02x", w[0])
		}
		if w[1] != 2 {
			t.Fatalf("expected length 2, got %d", w[1])
		}
	})

	t.Run("derTL_short", func(t *testing.T) {
		tl := derTL(0x30, 10)
		if len(tl) != 2 {
			t.Fatalf("expected 2 bytes for short TL, got %d", len(tl))
		}
	})

	t.Run("derTL_long", func(t *testing.T) {
		tl := derTL(0x30, 256)
		if len(tl) != 4 {
			t.Fatalf("expected 4 bytes for long TL (2-byte length), got %d", len(tl))
		}
		if tl[1] != 0x82 {
			t.Fatalf("expected long-form length marker 0x82, got 0x%02x", tl[1])
		}
	})

	t.Run("derAlgID", func(t *testing.T) {
		aid := derAlgID(gokrb5asn1.ObjectIdentifier{1, 2, 3})
		if aid[0] != 0x30 {
			t.Fatalf("expected SEQUENCE tag, got 0x%02x", aid[0])
		}
	})
}

func TestPKAuthenticatorChecksum(t *testing.T) {
	testBody := []byte{0x30, 0x05, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01}
	checksum := sha1.Sum(testBody)

	if len(checksum) != 20 {
		t.Fatalf("expected 20-byte SHA-1 checksum, got %d bytes", len(checksum))
	}

	auth := pkAuthenticator{
		CUSec:      0,
		CTime:      time.Now().UTC(),
		Nonce:      12345,
		PaChecksum: checksum[:],
	}
	marshaled, err := gokrb5asn1.Marshal(auth)
	if err != nil {
		t.Fatalf("failed to marshal pkAuthenticator: %v", err)
	}
	if len(marshaled) == 0 {
		t.Fatal("marshaled pkAuthenticator is empty")
	}

	var parsed pkAuthenticator
	rest, err := gokrb5asn1.Unmarshal(marshaled, &parsed)
	if err != nil {
		t.Fatalf("failed to unmarshal pkAuthenticator: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("trailing bytes: %d", len(rest))
	}
	if parsed.Nonce != 12345 {
		t.Fatalf("expected nonce 12345, got %d", parsed.Nonce)
	}
	if len(parsed.PaChecksum) != 20 {
		t.Fatalf("expected 20-byte checksum, got %d", len(parsed.PaChecksum))
	}
}

func TestDHGroupParameters(t *testing.T) {
	if dhGroupP == nil {
		t.Fatal("DH group P is nil")
	}
	if dhGroupG.Int64() != 2 {
		t.Fatalf("expected DH generator 2, got %s", dhGroupG.String())
	}
	if dhGroupP.BitLen() != 1024 {
		t.Fatalf("expected 1024-bit prime, got %d bits", dhGroupP.BitLen())
	}
}

func TestPkinitFormatOutput(t *testing.T) {
	certPEM, _, _ := generateTestCertKey(t)
	certBlock, _ := pem.Decode([]byte(certPEM))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)

	output := pkinitFormatOutput(
		"admin", "TEST.LOCAL", cert,
		types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
		time.Now(), time.Now().Add(24*time.Hour),
		"kirbi", "dGVzdA==",
	)
	if !strings.Contains(output, "PKINIT AS exchange successful") {
		t.Fatalf("expected success header, got %q", output)
	}
	if !strings.Contains(output, "admin@TEST.LOCAL") {
		t.Fatalf("expected user@realm in output, got %q", output)
	}
	if !strings.Contains(output, "etype 18") {
		t.Fatalf("expected etype 18 in output, got %q", output)
	}
	if !strings.Contains(output, "Rubeus") {
		t.Fatalf("expected kirbi usage hint, got %q", output)
	}

	outputCC := pkinitFormatOutput(
		"admin", "TEST.LOCAL", cert,
		types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)},
		time.Now(), time.Now().Add(24*time.Hour),
		"ccache", "dGVzdA==",
	)
	if !strings.Contains(outputCC, "KRB5CCNAME") {
		t.Fatalf("expected ccache usage hint, got %q", outputCC)
	}
}

func TestDecryptEncKeyPack_InvalidData(t *testing.T) {
	certPEM, keyPEM, _ := generateTestCertKey(t)
	ck, _ := parsePEMCertKey(certPEM, keyPEM)

	_, err := decryptEncKeyPack([]byte{0x01, 0x02, 0x03}, ck)
	if err == nil {
		t.Fatal("expected error for invalid encKeyPack data")
	}
}
