package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

// --- adcsParseSubject Tests ---

func TestAdcsParseSubject_CN(t *testing.T) {
	name, err := adcsParseSubject("CN=testuser")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "testuser" {
		t.Errorf("CommonName = %q, want %q", name.CommonName, "testuser")
	}
}

func TestAdcsParseSubject_Full(t *testing.T) {
	name, err := adcsParseSubject("CN=John Doe,O=ACME Corp,OU=IT,L=Springfield,ST=IL,C=US")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "John Doe" {
		t.Errorf("CommonName = %q", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "ACME Corp" {
		t.Errorf("Organization = %v", name.Organization)
	}
	if len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "IT" {
		t.Errorf("OrganizationalUnit = %v", name.OrganizationalUnit)
	}
	if len(name.Locality) != 1 || name.Locality[0] != "Springfield" {
		t.Errorf("Locality = %v", name.Locality)
	}
	if len(name.Province) != 1 || name.Province[0] != "IL" {
		t.Errorf("Province = %v", name.Province)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("Country = %v", name.Country)
	}
}

func TestAdcsParseSubject_WithSpaces(t *testing.T) {
	name, err := adcsParseSubject("CN = testuser , O = MyOrg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "testuser" {
		t.Errorf("CommonName = %q, want %q", name.CommonName, "testuser")
	}
	if len(name.Organization) != 1 || name.Organization[0] != "MyOrg" {
		t.Errorf("Organization = %v", name.Organization)
	}
}

func TestAdcsParseSubject_CaseInsensitive(t *testing.T) {
	name, err := adcsParseSubject("cn=user,ou=dept")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "user" {
		t.Errorf("CommonName = %q", name.CommonName)
	}
	if len(name.OrganizationalUnit) != 1 || name.OrganizationalUnit[0] != "dept" {
		t.Errorf("OU = %v", name.OrganizationalUnit)
	}
}

func TestAdcsParseSubject_StateAlias(t *testing.T) {
	name, err := adcsParseSubject("S=California")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(name.Province) != 1 || name.Province[0] != "California" {
		t.Errorf("Province = %v", name.Province)
	}
}

func TestAdcsParseSubject_UnknownComponent(t *testing.T) {
	_, err := adcsParseSubject("CN=user,XX=unknown")
	if err == nil {
		t.Error("expected error for unknown component XX")
	}
}

func TestAdcsParseSubject_Empty(t *testing.T) {
	name, err := adcsParseSubject("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "" {
		t.Errorf("CommonName should be empty, got %q", name.CommonName)
	}
}

func TestAdcsParseSubject_SkipMalformed(t *testing.T) {
	// Parts without = are skipped
	name, err := adcsParseSubject("CN=user,noequalssign")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if name.CommonName != "user" {
		t.Errorf("CommonName = %q", name.CommonName)
	}
}

// --- adcsDispositionString Tests ---

func TestAdcsDispositionString_Values(t *testing.T) {
	tests := []struct {
		input uint32
		want  string
	}{
		{crDispIssued, "ISSUED"},
		{crDispUnderSubmission, "PENDING"},
		{crDispDenied, "DENIED"},
		{crDispIssuedOutOfBand, "ISSUED_OUT_OF_BAND"},
		{0xFF, "ERROR"},
		{0, "ERROR"},
	}
	for _, tc := range tests {
		got := adcsDispositionString(tc.input)
		if got != tc.want {
			t.Errorf("adcsDispositionString(0x%x) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- adcsDecodeUTF16 Tests ---

func TestAdcsDecodeUTF16_Basic(t *testing.T) {
	// "Hi" in UTF-16LE: 'H'=0x48,0x00 'i'=0x69,0x00
	b := []byte{0x48, 0x00, 0x69, 0x00}
	got := adcsDecodeUTF16(b)
	if got != "Hi" {
		t.Errorf("adcsDecodeUTF16 = %q, want %q", got, "Hi")
	}
}

func TestAdcsDecodeUTF16_WithNullTerminator(t *testing.T) {
	// "A\0" in UTF-16LE with null terminator
	b := []byte{0x41, 0x00, 0x00, 0x00}
	got := adcsDecodeUTF16(b)
	if got != "A" {
		t.Errorf("adcsDecodeUTF16 = %q, want %q", got, "A")
	}
}

func TestAdcsDecodeUTF16_Empty(t *testing.T) {
	got := adcsDecodeUTF16(nil)
	if got != "" {
		t.Errorf("adcsDecodeUTF16(nil) = %q, want empty", got)
	}
	got = adcsDecodeUTF16([]byte{0})
	if got != "" {
		t.Errorf("adcsDecodeUTF16(1 byte) = %q, want empty", got)
	}
}

func TestAdcsDecodeUTF16_Unicode(t *testing.T) {
	// Euro sign: U+20AC = 0xAC, 0x20 in UTF-16LE
	b := []byte{0xAC, 0x20}
	got := adcsDecodeUTF16(b)
	if got != "\u20AC" {
		t.Errorf("adcsDecodeUTF16(euro) = %q, want %q", got, "\u20AC")
	}
}

// --- adcsBuildSANExtension Tests ---

func TestAdcsBuildSANExtension_DNS(t *testing.T) {
	ext, err := adcsBuildSANExtension("host.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ext.Id.Equal(oidSubjectAltName) {
		t.Errorf("OID = %v, want %v", ext.Id, oidSubjectAltName)
	}
	if ext.Critical {
		t.Error("SAN extension should not be critical")
	}
	// Value should contain the DNS name
	var rawValues []asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &rawValues)
	if err != nil {
		t.Fatalf("failed to unmarshal SAN: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("extra bytes after SAN: %d", len(rest))
	}
	if len(rawValues) != 1 {
		t.Fatalf("expected 1 SAN entry, got %d", len(rawValues))
	}
	if rawValues[0].Tag != 2 { // tagDNS
		t.Errorf("SAN tag = %d, want 2 (DNS)", rawValues[0].Tag)
	}
	if string(rawValues[0].Bytes) != "host.example.com" {
		t.Errorf("SAN DNS = %q, want %q", string(rawValues[0].Bytes), "host.example.com")
	}
}

func TestAdcsBuildSANExtension_UPN(t *testing.T) {
	ext, err := adcsBuildSANExtension("admin@domain.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should have OtherName tag (0) for UPN
	var rawValues []asn1.RawValue
	_, err = asn1.Unmarshal(ext.Value, &rawValues)
	if err != nil {
		t.Fatalf("failed to unmarshal SAN: %v", err)
	}
	if len(rawValues) != 1 {
		t.Fatalf("expected 1 SAN entry, got %d", len(rawValues))
	}
	if rawValues[0].Tag != 0 { // tagOtherName
		t.Errorf("SAN tag = %d, want 0 (OtherName/UPN)", rawValues[0].Tag)
	}
}

// --- adcsBuildCSR Tests ---

func TestAdcsBuildCSR_Basic(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	csrDER, err := adcsBuildCSR(key, "CN=testuser", "")
	if err != nil {
		t.Fatalf("adcsBuildCSR failed: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if csr.Subject.CommonName != "testuser" {
		t.Errorf("CSR subject CN = %q, want %q", csr.Subject.CommonName, "testuser")
	}
	if csr.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Errorf("CSR algorithm = %v, want SHA256WithRSA", csr.SignatureAlgorithm)
	}
}

func TestAdcsBuildCSR_WithSAN(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	csrDER, err := adcsBuildCSR(key, "CN=testuser", "admin@domain.local")
	if err != nil {
		t.Fatalf("adcsBuildCSR with SAN failed: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	// Should have at least one extension (SAN)
	found := false
	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			found = true
			break
		}
	}
	if !found {
		t.Error("CSR should contain SAN extension")
	}
}

func TestAdcsBuildCSR_FullSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	csrDER, err := adcsBuildCSR(key, "CN=user,O=Corp,C=US", "")
	if err != nil {
		t.Fatalf("adcsBuildCSR failed: %v", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}

	want := pkix.Name{
		CommonName:   "user",
		Organization: []string{"Corp"},
		Country:      []string{"US"},
	}
	if csr.Subject.CommonName != want.CommonName {
		t.Errorf("CN = %q, want %q", csr.Subject.CommonName, want.CommonName)
	}
	if len(csr.Subject.Organization) != 1 || csr.Subject.Organization[0] != "Corp" {
		t.Errorf("O = %v", csr.Subject.Organization)
	}
	if len(csr.Subject.Country) != 1 || csr.Subject.Country[0] != "US" {
		t.Errorf("C = %v", csr.Subject.Country)
	}
}

func TestAdcsBuildCSR_InvalidSubject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}

	_, err = adcsBuildCSR(key, "CN=user,XX=bad", "")
	if err == nil {
		t.Error("adcsBuildCSR with invalid subject should fail")
	}
}
