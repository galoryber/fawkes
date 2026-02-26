//go:build !windows
// +build !windows

package commands

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"
)

func TestKlistCommandName(t *testing.T) {
	cmd := &KlistCommand{}
	if cmd.Name() != "klist" {
		t.Errorf("expected 'klist', got %q", cmd.Name())
	}
}

func TestKlistCommandDescription(t *testing.T) {
	cmd := &KlistCommand{}
	desc := cmd.Description()
	if desc == "" {
		t.Error("description should not be empty")
	}
}

func TestKlistFormatFlags(t *testing.T) {
	tests := []struct {
		flags    uint32
		expected string
	}{
		{0, "(none)"},
		{0x40000000, "forwardable"},
		{0x50800000, "forwardable, proxiable, renewable"},
		{0x40e00000, "forwardable, renewable, initial, pre-authent"},
	}

	for _, tt := range tests {
		result := klistFormatFlags(tt.flags)
		if result != tt.expected {
			t.Errorf("klistFormatFlags(0x%08X) = %q, want %q", tt.flags, result, tt.expected)
		}
	}
}

func TestEtypeToNameKL(t *testing.T) {
	tests := []struct {
		etype    int32
		expected string
	}{
		{17, "AES128-CTS"},
		{18, "AES256-CTS"},
		{23, "RC4-HMAC"},
		{1, "DES-CBC-CRC"},
		{99, "etype-99"},
	}

	for _, tt := range tests {
		result := etypeToNameKL(tt.etype)
		if result != tt.expected {
			t.Errorf("etypeToNameKL(%d) = %q, want %q", tt.etype, result, tt.expected)
		}
	}
}

func TestKlistExecuteEmptyParams(t *testing.T) {
	cmd := &KlistCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	// Should default to list action and succeed (or report no tickets)
	if result.Status != "success" {
		t.Logf("Output: %s", result.Output)
		// On a system without Kerberos, this is acceptable
	}
}

func TestKlistExecuteInvalidAction(t *testing.T) {
	cmd := &KlistCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"invalid"}`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid action, got %s", result.Status)
	}
}

func TestKlistExecuteInvalidJSON(t *testing.T) {
	cmd := &KlistCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %s", result.Status)
	}
}

// buildTestCcache creates a minimal valid ccache v4 file for testing
func buildTestCcache(t *testing.T) []byte {
	t.Helper()

	var buf []byte

	// Version: 0x0504
	buf = binary.BigEndian.AppendUint16(buf, 0x0504)

	// Header length: 0 (no header tags)
	buf = binary.BigEndian.AppendUint16(buf, 0)

	// Default principal: user@EXAMPLE.COM
	buf = appendPrincipal(buf, 1, "EXAMPLE.COM", []string{"user"})

	// Credential 1: TGT
	// Client: user@EXAMPLE.COM
	buf = appendPrincipal(buf, 1, "EXAMPLE.COM", []string{"user"})
	// Server: krbtgt/EXAMPLE.COM@EXAMPLE.COM
	buf = appendPrincipal(buf, 2, "EXAMPLE.COM", []string{"krbtgt", "EXAMPLE.COM"})

	// Keyblock: etype 18 (AES256), key = 32 bytes of 0x41
	buf = binary.BigEndian.AppendUint16(buf, 18) // keytype
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0x41
	}
	buf = appendOctetString(buf, key)

	// Times
	now := time.Now()
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(-1*time.Hour).Unix()))  // authtime
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(-1*time.Hour).Unix()))  // starttime
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(9*time.Hour).Unix()))   // endtime
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(7*24*time.Hour).Unix())) // renew_till

	// is_skey
	buf = append(buf, 0)

	// ticket_flags: forwardable + renewable + initial + pre-authent
	buf = binary.BigEndian.AppendUint32(buf, 0x40e00000)

	// addresses: 0
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// authdata: 0
	buf = binary.BigEndian.AppendUint32(buf, 0)

	// ticket data: some dummy ASN.1 ticket
	dummyTicket := []byte{0x61, 0x03, 0x02, 0x01, 0x05} // minimal ASN.1
	buf = appendOctetString(buf, dummyTicket)

	// second ticket: empty
	buf = appendOctetString(buf, nil)

	return buf
}

func appendPrincipal(buf []byte, nameType uint32, realm string, components []string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, nameType)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(components)))
	buf = appendCcacheString(buf, realm)
	for _, c := range components {
		buf = appendCcacheString(buf, c)
	}
	return buf
}

func appendCcacheString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	buf = append(buf, []byte(s)...)
	return buf
}

func appendOctetString(buf []byte, data []byte) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(data)))
	buf = append(buf, data...)
	return buf
}

func TestParseCcacheValid(t *testing.T) {
	ccacheData := buildTestCcache(t)

	// Write to temp file
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_test")
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		t.Fatalf("failed to write test ccache: %v", err)
	}

	principal, creds, err := parseCcache(ccachePath)
	if err != nil {
		t.Fatalf("parseCcache failed: %v", err)
	}

	if principal == nil {
		t.Fatal("expected non-nil default principal")
	}
	if principal.String() != "user@EXAMPLE.COM" {
		t.Errorf("expected user@EXAMPLE.COM, got %s", principal.String())
	}

	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	cred := creds[0]
	if cred.Client.String() != "user@EXAMPLE.COM" {
		t.Errorf("client = %s, want user@EXAMPLE.COM", cred.Client.String())
	}
	if cred.Server.String() != "krbtgt/EXAMPLE.COM@EXAMPLE.COM" {
		t.Errorf("server = %s, want krbtgt/EXAMPLE.COM@EXAMPLE.COM", cred.Server.String())
	}
	if cred.KeyType != 18 {
		t.Errorf("keytype = %d, want 18", cred.KeyType)
	}
	if cred.TicketFlags != 0x40e00000 {
		t.Errorf("flags = 0x%08X, want 0x40e00000", cred.TicketFlags)
	}
	if cred.EndTime.Before(time.Now()) {
		t.Errorf("end time should be in the future")
	}
}

func TestParseCcacheNoFile(t *testing.T) {
	_, _, err := parseCcache("/nonexistent/path/krb5cc_test")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestParseCcacheInvalidVersion(t *testing.T) {
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "bad_ccache")

	// Write invalid version
	data := make([]byte, 10)
	binary.BigEndian.PutUint16(data, 0x0102) // invalid version
	if err := os.WriteFile(ccachePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err := parseCcache(ccachePath)
	if err == nil {
		t.Error("expected error for invalid version")
	}
}

func TestParseCcacheTruncated(t *testing.T) {
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "truncated")

	// Just the version bytes, nothing else
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, 0x0504)
	if err := os.WriteFile(ccachePath, data, 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err := parseCcache(ccachePath)
	if err == nil {
		t.Error("expected error for truncated file")
	}
}

func TestFindCcacheFileDefault(t *testing.T) {
	// Unset KRB5CCNAME to test default path
	orig := os.Getenv("KRB5CCNAME")
	os.Unsetenv("KRB5CCNAME")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		}
	}()

	path := findCcacheFile()
	if path == "" {
		t.Error("expected non-empty default path")
	}
}

func TestFindCcacheFileEnvVar(t *testing.T) {
	orig := os.Getenv("KRB5CCNAME")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	os.Setenv("KRB5CCNAME", "FILE:/tmp/custom_ccache")
	path := findCcacheFile()
	if path != "/tmp/custom_ccache" {
		t.Errorf("expected /tmp/custom_ccache, got %s", path)
	}

	os.Setenv("KRB5CCNAME", "/tmp/direct_path")
	path = findCcacheFile()
	if path != "/tmp/direct_path" {
		t.Errorf("expected /tmp/direct_path, got %s", path)
	}

	os.Setenv("KRB5CCNAME", "KEYRING:persistent:1000")
	path = findCcacheFile()
	if path != "" {
		t.Errorf("expected empty for KEYRING type, got %s", path)
	}
}

func TestCcachePrincipalString(t *testing.T) {
	tests := []struct {
		p        ccachePrincipal
		expected string
	}{
		{ccachePrincipal{Realm: "DOMAIN.COM", Components: []string{"user"}}, "user@DOMAIN.COM"},
		{ccachePrincipal{Realm: "DOMAIN.COM", Components: []string{"krbtgt", "DOMAIN.COM"}}, "krbtgt/DOMAIN.COM@DOMAIN.COM"},
		{ccachePrincipal{Realm: "DOMAIN.COM", Components: []string{"HTTP", "web.domain.com"}}, "HTTP/web.domain.com@DOMAIN.COM"},
		{ccachePrincipal{Realm: "", Components: []string{"user"}}, "user"},
	}

	for _, tt := range tests {
		result := tt.p.String()
		if result != tt.expected {
			t.Errorf("got %q, want %q", result, tt.expected)
		}
	}
}

// --- Import action tests ---

func TestKlistImportMissingTicket(t *testing.T) {
	result := klistImport(klistArgs{Action: "import"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "-ticket parameter required") {
		t.Errorf("unexpected output: %s", result.Output)
	}
}

func TestKlistImportBadBase64(t *testing.T) {
	result := klistImport(klistArgs{Action: "import", Ticket: "not!valid!base64!!!"})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Error decoding base64") {
		t.Errorf("unexpected output: %s", result.Output)
	}
}

func TestKlistImportTooShort(t *testing.T) {
	ticket := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02})
	result := klistImport(klistArgs{Action: "import", Ticket: ticket})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "too short") {
		t.Errorf("unexpected output: %s", result.Output)
	}
}

func TestKlistImportUnrecognizedFormat(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00}
	ticket := base64.StdEncoding.EncodeToString(data)
	result := klistImport(klistArgs{Action: "import", Ticket: ticket})
	if result.Status != "error" {
		t.Errorf("expected error, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "unrecognized ticket format") {
		t.Errorf("unexpected output: %s", result.Output)
	}
}

func TestKlistImportKirbiRejectedOnUnix(t *testing.T) {
	// Kirbi starts with 0x76 (ASN.1 APPLICATION 22)
	data := []byte{0x76, 0x03, 0x02, 0x01, 0x05}
	ticket := base64.StdEncoding.EncodeToString(data)
	result := klistImport(klistArgs{Action: "import", Ticket: ticket})
	if result.Status != "error" {
		t.Errorf("expected error for kirbi on Unix, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "kirbi format detected") {
		t.Errorf("unexpected output: %s", result.Output)
	}
	if !strings.Contains(result.Output, "ccache format") {
		t.Errorf("should suggest ccache format: %s", result.Output)
	}
}

func TestKlistImportCcacheSuccess(t *testing.T) {
	ccacheData := buildTestCcache(t)
	ticket := base64.StdEncoding.EncodeToString(ccacheData)

	// Use temp dir for output
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "krb5cc_import_test")

	// Save and restore KRB5CCNAME
	origCC := os.Getenv("KRB5CCNAME")
	defer func() {
		if origCC != "" {
			os.Setenv("KRB5CCNAME", origCC)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistImport(klistArgs{
		Action: "import",
		Ticket: ticket,
		Path:   outPath,
	})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	// Verify file was written
	if _, err := os.Stat(outPath); os.IsNotExist(err) {
		t.Error("ccache file was not created")
	}

	// Verify KRB5CCNAME was set
	if os.Getenv("KRB5CCNAME") != outPath {
		t.Errorf("KRB5CCNAME = %q, want %q", os.Getenv("KRB5CCNAME"), outPath)
	}

	// Verify output contains expected info
	if !strings.Contains(result.Output, "Ticket imported successfully") {
		t.Errorf("missing success message: %s", result.Output)
	}
	if !strings.Contains(result.Output, "user@EXAMPLE.COM") {
		t.Errorf("missing principal in output: %s", result.Output)
	}
	if !strings.Contains(result.Output, "krbtgt/EXAMPLE.COM@EXAMPLE.COM") {
		t.Errorf("missing server in output: %s", result.Output)
	}
	if !strings.Contains(result.Output, "KRB5CCNAME") {
		t.Errorf("missing KRB5CCNAME info: %s", result.Output)
	}
}

func TestKlistImportViaExecute(t *testing.T) {
	ccacheData := buildTestCcache(t)
	ticket := base64.StdEncoding.EncodeToString(ccacheData)

	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "krb5cc_exec_test")

	origCC := os.Getenv("KRB5CCNAME")
	defer func() {
		if origCC != "" {
			os.Setenv("KRB5CCNAME", origCC)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	cmd := &KlistCommand{}
	params := `{"action":"import","ticket":"` + ticket + `","path":"` + outPath + `"}`
	result := cmd.Execute(structs.Task{Params: params})

	if result.Status != "success" {
		t.Fatalf("expected success via Execute, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Ticket imported successfully") {
		t.Errorf("missing success message: %s", result.Output)
	}
}
