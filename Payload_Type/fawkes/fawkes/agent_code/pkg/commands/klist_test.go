//go:build !windows
// +build !windows

package commands

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(-1*time.Hour).Unix()))   // authtime
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(-1*time.Hour).Unix()))   // starttime
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(9*time.Hour).Unix()))    // endtime
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

// --- Standalone binary parser tests ---

func TestReadCcacheString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr bool
	}{
		{
			name: "simple string",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 5)
				b = append(b, "hello"...)
				return b
			}(),
			want: "hello",
		},
		{
			name: "empty string",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 0)
				return b
			}(),
			want: "",
		},
		{
			name:    "truncated length",
			data:    []byte{0x00, 0x00},
			wantErr: true,
		},
		{
			name: "truncated data",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 10)
				b = append(b, "short"...)
				return b
			}(),
			wantErr: true,
		},
		{
			name: "string too long",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 100000) // >65535
				return b
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := readCcacheString(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readCcacheString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("readCcacheString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadCcacheOctetString(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantLen int
		wantErr bool
	}{
		{
			name: "valid data",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 4)
				b = append(b, 0xDE, 0xAD, 0xBE, 0xEF)
				return b
			}(),
			wantLen: 4,
		},
		{
			name: "empty data",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 0)
				return b
			}(),
			wantLen: 0,
		},
		{
			name:    "truncated length",
			data:    []byte{0x00},
			wantErr: true,
		},
		{
			name: "too long (>1MB)",
			data: func() []byte {
				var b []byte
				b = binary.BigEndian.AppendUint32(b, 2000000)
				return b
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := bytes.NewReader(tt.data)
			got, err := readCcacheOctetString(r)
			if (err != nil) != tt.wantErr {
				t.Errorf("readCcacheOctetString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.wantLen {
				t.Errorf("readCcacheOctetString() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestSkipCcacheOctetString(t *testing.T) {
	// Valid skip — should consume exactly the right number of bytes
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 8)
	buf = append(buf, make([]byte, 8)...)
	buf = append(buf, 0xFF) // sentinel after the octet string

	r := bytes.NewReader(buf)
	if err := skipCcacheOctetString(r); err != nil {
		t.Fatalf("skipCcacheOctetString() error = %v", err)
	}
	// Should have exactly 1 byte remaining (sentinel)
	if r.Len() != 1 {
		t.Errorf("expected 1 byte remaining, got %d", r.Len())
	}

	// Too long (>1MB)
	var buf2 []byte
	buf2 = binary.BigEndian.AppendUint32(buf2, 2000000)
	r2 := bytes.NewReader(buf2)
	if err := skipCcacheOctetString(r2); err == nil {
		t.Error("expected error for >1MB octet string")
	}
}

func TestReadCcachePrincipalStandalone(t *testing.T) {
	// Build a principal with multiple components: HTTP/web.example.com@EXAMPLE.COM
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 2) // name type (NT-SRV-HST)
	buf = binary.BigEndian.AppendUint32(buf, 2) // 2 components
	buf = appendCcacheString(buf, "EXAMPLE.COM")
	buf = appendCcacheString(buf, "HTTP")
	buf = appendCcacheString(buf, "web.example.com")

	r := bytes.NewReader(buf)
	p, err := readCcachePrincipal(r)
	if err != nil {
		t.Fatalf("readCcachePrincipal() error = %v", err)
	}
	if p.NameType != 2 {
		t.Errorf("NameType = %d, want 2", p.NameType)
	}
	if p.Realm != "EXAMPLE.COM" {
		t.Errorf("Realm = %q, want EXAMPLE.COM", p.Realm)
	}
	if len(p.Components) != 2 {
		t.Fatalf("Components len = %d, want 2", len(p.Components))
	}
	if p.String() != "HTTP/web.example.com@EXAMPLE.COM" {
		t.Errorf("String() = %q, want HTTP/web.example.com@EXAMPLE.COM", p.String())
	}
}

func TestReadCcachePrincipalTruncated(t *testing.T) {
	// Only name type, no component count
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 1)
	r := bytes.NewReader(buf)
	_, err := readCcachePrincipal(r)
	if err == nil {
		t.Error("expected error for truncated principal")
	}
}

// --- v3 ccache format test ---

func TestParseCcacheV3(t *testing.T) {
	var buf []byte

	// Version: 0x0503 (no header)
	buf = binary.BigEndian.AppendUint16(buf, 0x0503)

	// Default principal: admin@CORP.LOCAL
	buf = appendPrincipal(buf, 1, "CORP.LOCAL", []string{"admin"})

	// One credential
	buf = appendPrincipal(buf, 1, "CORP.LOCAL", []string{"admin"})
	buf = appendPrincipal(buf, 2, "CORP.LOCAL", []string{"krbtgt", "CORP.LOCAL"})
	buf = binary.BigEndian.AppendUint16(buf, 23) // RC4-HMAC
	buf = appendOctetString(buf, make([]byte, 16))
	now := time.Now()
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(10*time.Hour).Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(7*24*time.Hour).Unix()))
	buf = append(buf, 0) // is_skey
	buf = binary.BigEndian.AppendUint32(buf, 0x40000000) // forwardable
	buf = binary.BigEndian.AppendUint32(buf, 0) // addresses
	buf = binary.BigEndian.AppendUint32(buf, 0) // authdata
	buf = appendOctetString(buf, []byte{0x61, 0x03}) // ticket
	buf = appendOctetString(buf, nil) // second ticket

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "krb5cc_v3")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}

	principal, creds, err := parseCcache(path)
	if err != nil {
		t.Fatalf("parseCcache v3 failed: %v", err)
	}
	if principal.String() != "admin@CORP.LOCAL" {
		t.Errorf("principal = %q, want admin@CORP.LOCAL", principal.String())
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if creds[0].KeyType != 23 {
		t.Errorf("keytype = %d, want 23 (RC4-HMAC)", creds[0].KeyType)
	}
}

// --- Multiple credentials test ---

func TestParseCcacheMultipleCredentials(t *testing.T) {
	var buf []byte

	buf = binary.BigEndian.AppendUint16(buf, 0x0504)
	buf = binary.BigEndian.AppendUint16(buf, 0) // header len

	// Default principal
	buf = appendPrincipal(buf, 1, "DOMAIN.COM", []string{"user"})

	now := time.Now()

	// Credential 1: TGT
	buf = appendCredential(buf, now,
		ccachePrincipal{NameType: 1, Realm: "DOMAIN.COM", Components: []string{"user"}},
		ccachePrincipal{NameType: 2, Realm: "DOMAIN.COM", Components: []string{"krbtgt", "DOMAIN.COM"}},
		18, 0x40e00000)

	// Credential 2: HTTP service ticket
	buf = appendCredential(buf, now,
		ccachePrincipal{NameType: 1, Realm: "DOMAIN.COM", Components: []string{"user"}},
		ccachePrincipal{NameType: 2, Realm: "DOMAIN.COM", Components: []string{"HTTP", "web.domain.com"}},
		17, 0x40000000)

	// Credential 3: CIFS service ticket
	buf = appendCredential(buf, now,
		ccachePrincipal{NameType: 1, Realm: "DOMAIN.COM", Components: []string{"user"}},
		ccachePrincipal{NameType: 2, Realm: "DOMAIN.COM", Components: []string{"cifs", "fileserver.domain.com"}},
		18, 0x40000000)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "krb5cc_multi")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}

	principal, creds, err := parseCcache(path)
	if err != nil {
		t.Fatalf("parseCcache failed: %v", err)
	}
	if principal.String() != "user@DOMAIN.COM" {
		t.Errorf("principal = %q", principal.String())
	}
	if len(creds) != 3 {
		t.Fatalf("expected 3 credentials, got %d", len(creds))
	}
	if creds[1].Server.String() != "HTTP/web.domain.com@DOMAIN.COM" {
		t.Errorf("cred[1] server = %q", creds[1].Server.String())
	}
	if creds[2].Server.String() != "cifs/fileserver.domain.com@DOMAIN.COM" {
		t.Errorf("cred[2] server = %q", creds[2].Server.String())
	}
}

// appendCredential is a test helper to build a binary credential entry
func appendCredential(buf []byte, now time.Time, client, server ccachePrincipal, etype uint16, flags uint32) []byte {
	buf = appendPrincipal(buf, client.NameType, client.Realm, client.Components)
	buf = appendPrincipal(buf, server.NameType, server.Realm, server.Components)
	buf = binary.BigEndian.AppendUint16(buf, etype)
	buf = appendOctetString(buf, make([]byte, 16)) // key data
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(10*time.Hour).Unix()))
	buf = binary.BigEndian.AppendUint32(buf, uint32(now.Add(7*24*time.Hour).Unix()))
	buf = append(buf, 0)                            // is_skey
	buf = binary.BigEndian.AppendUint32(buf, flags)  // ticket_flags
	buf = binary.BigEndian.AppendUint32(buf, 0)      // addresses
	buf = binary.BigEndian.AppendUint32(buf, 0)      // authdata
	buf = appendOctetString(buf, []byte{0x61, 0x03}) // ticket
	buf = appendOctetString(buf, nil)                 // second ticket
	return buf
}

// --- klistList action tests ---

func TestKlistListWithRealCcache(t *testing.T) {
	ccacheData := buildTestCcache(t)
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_listtest")
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		t.Fatal(err)
	}

	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", ccachePath)
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistList(klistArgs{Action: "list"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	// Output should be JSON array of ticket entries
	var entries []klistTicketEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput: %s", err, result.Output)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Server != "krbtgt/EXAMPLE.COM@EXAMPLE.COM" {
		t.Errorf("server = %q", entries[0].Server)
	}
	if entries[0].Status != "valid" {
		t.Errorf("status = %q, want valid", entries[0].Status)
	}
	if entries[0].Encryption != "AES256-CTS" {
		t.Errorf("encryption = %q, want AES256-CTS", entries[0].Encryption)
	}
}

func TestKlistListWithServerFilter(t *testing.T) {
	// Build ccache with multiple credentials
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, 0x0504)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = appendPrincipal(buf, 1, "DOMAIN.COM", []string{"user"})
	now := time.Now()
	buf = appendCredential(buf, now,
		ccachePrincipal{NameType: 1, Realm: "DOMAIN.COM", Components: []string{"user"}},
		ccachePrincipal{NameType: 2, Realm: "DOMAIN.COM", Components: []string{"krbtgt", "DOMAIN.COM"}},
		18, 0x40e00000)
	buf = appendCredential(buf, now,
		ccachePrincipal{NameType: 1, Realm: "DOMAIN.COM", Components: []string{"user"}},
		ccachePrincipal{NameType: 2, Realm: "DOMAIN.COM", Components: []string{"HTTP", "web.domain.com"}},
		17, 0x40000000)

	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_filter")
	if err := os.WriteFile(ccachePath, buf, 0600); err != nil {
		t.Fatal(err)
	}

	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", ccachePath)
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	// Filter for HTTP — should return only 1 entry
	result := klistList(klistArgs{Action: "list", Server: "HTTP"})
	if result.Status != "success" {
		t.Fatalf("expected success: %s", result.Output)
	}
	var entries []klistTicketEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 filtered entry, got %d", len(entries))
	}
	if !strings.Contains(entries[0].Server, "HTTP") {
		t.Errorf("filtered entry server = %q, expected HTTP", entries[0].Server)
	}
}

func TestKlistListNoFile(t *testing.T) {
	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", "/nonexistent/krb5cc_missing")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistList(klistArgs{Action: "list"})
	if result.Status != "success" {
		t.Errorf("expected success (graceful not-found), got %s", result.Status)
	}
	if !strings.Contains(result.Output, "No ccache file") {
		t.Errorf("expected not-found message, got: %s", result.Output)
	}
}

// --- klistPurge action tests ---

func TestKlistPurgeSuccess(t *testing.T) {
	ccacheData := buildTestCcache(t)
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_purge")
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		t.Fatal(err)
	}

	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", ccachePath)
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistPurge(klistArgs{Action: "purge"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "purged") {
		t.Errorf("expected purge confirmation, got: %s", result.Output)
	}

	// File should be gone
	if _, err := os.Stat(ccachePath); !os.IsNotExist(err) {
		t.Error("ccache file should have been deleted")
	}
}

func TestKlistPurgeNoFile(t *testing.T) {
	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", "/nonexistent/krb5cc_nope")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistPurge(klistArgs{Action: "purge"})
	if result.Status != "success" {
		t.Errorf("expected success (graceful not-found), got %s", result.Status)
	}
}

func TestKlistPurgeNonFileType(t *testing.T) {
	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", "KEYRING:persistent:1000")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistPurge(klistArgs{Action: "purge"})
	if result.Status != "success" {
		t.Errorf("expected success, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "No file-based ccache") {
		t.Errorf("expected non-file message, got: %s", result.Output)
	}
}

// --- klistDump action tests ---

func TestKlistDumpSuccess(t *testing.T) {
	ccacheData := buildTestCcache(t)
	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_dump")
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		t.Fatal(err)
	}

	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", ccachePath)
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistDump(klistArgs{Action: "dump"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Dumped ccache") {
		t.Errorf("expected dump header, got: %s", result.Output)
	}

	// The output should contain base64-encoded ccache data
	// Extract the base64 and verify it decodes back to the original
	lines := strings.Split(result.Output, "\n")
	var b64Lines []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "[") {
			b64Lines = append(b64Lines, trimmed)
		}
	}
	b64 := strings.Join(b64Lines, "")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	if len(decoded) != len(ccacheData) {
		t.Errorf("decoded length %d != original %d", len(decoded), len(ccacheData))
	}
}

func TestKlistDumpNoFile(t *testing.T) {
	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", "/nonexistent/krb5cc_nodump")
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistDump(klistArgs{Action: "dump"})
	if result.Status != "error" {
		t.Errorf("expected error for missing file, got %s", result.Status)
	}
}

// --- Credential with addresses and authdata ---

func TestParseCcacheWithAddressesAndAuthdata(t *testing.T) {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, 0x0504)
	buf = binary.BigEndian.AppendUint16(buf, 0) // header len

	buf = appendPrincipal(buf, 1, "TEST.LOCAL", []string{"svc"})

	// Client and server
	buf = appendPrincipal(buf, 1, "TEST.LOCAL", []string{"svc"})
	buf = appendPrincipal(buf, 2, "TEST.LOCAL", []string{"krbtgt", "TEST.LOCAL"})

	// Keyblock
	buf = binary.BigEndian.AppendUint16(buf, 18)
	buf = appendOctetString(buf, make([]byte, 32))

	// Times
	now := time.Now()
	for i := 0; i < 4; i++ {
		buf = binary.BigEndian.AppendUint32(buf, uint32(now.Unix()))
	}

	buf = append(buf, 1)                            // is_skey = true
	buf = binary.BigEndian.AppendUint32(buf, 0x08000000) // proxy flag

	// 1 address: IPv4 (type 2), 4 bytes
	buf = binary.BigEndian.AppendUint32(buf, 1)      // num_addresses
	buf = binary.BigEndian.AppendUint16(buf, 2)      // addr type = IPv4
	buf = appendOctetString(buf, []byte{10, 0, 0, 1}) // 10.0.0.1

	// 1 authdata entry: AD-IF-RELEVANT (type 1)
	buf = binary.BigEndian.AppendUint32(buf, 1)            // num_authdata
	buf = binary.BigEndian.AppendUint16(buf, 1)            // ad_type
	buf = appendOctetString(buf, []byte{0x30, 0x00})       // minimal authdata

	// Ticket + second ticket
	buf = appendOctetString(buf, []byte{0x61, 0x03, 0x02, 0x01, 0x05})
	buf = appendOctetString(buf, nil)

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "krb5cc_addrs")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}

	principal, creds, err := parseCcache(path)
	if err != nil {
		t.Fatalf("parseCcache failed: %v", err)
	}
	if principal.String() != "svc@TEST.LOCAL" {
		t.Errorf("principal = %q", principal.String())
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 cred, got %d", len(creds))
	}
	if !creds[0].IsSKey {
		t.Error("expected IsSKey = true")
	}
	if creds[0].TicketFlags != 0x08000000 {
		t.Errorf("flags = 0x%08X, want 0x08000000", creds[0].TicketFlags)
	}
}

// --- Expired ticket detection in klistList ---

func TestKlistListExpiredTicket(t *testing.T) {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, 0x0504)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	buf = appendPrincipal(buf, 1, "EXPIRED.COM", []string{"user"})

	// Build credential with end time in the past
	buf = appendPrincipal(buf, 1, "EXPIRED.COM", []string{"user"})
	buf = appendPrincipal(buf, 2, "EXPIRED.COM", []string{"krbtgt", "EXPIRED.COM"})
	buf = binary.BigEndian.AppendUint16(buf, 18)
	buf = appendOctetString(buf, make([]byte, 32))
	past := time.Now().Add(-24 * time.Hour)
	buf = binary.BigEndian.AppendUint32(buf, uint32(past.Add(-48*time.Hour).Unix())) // authtime
	buf = binary.BigEndian.AppendUint32(buf, uint32(past.Add(-48*time.Hour).Unix())) // starttime
	buf = binary.BigEndian.AppendUint32(buf, uint32(past.Unix()))                     // endtime (past)
	buf = binary.BigEndian.AppendUint32(buf, uint32(past.Unix()))                     // renew_till
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, 0x40000000)
	buf = binary.BigEndian.AppendUint32(buf, 0) // addresses
	buf = binary.BigEndian.AppendUint32(buf, 0) // authdata
	buf = appendOctetString(buf, []byte{0x61})
	buf = appendOctetString(buf, nil)

	tmpDir := t.TempDir()
	ccachePath := filepath.Join(tmpDir, "krb5cc_expired")
	if err := os.WriteFile(ccachePath, buf, 0600); err != nil {
		t.Fatal(err)
	}

	orig := os.Getenv("KRB5CCNAME")
	os.Setenv("KRB5CCNAME", ccachePath)
	defer func() {
		if orig != "" {
			os.Setenv("KRB5CCNAME", orig)
		} else {
			os.Unsetenv("KRB5CCNAME")
		}
	}()

	result := klistList(klistArgs{Action: "list"})
	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}

	var entries []klistTicketEntry
	if err := json.Unmarshal([]byte(result.Output), &entries); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Status != "EXPIRED" {
		t.Errorf("status = %q, want EXPIRED", entries[0].Status)
	}
}

// --- v4 header with tags ---

func TestParseCcacheV4WithHeader(t *testing.T) {
	var buf []byte
	buf = binary.BigEndian.AppendUint16(buf, 0x0504)

	// Header with 12 bytes of tag data
	headerData := make([]byte, 12)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(headerData)))
	buf = append(buf, headerData...)

	buf = appendPrincipal(buf, 1, "HEADERED.COM", []string{"admin"})

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "krb5cc_header")
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatal(err)
	}

	principal, creds, err := parseCcache(path)
	if err != nil {
		t.Fatalf("parseCcache with header failed: %v", err)
	}
	if principal.String() != "admin@HEADERED.COM" {
		t.Errorf("principal = %q", principal.String())
	}
	if len(creds) != 0 {
		t.Errorf("expected 0 creds, got %d", len(creds))
	}
}
