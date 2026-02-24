package commands

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fawkes/pkg/structs"

	"github.com/jcmturner/gokrb5/v8/types"
)

func TestTicketName(t *testing.T) {
	cmd := &TicketCommand{}
	if cmd.Name() != "ticket" {
		t.Fatalf("expected 'ticket', got %q", cmd.Name())
	}
}

func TestTicketEmptyParams(t *testing.T) {
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error for empty params, got %q", result.Status)
	}
}

func TestTicketBadJSON(t *testing.T) {
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Fatalf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestTicketUnknownAction(t *testing.T) {
	args := ticketArgs{Action: "list"}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for unknown action, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Fatalf("expected 'Unknown action' in output, got %q", result.Output)
	}
}

func TestTicketMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args ticketArgs
	}{
		{"missing realm", ticketArgs{Action: "forge", Username: "admin", Key: "aa" + strings.Repeat("bb", 31), DomainSID: "S-1-5-21-1-2-3"}},
		{"missing username", ticketArgs{Action: "forge", Realm: "CORP.LOCAL", Key: "aa" + strings.Repeat("bb", 31), DomainSID: "S-1-5-21-1-2-3"}},
		{"missing key", ticketArgs{Action: "forge", Realm: "CORP.LOCAL", Username: "admin", DomainSID: "S-1-5-21-1-2-3"}},
		{"missing domain_sid", ticketArgs{Action: "forge", Realm: "CORP.LOCAL", Username: "admin", Key: "aa" + strings.Repeat("bb", 31)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.args)
			cmd := &TicketCommand{}
			result := cmd.Execute(structs.Task{Params: string(b)})
			if result.Status != "error" {
				t.Fatalf("expected error, got %q: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "required") {
				t.Fatalf("expected 'required' in output, got %q", result.Output)
			}
		})
	}
}

func TestTicketBadKeyHex(t *testing.T) {
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "Administrator",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       "not_hex",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for bad hex key, got %q", result.Status)
	}
}

func TestTicketWrongKeyLength(t *testing.T) {
	tests := []struct {
		name    string
		keyType string
		keyLen  int // bytes
	}{
		{"aes256 too short", "aes256", 16},
		{"aes256 too long", "aes256", 64},
		{"aes128 too short", "aes128", 8},
		{"aes128 too long", "aes128", 32},
		{"rc4 too short", "rc4", 8},
		{"rc4 too long", "rc4", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := hex.EncodeToString(make([]byte, tt.keyLen))
			args := ticketArgs{
				Action:    "forge",
				Realm:     "CORP.LOCAL",
				Username:  "Administrator",
				DomainSID: "S-1-5-21-1-2-3",
				Key:       key,
				KeyType:   tt.keyType,
			}
			b, _ := json.Marshal(args)
			cmd := &TicketCommand{}
			result := cmd.Execute(structs.Task{Params: string(b)})
			if result.Status != "error" {
				t.Fatalf("expected error for wrong key length, got %q: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, "must be") {
				t.Fatalf("expected key length error, got %q", result.Output)
			}
		})
	}
}

func TestTicketUnknownKeyType(t *testing.T) {
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "Administrator",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       hex.EncodeToString(make([]byte, 32)),
		KeyType:   "des",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for unknown key type, got %q", result.Status)
	}
}

func TestTicketGoldenKirbi(t *testing.T) {
	// Forge a Golden Ticket with AES256 in kirbi format
	key := hex.EncodeToString(make([]byte, 32)) // 32 zero bytes
	args := ticketArgs{
		Action:    "forge",
		Realm:     "NORTH.SEVENKINGDOMS.LOCAL",
		Username:  "Administrator",
		UserRID:   500,
		DomainSID: "S-1-5-21-505720233-3541239624-1745104043",
		Key:       key,
		KeyType:   "aes256",
		Format:    "kirbi",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Verify output contains expected fields
	checks := []string{
		"Golden Ticket (TGT) forged successfully",
		"Administrator@NORTH.SEVENKINGDOMS.LOCAL",
		"RID: 500",
		"S-1-5-21-505720233-3541239624-1745104043",
		"aes256",
		"kirbi",
		"Base64 kirbi ticket:",
		"Rubeus.exe ptt",
	}
	for _, c := range checks {
		if !strings.Contains(result.Output, c) {
			t.Errorf("output missing %q", c)
		}
	}

	// Extract the base64 blob (line after "[+] Base64")
	lines := strings.Split(result.Output, "\n")
	var b64Line string
	for i, line := range lines {
		if strings.Contains(line, "Base64") && strings.Contains(line, "ticket:") {
			if i+1 < len(lines) {
				b64Line = strings.TrimSpace(lines[i+1])
			}
			break
		}
	}
	if b64Line == "" {
		t.Fatalf("no base64 blob found in output:\n%s", result.Output)
	}

	kirbiBytes, err := base64.StdEncoding.DecodeString(b64Line)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}

	// KRB-CRED is APPLICATION 22 → tag byte should be 0x76 (0x60 | 22)
	if len(kirbiBytes) < 2 {
		t.Fatal("kirbi too short")
	}
	if kirbiBytes[0] != 0x76 {
		t.Errorf("expected kirbi tag 0x76 (APPLICATION 22), got 0x%02x", kirbiBytes[0])
	}
}

func TestTicketGoldenCCache(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "aes256",
		Format:    "ccache",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "Golden Ticket (TGT) forged successfully") {
		t.Error("output missing Golden Ticket confirmation")
	}
	if !strings.Contains(result.Output, "ccache") {
		t.Error("output missing ccache format")
	}
	if !strings.Contains(result.Output, "KRB5CCNAME") {
		t.Error("output missing KRB5CCNAME usage hint")
	}

	// Extract the base64 blob (line after "[+] Base64")
	lines := strings.Split(result.Output, "\n")
	var b64Line string
	for i, line := range lines {
		if strings.Contains(line, "Base64") && strings.Contains(line, "ticket:") {
			if i+1 < len(lines) {
				b64Line = strings.TrimSpace(lines[i+1])
			}
			break
		}
	}
	if b64Line == "" {
		t.Fatalf("no base64 blob found in output:\n%s", result.Output)
	}

	ccacheBytes, err := base64.StdEncoding.DecodeString(b64Line)
	if err != nil {
		t.Fatalf("invalid base64: %v", err)
	}

	// CCache version 4: starts with 0x05, 0x04
	if len(ccacheBytes) < 4 {
		t.Fatal("ccache too short")
	}
	if ccacheBytes[0] != 0x05 || ccacheBytes[1] != 0x04 {
		t.Errorf("expected ccache version 0x0504, got 0x%02x%02x", ccacheBytes[0], ccacheBytes[1])
	}

	// Header length at bytes 2-3
	headerLen := binary.BigEndian.Uint16(ccacheBytes[2:4])
	if headerLen != 12 {
		t.Errorf("expected header length 12, got %d", headerLen)
	}
}

func TestTicketSilverKirbi(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "aes256",
		Format:    "kirbi",
		SPN:       "cifs/dc01.corp.local",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	if !strings.Contains(result.Output, "Silver Ticket (TGS: cifs/dc01.corp.local)") {
		t.Error("output missing Silver Ticket confirmation")
	}
}

func TestTicketRC4(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 16)) // 16 zero bytes for RC4
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "rc4",
		Format:    "kirbi",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "rc4") {
		t.Error("output missing rc4 key type")
	}
}

func TestTicketAES128(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 16))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "aes128",
		Format:    "kirbi",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "aes128") {
		t.Error("output missing aes128 key type")
	}
}

func TestTicketNTLMAlias(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 16))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "ntlm", // alias for rc4
		Format:    "kirbi",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
}

func TestTicketUnknownFormat(t *testing.T) {
	key := hex.EncodeToString(make([]byte, 32))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		KeyType:   "aes256",
		Format:    "base64",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for unknown format, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown format") {
		t.Fatalf("expected 'unknown format' in output, got %q", result.Output)
	}
}

func TestTicketDefaults(t *testing.T) {
	// Test that defaults are applied correctly
	key := hex.EncodeToString(make([]byte, 32))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		// All defaults: key_type=aes256, format=kirbi, user_rid=500, kvno=2, lifetime=24
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "success" {
		t.Fatalf("expected success with defaults, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "RID: 500") {
		t.Error("default RID 500 not applied")
	}
	if !strings.Contains(result.Output, "KVNO:      2") {
		t.Error("default KVNO 2 not applied")
	}
	if !strings.Contains(result.Output, "kirbi") {
		t.Error("default kirbi format not applied")
	}
}

// --- Request action (Overpass-the-Hash) tests ---

func TestTicketRequestMissingParams(t *testing.T) {
	tests := []struct {
		name   string
		args   map[string]interface{}
		expect string
	}{
		{"missing all", map[string]interface{}{"action": "request"}, "realm, username, key, and server"},
		{"missing server", map[string]interface{}{"action": "request", "realm": "TEST.LOCAL", "username": "admin", "key": strings.Repeat("aa", 32)}, "server"},
		{"missing key", map[string]interface{}{"action": "request", "realm": "TEST.LOCAL", "username": "admin", "server": "dc01"}, "key"},
		{"missing realm", map[string]interface{}{"action": "request", "username": "admin", "key": strings.Repeat("aa", 32), "server": "dc01"}, "realm"},
		{"missing username", map[string]interface{}{"action": "request", "realm": "TEST.LOCAL", "key": strings.Repeat("aa", 32), "server": "dc01"}, "username"},
	}

	cmd := &TicketCommand{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.args)
			result := cmd.Execute(structs.Task{Params: string(b)})
			if result.Status != "error" {
				t.Errorf("expected error, got %s", result.Status)
			}
			if !strings.Contains(result.Output, tt.expect) {
				t.Errorf("expected output to contain %q, got: %s", tt.expect, result.Output)
			}
		})
	}
}

func TestTicketRequestBadKey(t *testing.T) {
	cmd := &TicketCommand{}

	// Invalid hex
	b, _ := json.Marshal(map[string]interface{}{
		"action": "request", "realm": "TEST.LOCAL", "username": "admin",
		"key": "not_hex", "server": "dc01",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "Error decoding key") {
		t.Errorf("expected key decode error, got: %s", result.Output)
	}

	// Wrong length for AES256
	b, _ = json.Marshal(map[string]interface{}{
		"action": "request", "realm": "TEST.LOCAL", "username": "admin",
		"key": strings.Repeat("aa", 16), "key_type": "aes256", "server": "dc01",
	})
	result = cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "32 bytes") {
		t.Errorf("expected key length error, got: %s", result.Output)
	}
}

func TestTicketRequestBadKeyType(t *testing.T) {
	cmd := &TicketCommand{}
	b, _ := json.Marshal(map[string]interface{}{
		"action": "request", "realm": "TEST.LOCAL", "username": "admin",
		"key": strings.Repeat("aa", 32), "key_type": "des", "server": "dc01",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "unknown key_type") {
		t.Errorf("expected key_type error, got: %s", result.Output)
	}
}

func TestTicketRequestConnectionRefused(t *testing.T) {
	cmd := &TicketCommand{}
	// Use localhost with a port that's almost certainly not listening
	b, _ := json.Marshal(map[string]interface{}{
		"action": "request", "realm": "TEST.LOCAL", "username": "admin",
		"key": strings.Repeat("aa", 32), "server": "127.0.0.1:19999",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Errorf("expected error for connection refused, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Error connecting to KDC") && !strings.Contains(result.Output, "Error") {
		t.Errorf("expected connection error, got: %s", result.Output)
	}
}

func TestTicketKrbErrorMsg(t *testing.T) {
	tests := []struct {
		code   int32
		expect string
	}{
		{6, "PRINCIPAL_UNKNOWN"},
		{18, "CLIENT_REVOKED"},
		{24, "PREAUTH_FAILED"},
		{25, "PREAUTH_REQUIRED"},
		{31, "SKEW"},
		{999, "error code 999"},
	}

	for _, tt := range tests {
		msg := ticketKrbErrorMsg(tt.code)
		if !strings.Contains(msg, tt.expect) {
			t.Errorf("ticketKrbErrorMsg(%d) = %q, want to contain %q", tt.code, msg, tt.expect)
		}
	}
}

func TestTicketRequestViaExecuteSwitch(t *testing.T) {
	// Verify the "request" action is recognized (not "unknown")
	cmd := &TicketCommand{}
	b, _ := json.Marshal(map[string]interface{}{"action": "request"})
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail with missing params, NOT "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("request action not recognized in switch")
	}
}

// --- S4U (constrained delegation) tests ---

func TestTicketS4UViaExecuteSwitch(t *testing.T) {
	// Verify the "s4u" action is recognized (not "unknown")
	cmd := &TicketCommand{}
	b, _ := json.Marshal(map[string]interface{}{"action": "s4u"})
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail with missing params, NOT "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Error("s4u action not recognized in switch")
	}
	if result.Status != "error" {
		t.Error("expected error for missing s4u params")
	}
}

func TestTicketS4UMissingParams(t *testing.T) {
	key32 := strings.Repeat("aa", 32)
	tests := []struct {
		name   string
		args   map[string]interface{}
		expect string
	}{
		{"missing all", map[string]interface{}{"action": "s4u"}, "required"},
		{"missing impersonate", map[string]interface{}{
			"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
			"key": key32, "server": "dc01", "spn": "cifs/srv01",
		}, "impersonate"},
		{"missing spn", map[string]interface{}{
			"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
			"key": key32, "server": "dc01", "impersonate": "admin",
		}, "spn"},
		{"missing server", map[string]interface{}{
			"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
			"key": key32, "impersonate": "admin", "spn": "cifs/srv01",
		}, "server"},
		{"missing key", map[string]interface{}{
			"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
			"server": "dc01", "impersonate": "admin", "spn": "cifs/srv01",
		}, "key"},
	}

	cmd := &TicketCommand{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := json.Marshal(tt.args)
			result := cmd.Execute(structs.Task{Params: string(b)})
			if result.Status != "error" {
				t.Errorf("expected error, got %s: %s", result.Status, result.Output)
			}
			if !strings.Contains(result.Output, tt.expect) {
				t.Errorf("expected output to contain %q, got: %s", tt.expect, result.Output)
			}
		})
	}
}

func TestTicketS4UBadKey(t *testing.T) {
	cmd := &TicketCommand{}

	// Invalid hex
	b, _ := json.Marshal(map[string]interface{}{
		"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
		"key": "not_hex", "server": "dc01", "impersonate": "admin", "spn": "cifs/srv01",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "Error decoding key") {
		t.Errorf("expected key decode error, got: %s", result.Output)
	}

	// Wrong length for AES256
	b, _ = json.Marshal(map[string]interface{}{
		"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
		"key": strings.Repeat("aa", 16), "key_type": "aes256", "server": "dc01",
		"impersonate": "admin", "spn": "cifs/srv01",
	})
	result = cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "32 bytes") {
		t.Errorf("expected key length error, got: %s", result.Output)
	}
}

func TestTicketS4UBadKeyType(t *testing.T) {
	cmd := &TicketCommand{}
	b, _ := json.Marshal(map[string]interface{}{
		"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
		"key": strings.Repeat("aa", 32), "key_type": "des", "server": "dc01",
		"impersonate": "admin", "spn": "cifs/srv01",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" || !strings.Contains(result.Output, "unknown key_type") {
		t.Errorf("expected key_type error, got: %s", result.Output)
	}
}

func TestTicketS4UConnectionRefused(t *testing.T) {
	cmd := &TicketCommand{}
	// Use localhost with a port that's almost certainly not listening
	b, _ := json.Marshal(map[string]interface{}{
		"action": "s4u", "realm": "TEST.LOCAL", "username": "sqlsvc",
		"key": strings.Repeat("aa", 32), "server": "127.0.0.1:19999",
		"impersonate": "admin", "spn": "cifs/srv01",
	})
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Errorf("expected error for connection refused, got: %s — %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Error obtaining TGT") && !strings.Contains(result.Output, "Error") {
		t.Errorf("expected connection error, got: %s", result.Output)
	}
}

func TestTicketParseKeyType(t *testing.T) {
	tests := []struct {
		keyType  string
		keyLen   int
		wantID   int32
		wantName string
		wantErr  bool
	}{
		{"aes256", 32, 18, "aes256-cts-hmac-sha1-96", false},
		{"aes128", 16, 17, "aes128-cts-hmac-sha1-96", false},
		{"rc4", 16, 23, "rc4-hmac", false},
		{"ntlm", 16, 23, "rc4-hmac", false},
		{"aes256", 16, 0, "", true},  // wrong length
		{"aes128", 32, 0, "", true},  // wrong length
		{"rc4", 32, 0, "", true},     // wrong length
		{"des", 8, 0, "", true},      // unknown type
	}

	for _, tt := range tests {
		t.Run(tt.keyType+"_"+string(rune('0'+tt.keyLen)), func(t *testing.T) {
			keyBytes := make([]byte, tt.keyLen)
			id, name, errResult := ticketParseKeyType(tt.keyType, keyBytes)
			if tt.wantErr {
				if errResult == nil {
					t.Error("expected error result, got nil")
				}
			} else {
				if errResult != nil {
					t.Errorf("unexpected error: %s", errResult.Output)
				}
				if id != tt.wantID {
					t.Errorf("etype ID: got %d, want %d", id, tt.wantID)
				}
				if name != tt.wantName {
					t.Errorf("config name: got %q, want %q", name, tt.wantName)
				}
			}
		})
	}
}

func TestTicketBuildPAForUser(t *testing.T) {
	// Test PA-FOR-USER construction with a known session key
	sessionKey := types.EncryptionKey{
		KeyType:  23, // RC4
		KeyValue: make([]byte, 16),
	}
	paData, err := ticketBuildPAForUser("Administrator", "CORP.LOCAL", sessionKey)
	if err != nil {
		t.Fatalf("ticketBuildPAForUser failed: %v", err)
	}
	if paData.PADataType != 129 {
		t.Errorf("expected PA_FOR_USER type 129, got %d", paData.PADataType)
	}
	if len(paData.PADataValue) == 0 {
		t.Error("PA-FOR-USER value is empty")
	}
}

func TestTicketS4UFormatOutput(t *testing.T) {
	selfKey := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	proxyKey := types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}
	args := ticketArgs{
		Action:      "s4u",
		Realm:       "CORP.LOCAL",
		Username:    "sqlsvc",
		Impersonate: "Administrator",
		SPN:         "cifs/fileserver.corp.local",
		Server:      "dc01.corp.local",
		KeyType:     "aes256",
		Format:      "kirbi",
	}
	output := ticketS4UFormatOutput(args, "CORP.LOCAL", selfKey, proxyKey, now(), now(), "dGVzdA==")

	checks := []string{
		"S4U delegation attack completed",
		"sqlsvc@CORP.LOCAL",
		"Administrator@CORP.LOCAL",
		"cifs/fileserver.corp.local",
		"dc01.corp.local",
		"aes256",
		"kirbi",
		"klist -action import",
	}
	for _, c := range checks {
		if !strings.Contains(output, c) {
			t.Errorf("output missing %q", c)
		}
	}
}

func now() time.Time {
	return time.Now().UTC()
}
