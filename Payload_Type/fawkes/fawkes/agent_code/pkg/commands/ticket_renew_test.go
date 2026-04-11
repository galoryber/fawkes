package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestRenewMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args ticketArgs
	}{
		{"missing ticket", ticketArgs{Action: "renew", Realm: "CORP.LOCAL", Server: "dc01"}},
		{"missing realm", ticketArgs{Action: "renew", Ticket: "dGVzdA==", Server: "dc01"}},
		{"missing server", ticketArgs{Action: "renew", Ticket: "dGVzdA==", Realm: "CORP.LOCAL"}},
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

func TestRenewBadBase64(t *testing.T) {
	args := ticketArgs{
		Action: "renew",
		Realm:  "CORP.LOCAL",
		Server: "dc01",
		Ticket: "not valid base64!@#$",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for bad base64, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "base64") {
		t.Fatalf("expected base64 error, got %q", result.Output)
	}
}

func TestRenewBadKirbi(t *testing.T) {
	// Valid base64 but not a kirbi
	args := ticketArgs{
		Action: "renew",
		Realm:  "CORP.LOCAL",
		Server: "dc01",
		Ticket: base64.StdEncoding.EncodeToString([]byte("not a kirbi")),
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for invalid kirbi, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "kirbi") || !strings.Contains(result.Output, "parsing") {
		t.Fatalf("expected kirbi parse error, got %q", result.Output)
	}
}

func TestRenewDispatch(t *testing.T) {
	// Verify renew action is dispatched correctly
	args := ticketArgs{Action: "renew"}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %q", result.Status)
	}
	// Should fail at renew validation, not at "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Fatalf("renew action should be recognized, got %q", result.Output)
	}
}

func TestParseKirbiRoundTrip(t *testing.T) {
	// Use the forge action to create a valid kirbi, then parse it back
	key := hex.EncodeToString(make([]byte, 32))
	args := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "testuser",
		UserRID:   500,
		DomainSID: "S-1-5-21-1234567890-1234567890-1234567890",
		Key:       key,
		KeyType:   "aes256",
		Format:    "kirbi",
	}
	argsJSON, _ := json.Marshal(args)
	result := (&TicketCommand{}).Execute(structs.Task{Params: string(argsJSON)})
	if result.Status != "success" {
		t.Fatalf("forge failed: %s", result.Output)
	}

	// Extract base64 kirbi from output (after "[+] Base64 kirbi ticket:\n")
	lines := strings.Split(result.Output, "\n")
	var b64Line string
	foundMarker := false
	for _, line := range lines {
		if strings.Contains(line, "Base64 kirbi ticket:") {
			foundMarker = true
			continue
		}
		if foundMarker && strings.TrimSpace(line) != "" {
			b64Line = strings.TrimSpace(line)
			break
		}
	}
	if b64Line == "" {
		t.Fatalf("could not find base64 kirbi in output:\n%s", result.Output)
	}

	kirbiBytes, err := base64.StdEncoding.DecodeString(b64Line)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}

	// Parse the kirbi
	parsedTicket, parsedKey, parsedUser, err := ticketParseKirbi(kirbiBytes)
	if err != nil {
		t.Fatalf("ticketParseKirbi failed: %v", err)
	}

	if parsedUser != "testuser" {
		t.Errorf("expected username 'testuser', got %q", parsedUser)
	}

	if parsedKey.KeyType != 18 {
		t.Errorf("expected key type 18, got %d", parsedKey.KeyType)
	}

	if len(parsedKey.KeyValue) != 32 {
		t.Errorf("expected 32-byte key, got %d bytes", len(parsedKey.KeyValue))
	}

	if parsedTicket.Realm != "CORP.LOCAL" {
		t.Errorf("expected realm CORP.LOCAL, got %q", parsedTicket.Realm)
	}

	if parsedTicket.TktVNO != 5 {
		t.Errorf("expected TktVNO 5, got %d", parsedTicket.TktVNO)
	}
}

func TestParseKeyTypeByEtype(t *testing.T) {
	tests := []struct {
		etype    int32
		wantName string
	}{
		{18, "aes256-cts-hmac-sha1-96"},
		{17, "aes128-cts-hmac-sha1-96"},
		{23, "rc4-hmac"},
		{99, "aes256-cts-hmac-sha1-96"}, // unknown falls back
	}

	for _, tt := range tests {
		_, name, errResult := ticketParseKeyTypeByEtype(tt.etype)
		if errResult != nil {
			t.Errorf("etype %d: unexpected error", tt.etype)
		}
		if name != tt.wantName {
			t.Errorf("etype %d: expected %q, got %q", tt.etype, tt.wantName, name)
		}
	}
}

func TestRenewWithValidKirbi(t *testing.T) {
	// Use forge to create a valid kirbi, then try to renew — should fail at KDC connect
	key := hex.EncodeToString(make([]byte, 32))
	forgeArgs := ticketArgs{
		Action:    "forge",
		Realm:     "CORP.LOCAL",
		Username:  "admin",
		DomainSID: "S-1-5-21-1-2-3",
		Key:       key,
		Format:    "kirbi",
	}
	forgeJSON, _ := json.Marshal(forgeArgs)
	forgeResult := (&TicketCommand{}).Execute(structs.Task{Params: string(forgeJSON)})
	if forgeResult.Status != "success" {
		t.Fatalf("forge failed: %s", forgeResult.Output)
	}

	// Extract base64 from forge output
	lines := strings.Split(forgeResult.Output, "\n")
	var b64 string
	foundMarker := false
	for _, line := range lines {
		if strings.Contains(line, "Base64 kirbi ticket:") {
			foundMarker = true
			continue
		}
		if foundMarker && strings.TrimSpace(line) != "" {
			b64 = strings.TrimSpace(line)
			break
		}
	}
	if b64 == "" {
		t.Fatalf("could not find base64 kirbi in forge output")
	}

	args := ticketArgs{
		Action: "renew",
		Realm:  "CORP.LOCAL",
		Server: "127.0.0.1:1", // unreachable
		Ticket: b64,
	}
	argsJSON, _ := json.Marshal(args)
	result := (&TicketCommand{}).Execute(structs.Task{Params: string(argsJSON)})

	if result.Status != "error" {
		t.Fatalf("expected error (KDC unreachable), got %q", result.Status)
	}
	// Should fail at KDC connection, not at kirbi parsing
	if strings.Contains(result.Output, "kirbi") && strings.Contains(result.Output, "parsing") {
		t.Fatalf("should not fail at kirbi parsing, got %q", result.Output)
	}
}
