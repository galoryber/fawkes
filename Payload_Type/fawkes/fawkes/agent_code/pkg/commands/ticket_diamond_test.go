package commands

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestDiamondMissingRequired(t *testing.T) {
	tests := []struct {
		name string
		args ticketArgs
	}{
		{"missing realm", ticketArgs{Action: "diamond", Username: "user", Key: hex.EncodeToString(make([]byte, 32)), KrbtgtKey: hex.EncodeToString(make([]byte, 32)), Server: "dc01"}},
		{"missing username", ticketArgs{Action: "diamond", Realm: "CORP.LOCAL", Key: hex.EncodeToString(make([]byte, 32)), KrbtgtKey: hex.EncodeToString(make([]byte, 32)), Server: "dc01"}},
		{"missing key", ticketArgs{Action: "diamond", Realm: "CORP.LOCAL", Username: "user", KrbtgtKey: hex.EncodeToString(make([]byte, 32)), Server: "dc01"}},
		{"missing krbtgt_key", ticketArgs{Action: "diamond", Realm: "CORP.LOCAL", Username: "user", Key: hex.EncodeToString(make([]byte, 32)), Server: "dc01"}},
		{"missing server", ticketArgs{Action: "diamond", Realm: "CORP.LOCAL", Username: "user", Key: hex.EncodeToString(make([]byte, 32)), KrbtgtKey: hex.EncodeToString(make([]byte, 32))}},
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

func TestDiamondBadUserKeyHex(t *testing.T) {
	args := ticketArgs{
		Action:    "diamond",
		Realm:     "CORP.LOCAL",
		Username:  "user",
		Key:       "not_hex",
		KrbtgtKey: hex.EncodeToString(make([]byte, 32)),
		Server:    "dc01",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for bad hex, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "user key") {
		t.Fatalf("expected user key error, got %q", result.Output)
	}
}

func TestDiamondBadKrbtgtKeyHex(t *testing.T) {
	args := ticketArgs{
		Action:    "diamond",
		Realm:     "CORP.LOCAL",
		Username:  "user",
		Key:       hex.EncodeToString(make([]byte, 32)),
		KrbtgtKey: "not_hex",
		Server:    "dc01",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for bad krbtgt hex, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "krbtgt key") {
		t.Fatalf("expected krbtgt key error, got %q", result.Output)
	}
}

func TestDiamondWrongUserKeyLength(t *testing.T) {
	args := ticketArgs{
		Action:    "diamond",
		Realm:     "CORP.LOCAL",
		Username:  "user",
		Key:       hex.EncodeToString(make([]byte, 16)), // wrong for aes256
		KeyType:   "aes256",
		KrbtgtKey: hex.EncodeToString(make([]byte, 32)),
		Server:    "dc01",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for wrong key length, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "must be") {
		t.Fatalf("expected key length error, got %q", result.Output)
	}
}

func TestDiamondWrongKrbtgtKeyLength(t *testing.T) {
	args := ticketArgs{
		Action:        "diamond",
		Realm:         "CORP.LOCAL",
		Username:      "user",
		Key:           hex.EncodeToString(make([]byte, 32)),
		KrbtgtKey:     hex.EncodeToString(make([]byte, 8)), // wrong length
		KrbtgtKeyType: "aes256",
		Server:        "dc01",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for wrong krbtgt key length, got %q", result.Status)
	}
}

func TestDiamondDefaultsTargetUser(t *testing.T) {
	// Verify that if target_user is empty, it defaults to username
	// This is tested indirectly — diamond will fail at KDC connect (no real KDC)
	// but we can verify it gets past arg validation
	args := ticketArgs{
		Action:    "diamond",
		Realm:     "CORP.LOCAL",
		Username:  "jsmith",
		Key:       hex.EncodeToString(make([]byte, 32)),
		KrbtgtKey: hex.EncodeToString(make([]byte, 32)),
		Server:    "127.0.0.1:1", // unreachable
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail at KDC connection, not at arg validation
	if result.Status != "error" {
		t.Fatalf("expected error (KDC unreachable), got %q", result.Status)
	}
	if strings.Contains(result.Output, "required") {
		t.Fatalf("should not fail at validation, got %q", result.Output)
	}
	if !strings.Contains(result.Output, "TGT") && !strings.Contains(result.Output, "connect") && !strings.Contains(result.Output, "KDC") {
		t.Fatalf("expected KDC connection error, got %q", result.Output)
	}
}

func TestDiamondRC4KeyType(t *testing.T) {
	// Test RC4 key type validation
	args := ticketArgs{
		Action:        "diamond",
		Realm:         "CORP.LOCAL",
		Username:      "user",
		Key:           hex.EncodeToString(make([]byte, 16)),
		KeyType:       "rc4",
		KrbtgtKey:     hex.EncodeToString(make([]byte, 16)),
		KrbtgtKeyType: "rc4",
		Server:        "127.0.0.1:1",
	}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should pass validation and fail at KDC
	if result.Status != "error" {
		t.Fatalf("expected error (KDC unreachable), got %q", result.Status)
	}
	if strings.Contains(result.Output, "must be") || strings.Contains(result.Output, "required") {
		t.Fatalf("should pass key validation with RC4, got %q", result.Output)
	}
}

func TestDiamondDispatch(t *testing.T) {
	// Verify diamond action is dispatched correctly
	args := ticketArgs{Action: "diamond"}
	b, _ := json.Marshal(args)
	cmd := &TicketCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error, got %q", result.Status)
	}
	// Should fail at diamond validation, not at "Unknown action"
	if strings.Contains(result.Output, "Unknown action") {
		t.Fatalf("diamond action should be recognized, got %q", result.Output)
	}
}
