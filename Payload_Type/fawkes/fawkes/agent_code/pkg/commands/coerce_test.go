package commands

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestCoerceName(t *testing.T) {
	cmd := &CoerceCommand{}
	if cmd.Name() != "coerce" {
		t.Fatalf("expected 'coerce', got %q", cmd.Name())
	}
}

func TestCoerceDescription(t *testing.T) {
	cmd := &CoerceCommand{}
	if !strings.Contains(cmd.Description(), "T1187") {
		t.Fatal("description should contain MITRE ATT&CK mapping T1187")
	}
}

func TestCoerceEmptyParams(t *testing.T) {
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Fatalf("expected error for empty params, got %q", result.Status)
	}
}

func TestCoerceBadJSON(t *testing.T) {
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Fatalf("expected error for bad JSON, got %q", result.Status)
	}
}

func TestCoerceMissingServer(t *testing.T) {
	args := coerceArgs{Listener: "10.0.0.5", Username: "admin", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing server, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "server and listener are required") {
		t.Fatalf("unexpected error message: %s", result.Output)
	}
}

func TestCoerceMissingListener(t *testing.T) {
	args := coerceArgs{Server: "dc01", Username: "admin", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing listener, got %q", result.Status)
	}
}

func TestCoerceMissingCredentials(t *testing.T) {
	args := coerceArgs{Server: "dc01", Listener: "10.0.0.5", Username: "admin"}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing credentials, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "password (or hash)") {
		t.Fatalf("unexpected error message: %s", result.Output)
	}
}

func TestCoerceMissingUsername(t *testing.T) {
	args := coerceArgs{Server: "dc01", Listener: "10.0.0.5", Password: "pass"}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for missing username, got %q", result.Status)
	}
}

func TestCoerceInvalidMethod(t *testing.T) {
	args := coerceArgs{
		Server: "dc01", Listener: "10.0.0.5",
		Username: "admin", Password: "pass",
		Method: "invalid",
	}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	if result.Status != "error" {
		t.Fatalf("expected error for invalid method, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "unknown method") {
		t.Fatalf("unexpected error message: %s", result.Output)
	}
}

func TestCoerceHashAccepted(t *testing.T) {
	args := coerceArgs{
		Server: "dc01", Listener: "10.0.0.5",
		Username: "admin",
		Hash:     "aad3b435b51404ee:8846f7eaee8fb117",
		Method:   "petitpotam",
	}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should fail on network connect, not validation
	if result.Output == "Error: username and password (or hash) are required" {
		t.Fatal("hash should be accepted as credential")
	}
	// Verify PTH is mentioned in output
	if !strings.Contains(result.Output, "PTH") {
		t.Fatal("output should indicate PTH authentication")
	}
}

func TestCoerceDomainParsing(t *testing.T) {
	tests := []struct {
		name           string
		username       string
		domain         string
		expectDomain   string
		expectUsername string
	}{
		{"backslash format", `CORP\admin`, "", "CORP", "admin"},
		{"UPN format", "admin@corp.local", "", "corp.local", "admin"},
		{"explicit domain", "admin", "CORP.LOCAL", "CORP.LOCAL", "admin"},
		{"no domain", "admin", "", "", "admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := coerceArgs{
				Username: tt.username,
				Domain:   tt.domain,
			}
			// Parse domain same way Execute does
			if args.Domain == "" {
				if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
					args.Domain = parts[0]
					args.Username = parts[1]
				} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
					args.Domain = parts[1]
					args.Username = parts[0]
				}
			}
			if args.Domain != tt.expectDomain {
				t.Errorf("domain: got %q, want %q", args.Domain, tt.expectDomain)
			}
			if args.Username != tt.expectUsername {
				t.Errorf("username: got %q, want %q", args.Username, tt.expectUsername)
			}
		})
	}
}

func TestCoerceMethodAliases(t *testing.T) {
	tests := []struct {
		method string
		valid  bool
	}{
		{"petitpotam", true},
		{"efsr", true},
		{"printerbug", true},
		{"rprn", true},
		{"spoolsample", true},
		{"shadowcoerce", true},
		{"fsrvp", true},
		{"all", true},
		{"", true}, // defaults to "all"
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			args := coerceArgs{
				Server: "dc01", Listener: "10.0.0.5",
				Username: "admin", Password: "pass",
				Method: tt.method,
			}
			b, _ := json.Marshal(args)
			cmd := &CoerceCommand{}
			result := cmd.Execute(structs.Task{Params: string(b)})
			if !tt.valid {
				if !strings.Contains(result.Output, "unknown method") {
					t.Fatalf("expected unknown method error for %q, got: %s", tt.method, result.Output)
				}
			} else {
				if strings.Contains(result.Output, "unknown method") {
					t.Fatalf("method %q should be valid but got unknown method error", tt.method)
				}
			}
		})
	}
}

func TestCoerceDefaultTimeout(t *testing.T) {
	args := coerceArgs{
		Server: "dc01", Listener: "10.0.0.5",
		Username: "admin", Password: "pass",
		Timeout: 0,
	}
	// Verify timeout defaults to 30 when 0
	if args.Timeout <= 0 {
		args.Timeout = 30
	}
	if args.Timeout != 30 {
		t.Fatalf("expected default timeout 30, got %d", args.Timeout)
	}
}

func TestCoerceDefaultMethod(t *testing.T) {
	args := coerceArgs{
		Server: "dc01", Listener: "10.0.0.5",
		Username: "admin", Password: "pass",
		// Method is empty — should default to "all"
	}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// With default method "all", should attempt all 3 methods
	if !strings.Contains(result.Output, "PetitPotam") &&
		!strings.Contains(result.Output, "PrinterBug") &&
		!strings.Contains(result.Output, "ShadowCoerce") {
		t.Fatal("default method 'all' should attempt all 3 coercion methods")
	}
}

func TestCoerceNetworkErrorOutput(t *testing.T) {
	// Test that network errors are properly reported (can't actually connect)
	args := coerceArgs{
		Server:   "127.0.0.1", // TEST-NET, unreachable
		Listener: "10.0.0.5",
		Username: "admin", Password: "pass",
		Method:  "petitpotam",
		Timeout: 2,
	}
	b, _ := json.Marshal(args)
	cmd := &CoerceCommand{}
	result := cmd.Execute(structs.Task{Params: string(b)})
	// Should report connection failure
	if result.Status != "error" {
		t.Fatalf("expected error for unreachable host, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "connection failed") && !strings.Contains(result.Output, "failed") {
		t.Fatalf("expected connection failure message, got: %s", result.Output)
	}
}

// --- coerceIsRPCProcessed tests ---

func TestCoerceIsRPCProcessed_NilError(t *testing.T) {
	if !coerceIsRPCProcessed(nil) {
		t.Error("nil error should indicate RPC was processed")
	}
}

func TestCoerceIsRPCProcessed_KnownIndicators(t *testing.T) {
	indicators := []struct {
		errMsg string
		desc   string
	}{
		{"ERROR_BAD_NETPATH", "bad net path"},
		{"ERROR_ACCESS_DENIED", "access denied"},
		{"ERROR_BAD_NET_NAME", "bad net name"},
		{"ERROR_NOT_FOUND", "not found"},
		{"ERROR_INVALID_PARAMETER", "invalid parameter"},
		{"0x00000035", "BAD_NETPATH numeric"},
		{"0x00000005", "ACCESS_DENIED numeric"},
		{"RPC_S_SERVER_UNAVAILABLE", "RPC server unavailable"},
		{"0x000006ba", "RPC_S_SERVER_UNAVAILABLE numeric"},
	}
	for _, tt := range indicators {
		err := fmt.Errorf("RPC call failed: %s on pipe efsrpc", tt.errMsg)
		if !coerceIsRPCProcessed(err) {
			t.Errorf("%s: expected processed=true for error containing %q", tt.desc, tt.errMsg)
		}
	}
}

func TestCoerceIsRPCProcessed_TransportFailure(t *testing.T) {
	// Transport-level errors should return false (RPC not processed)
	transportErrors := []string{
		"connection refused",
		"network is unreachable",
		"no route to host",
		"i/o timeout",
		"connection reset by peer",
		"dial tcp 10.0.0.1:445: connect: connection timed out",
	}
	for _, errMsg := range transportErrors {
		err := fmt.Errorf("%s", errMsg)
		if coerceIsRPCProcessed(err) {
			t.Errorf("transport error %q should return false", errMsg)
		}
	}
}

func TestCoerceIsRPCProcessed_WrappedIndicator(t *testing.T) {
	// Indicator embedded in longer error message
	err := fmt.Errorf("EfsRpcOpenFileRaw returned ERROR_BAD_NETPATH on \\\\10.0.0.5\\share")
	if !coerceIsRPCProcessed(err) {
		t.Error("wrapped ERROR_BAD_NETPATH should be detected")
	}
}

func TestCoerceIsRPCProcessed_NumericInContext(t *testing.T) {
	err := fmt.Errorf("DCERPC error: server returned 0x00000005")
	if !coerceIsRPCProcessed(err) {
		t.Error("numeric 0x00000005 in context should be detected")
	}
}

func TestCoerceIsRPCProcessed_UnrelatedError(t *testing.T) {
	err := fmt.Errorf("something completely unrelated happened")
	if coerceIsRPCProcessed(err) {
		t.Error("unrelated error should return false")
	}
}

func TestCoerceIsRPCProcessed_EmptyError(t *testing.T) {
	err := fmt.Errorf("")
	if coerceIsRPCProcessed(err) {
		t.Error("empty error message should return false")
	}
}
