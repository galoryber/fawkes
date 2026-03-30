//go:build darwin

package commands

import (
	"encoding/json"
	"testing"
	"time"
)

func TestKeychainCommandName(t *testing.T) {
	assertCommandName(t, &KeychainCommand{}, "keychain")
}

func TestKeychainCommandDescription(t *testing.T) {
	assertCommandHasDescription(t, &KeychainCommand{})
}

func TestKeychainEmptyParams(t *testing.T) {
	cmd := &KeychainCommand{}
	result := cmd.Execute(mockTask("keychain", ""))
	assertError(t, result)
}

func TestKeychainInvalidJSON(t *testing.T) {
	cmd := &KeychainCommand{}
	result := cmd.Execute(mockTask("keychain", "not json"))
	assertError(t, result)
}

func TestKeychainUnknownAction(t *testing.T) {
	cmd := &KeychainCommand{}
	params, _ := json.Marshal(keychainArgs{Action: "invalid"})
	result := cmd.Execute(mockTask("keychain", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "Unknown action")
}

func TestKeychainFindPasswordMissingFilter(t *testing.T) {
	cmd := &KeychainCommand{}
	params, _ := json.Marshal(keychainArgs{Action: "find-password"})
	result := cmd.Execute(mockTask("keychain", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "specify at least one filter")
}

func TestKeychainFindInternetMissingFilter(t *testing.T) {
	cmd := &KeychainCommand{}
	params, _ := json.Marshal(keychainArgs{Action: "find-internet"})
	result := cmd.Execute(mockTask("keychain", string(params)))
	assertError(t, result)
	assertOutputContains(t, result, "specify at least one filter")
}

func TestKeychainArgsUnmarshal(t *testing.T) {
	var args keychainArgs
	data := `{"action":"find-password","service":"Wi-Fi","account":"admin","label":"test"}`
	if err := json.Unmarshal([]byte(data), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Action != "find-password" {
		t.Errorf("Action = %q, want find-password", args.Action)
	}
	if args.Service != "Wi-Fi" {
		t.Errorf("Service = %q, want Wi-Fi", args.Service)
	}
	if args.Account != "admin" {
		t.Errorf("Account = %q, want admin", args.Account)
	}
}

func TestKeychainListAction(t *testing.T) {
	cmd := &KeychainCommand{}
	params, _ := json.Marshal(keychainArgs{Action: "list"})
	result := cmd.Execute(mockTask("keychain", string(params)))
	// On macOS CI/dev machine, list should succeed
	assertSuccess(t, result)
	assertOutputContains(t, result, "macOS Keychains")
}

func TestKeychainTimeoutConstant(t *testing.T) {
	if keychainTimeout != 30*time.Second {
		t.Errorf("keychainTimeout = %v, want 30s", keychainTimeout)
	}
}
