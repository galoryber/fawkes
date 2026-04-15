package agentfunctions

import (
	"testing"
)

func TestDetectCoercionSuccess_PetitPotam(t *testing.T) {
	input := "[+] PetitPotam: Authentication triggered successfully!"
	method, ok := detectCoercionSuccess(input)
	if !ok {
		t.Fatal("expected success")
	}
	if method != "petitpotam" {
		t.Errorf("expected petitpotam, got %q", method)
	}
}

func TestDetectCoercionSuccess_PrinterBug(t *testing.T) {
	input := "[+] MS-RPRN PrinterBug: Success — target authenticated to listener"
	method, ok := detectCoercionSuccess(input)
	if !ok {
		t.Fatal("expected success")
	}
	if method != "printerbug" {
		t.Errorf("expected printerbug, got %q", method)
	}
}

func TestDetectCoercionSuccess_ShadowCoerce(t *testing.T) {
	input := "[+] MS-FSRVP ShadowCoerce triggered on DC01"
	method, ok := detectCoercionSuccess(input)
	if !ok {
		t.Fatal("expected success")
	}
	if method != "shadowcoerce" {
		t.Errorf("expected shadowcoerce, got %q", method)
	}
}

func TestDetectCoercionSuccess_NoSuccess(t *testing.T) {
	input := "[-] Failed: RPC connection refused"
	_, ok := detectCoercionSuccess(input)
	if ok {
		t.Error("expected no success for failed output")
	}
}

func TestDetectCoercionSuccess_Empty(t *testing.T) {
	_, ok := detectCoercionSuccess("")
	if ok {
		t.Error("expected no success for empty input")
	}
}

func TestDetectCoercionSuccess_UnknownMethod(t *testing.T) {
	input := "Authentication coercion triggered successfully via custom method"
	method, ok := detectCoercionSuccess(input)
	if !ok {
		t.Fatal("expected success (triggered keyword)")
	}
	if method != "unknown" {
		t.Errorf("expected unknown (no recognized method), got %q", method)
	}
}
