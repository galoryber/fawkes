//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestResolveHive_HKLM(t *testing.T) {
	for _, name := range []string{"HKLM", "hklm", "HKEY_LOCAL_MACHINE", "Hklm"} {
		h, err := resolveHive(name)
		if err != nil {
			t.Errorf("resolveHive(%q) error: %v", name, err)
		}
		if h != hkeyLocalMachine {
			t.Errorf("resolveHive(%q) = 0x%X, want 0x%X", name, h, hkeyLocalMachine)
		}
	}
}

func TestResolveHive_HKCU(t *testing.T) {
	for _, name := range []string{"HKCU", "hkcu", "HKEY_CURRENT_USER"} {
		h, err := resolveHive(name)
		if err != nil {
			t.Errorf("resolveHive(%q) error: %v", name, err)
		}
		if h != 0x80000001 {
			t.Errorf("resolveHive(%q) = 0x%X, want 0x80000001", name, h)
		}
	}
}

func TestResolveHive_HKCR(t *testing.T) {
	h, err := resolveHive("HKCR")
	if err != nil {
		t.Fatalf("resolveHive(\"HKCR\") error: %v", err)
	}
	if h != 0x80000000 {
		t.Errorf("resolveHive(\"HKCR\") = 0x%X, want 0x80000000", h)
	}
}

func TestResolveHive_HKU(t *testing.T) {
	h, err := resolveHive("HKU")
	if err != nil {
		t.Fatalf("resolveHive(\"HKU\") error: %v", err)
	}
	if h != 0x80000003 {
		t.Errorf("resolveHive(\"HKU\") = 0x%X, want 0x80000003", h)
	}
}

func TestResolveHive_Unknown(t *testing.T) {
	_, err := resolveHive("HKCC")
	if err == nil {
		t.Error("resolveHive(\"HKCC\") should return error")
	}

	_, err = resolveHive("")
	if err == nil {
		t.Error("resolveHive(\"\") should return error")
	}

	_, err = resolveHive("invalid")
	if err == nil {
		t.Error("resolveHive(\"invalid\") should return error")
	}
}
