//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestPerformRetPatch_InvalidDLL(t *testing.T) {
	_, err := PerformRetPatch("nonexistent_dll_12345.dll", "SomeFunction")
	if err == nil {
		t.Error("PerformRetPatch with nonexistent DLL should return error")
	}
}

func TestPerformRetPatch_InvalidFunction(t *testing.T) {
	// kernel32.dll exists but FakeFunction999 does not
	_, err := PerformRetPatch("kernel32.dll", "FakeFunction999")
	if err == nil {
		t.Error("PerformRetPatch with nonexistent function should return error")
	}
}
