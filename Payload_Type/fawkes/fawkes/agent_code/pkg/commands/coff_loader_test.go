//go:build windows
// +build windows

package commands

import (
	"testing"
)

func TestLoadAndRunBOF_EmptyBytes(t *testing.T) {
	_, err := LoadAndRunBOF([]byte{}, nil, "go")
	if err == nil {
		t.Error("LoadAndRunBOF with empty bytes should return error")
	}
}

func TestLoadAndRunBOF_InvalidCOFF(t *testing.T) {
	// Random bytes that aren't a valid COFF
	_, err := LoadAndRunBOF([]byte{0x01, 0x02, 0x03, 0x04}, nil, "go")
	if err == nil {
		t.Error("LoadAndRunBOF with invalid COFF should return error")
	}
}

func TestCoffImageScnMemExecute_Value(t *testing.T) {
	if coffImageScnMemExecute != 0x20000000 {
		t.Errorf("coffImageScnMemExecute = 0x%X, want 0x20000000", coffImageScnMemExecute)
	}
}
