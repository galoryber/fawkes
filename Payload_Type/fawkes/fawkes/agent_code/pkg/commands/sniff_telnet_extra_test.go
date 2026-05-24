package commands

import (
	"bytes"
	"testing"
)

// TestStripTelnetIACOtherCommand covers the "other 2-byte IAC command" else branch (line 101).
// Commands like 0xF1 (NOP) fall through all specific cases and are skipped as 2 bytes.
func TestStripTelnetIACOtherCommand(t *testing.T) {
	// 0xFF 0xF1 = IAC NOP — not escaped, not WILL/WONT/DO/DONT, not subneg
	// Should skip 2 bytes and return the following 'a'
	input := []byte{0xFF, 0xF1, 'a'}
	got := stripTelnetIAC(input)
	if !bytes.Equal(got, []byte{'a'}) {
		t.Errorf("stripTelnetIAC for IAC NOP: got %v, want [0x61]", got)
	}
}

// TestStripTelnetIACTrailingFF covers the case where 0xFF is the last byte (no cmd follows).
// The outer condition `i+1 < len(data)` is false, so 0xFF is output literally.
func TestStripTelnetIACTrailingFF(t *testing.T) {
	input := []byte{'h', 'i', 0xFF}
	got := stripTelnetIAC(input)
	if !bytes.Equal(got, []byte{'h', 'i', 0xFF}) {
		t.Errorf("stripTelnetIAC for trailing 0xFF: got %v, want [hi 0xFF]", got)
	}
}
