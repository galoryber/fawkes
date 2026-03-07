package structs

import (
	"testing"
	"unsafe"
)

func TestZeroBytes_ClearsAll(t *testing.T) {
	data := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("ZeroBytes did not clear byte %d: got 0x%02x", i, b)
		}
	}
}

func TestZeroBytes_Empty(t *testing.T) {
	data := []byte{}
	ZeroBytes(data) // should not panic
}

func TestZeroBytes_Nil(t *testing.T) {
	ZeroBytes(nil) // should not panic
}

func TestZeroBytes_Large(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	ZeroBytes(data)
	for i, b := range data {
		if b != 0 {
			t.Errorf("ZeroBytes did not clear byte %d of large slice", i)
			break
		}
	}
}

func TestZeroString_ClearsBacking(t *testing.T) {
	// Build string from mutable bytes so we can verify zeroing
	original := []byte("SuperSecretPassword123!")
	s := string(original)

	// Get pointer to backing data before zeroing
	ptr := unsafe.StringData(s)

	ZeroString(&s)

	// After zeroing, the variable should be empty
	if s != "" {
		t.Errorf("ZeroString did not clear string variable: got %q", s)
	}

	// The backing memory should be zeroed
	backed := unsafe.Slice(ptr, len(original))
	for i, b := range backed {
		if b != 0 {
			t.Errorf("ZeroString did not zero backing byte %d: got 0x%02x", i, b)
			break
		}
	}
}

func TestZeroString_Empty(t *testing.T) {
	s := ""
	ZeroString(&s) // should not panic
	if s != "" {
		t.Error("ZeroString changed empty string")
	}
}

func TestZeroString_LongString(t *testing.T) {
	// 1KB string
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}
	s := string(data)

	ZeroString(&s)

	if s != "" {
		t.Error("ZeroString did not clear long string variable")
	}
}
