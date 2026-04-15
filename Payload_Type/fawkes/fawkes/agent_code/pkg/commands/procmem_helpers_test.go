//go:build linux && amd64

package commands

import (
	"strings"
	"testing"
)

func TestWriteProcMem_InvalidPath(t *testing.T) {
	_, err := writeProcMem("/proc/999999999/mem", 0x1000, []byte{0x90})
	if err == nil {
		t.Error("writeProcMem should fail with invalid PID path")
	}
	if !strings.Contains(err.Error(), "open") {
		t.Errorf("Error should mention open, got %v", err)
	}
}

func TestWriteProcMem_EmptyData(t *testing.T) {
	_, err := writeProcMem("/proc/999999999/mem", 0x1000, []byte{})
	if err == nil {
		t.Error("writeProcMem should fail with invalid path even for empty data")
	}
}
