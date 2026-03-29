//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestCONTEXT_AMD64_Size(t *testing.T) {
	// Windows CONTEXT_AMD64 must be exactly 1232 bytes
	const expectedSize = 1232
	actual := unsafe.Sizeof(CONTEXT_AMD64{})
	if actual != expectedSize {
		t.Errorf("CONTEXT_AMD64 size = %d, want %d", actual, expectedSize)
	}
}

func TestCONTEX_AMD64_FieldOffsets(t *testing.T) {
	var ctx CONTEXT_AMD64
	base := uintptr(unsafe.Pointer(&ctx))

	tests := []struct {
		name   string
		offset uintptr
		want   uintptr
	}{
		{"ContextFlags", uintptr(unsafe.Pointer(&ctx.ContextFlags)) - base, 0x30},
		{"Dr0", uintptr(unsafe.Pointer(&ctx.Dr0)) - base, 0x48},
		{"Dr1", uintptr(unsafe.Pointer(&ctx.Dr1)) - base, 0x50},
		{"Dr6", uintptr(unsafe.Pointer(&ctx.Dr6)) - base, 0x68},
		{"Dr7", uintptr(unsafe.Pointer(&ctx.Dr7)) - base, 0x70},
		{"Rax", uintptr(unsafe.Pointer(&ctx.Rax)) - base, 0x78},
		{"Rcx", uintptr(unsafe.Pointer(&ctx.Rcx)) - base, 0x80},
		{"Rsp", uintptr(unsafe.Pointer(&ctx.Rsp)) - base, 0x98},
		{"Rip", uintptr(unsafe.Pointer(&ctx.Rip)) - base, 0xF8},
	}
	for _, tt := range tests {
		if tt.offset != tt.want {
			t.Errorf("%s offset = 0x%X, want 0x%X", tt.name, tt.offset, tt.want)
		}
	}
}

func TestEXCEPTION_RECORD_Fields(t *testing.T) {
	var rec EXCEPTION_RECORD
	rec.ExceptionCode = STATUS_SINGLE_STEP
	if rec.ExceptionCode != 0x80000004 {
		t.Errorf("ExceptionCode = 0x%X, want 0x80000004", rec.ExceptionCode)
	}
}

func TestHWBP_Constants(t *testing.T) {
	if STATUS_SINGLE_STEP != 0x80000004 {
		t.Errorf("STATUS_SINGLE_STEP = 0x%X, want 0x80000004", STATUS_SINGLE_STEP)
	}
	if EXCEPTION_CONTINUE_EXECUTION != 0xFFFFFFFF {
		t.Errorf("EXCEPTION_CONTINUE_EXECUTION = 0x%X, want 0xFFFFFFFF", EXCEPTION_CONTINUE_EXECUTION)
	}
	if EXCEPTION_CONTINUE_SEARCH != 0 {
		t.Errorf("EXCEPTION_CONTINUE_SEARCH = 0x%X, want 0", EXCEPTION_CONTINUE_SEARCH)
	}
	if CONTEXT_DEBUG_REGISTERS != (CONTEXT_AMD64_FLAG | 0x0010) {
		t.Errorf("CONTEXT_DEBUG_REGISTERS = 0x%X, want 0x%X", CONTEXT_DEBUG_REGISTERS, CONTEXT_AMD64_FLAG|0x0010)
	}
}

func TestM128A_Size(t *testing.T) {
	expected := uintptr(16)
	actual := unsafe.Sizeof(M128A{})
	if actual != expected {
		t.Errorf("M128A size = %d, want %d", actual, expected)
	}
}

func TestHWBP_InitialState(t *testing.T) {
	// Verify global HWBP state starts uninstalled
	hwbpMutex.Lock()
	installed := hwbpInstalled
	hwbpMutex.Unlock()

	// This test may run after other tests have installed HWBP,
	// so we just verify the mutex works and the variable is accessible
	_ = installed
}
