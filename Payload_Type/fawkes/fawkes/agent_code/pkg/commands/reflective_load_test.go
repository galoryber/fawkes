//go:build windows
// +build windows

package commands

import "testing"

// --- rlSectionProtection Tests ---

func TestRlSectionProtection_ExecReadWrite(t *testing.T) {
	chars := uint32(rlSCNMemExecute | rlSCNMemRead | rlSCNMemWrite)
	got := rlSectionProtection(chars)
	if got != rlPageExecuteRW {
		t.Errorf("rlSectionProtection(ERW) = 0x%x, want 0x%x", got, rlPageExecuteRW)
	}
}

func TestRlSectionProtection_ExecRead(t *testing.T) {
	chars := uint32(rlSCNMemExecute | rlSCNMemRead)
	got := rlSectionProtection(chars)
	if got != rlPageExecuteRead {
		t.Errorf("rlSectionProtection(ER) = 0x%x, want 0x%x", got, rlPageExecuteRead)
	}
}

func TestRlSectionProtection_ExecOnly(t *testing.T) {
	chars := uint32(rlSCNMemExecute)
	got := rlSectionProtection(chars)
	if got != rlPageExecuteRead {
		t.Errorf("rlSectionProtection(E) = 0x%x, want 0x%x (falls through to exec+read)", got, rlPageExecuteRead)
	}
}

func TestRlSectionProtection_ReadWrite(t *testing.T) {
	chars := uint32(rlSCNMemRead | rlSCNMemWrite)
	got := rlSectionProtection(chars)
	if got != rlPageReadWrite {
		t.Errorf("rlSectionProtection(RW) = 0x%x, want 0x%x", got, rlPageReadWrite)
	}
}

func TestRlSectionProtection_ReadOnly(t *testing.T) {
	chars := uint32(rlSCNMemRead)
	got := rlSectionProtection(chars)
	if got != rlPageReadOnly {
		t.Errorf("rlSectionProtection(R) = 0x%x, want 0x%x", got, rlPageReadOnly)
	}
}

func TestRlSectionProtection_NoAccess(t *testing.T) {
	got := rlSectionProtection(0)
	if got != rlPageNoAccess {
		t.Errorf("rlSectionProtection(0) = 0x%x, want 0x%x", got, rlPageNoAccess)
	}
}

func TestRlSectionProtection_WriteOnly(t *testing.T) {
	// Write without read — should fall to NoAccess (no explicit write-only case)
	chars := uint32(rlSCNMemWrite)
	got := rlSectionProtection(chars)
	if got != rlPageNoAccess {
		t.Errorf("rlSectionProtection(W) = 0x%x, want 0x%x (no write-only mapping)", got, rlPageNoAccess)
	}
}

// --- rlSectionName Tests ---

func TestRlSectionName_Text(t *testing.T) {
	name := [8]byte{'.', 't', 'e', 'x', 't', 0, 0, 0}
	got := rlSectionName(name)
	if got != ".text" {
		t.Errorf("rlSectionName = %q, want .text", got)
	}
}

func TestRlSectionName_Data(t *testing.T) {
	name := [8]byte{'.', 'd', 'a', 't', 'a', 0, 0, 0}
	got := rlSectionName(name)
	if got != ".data" {
		t.Errorf("rlSectionName = %q, want .data", got)
	}
}

func TestRlSectionName_FullLength(t *testing.T) {
	// 8 chars, no null terminator — should use all 8
	name := [8]byte{'.', 'r', 'e', 'l', 'o', 'c', 'x', 'y'}
	got := rlSectionName(name)
	if got != ".relocxy" {
		t.Errorf("rlSectionName = %q, want .relocxy", got)
	}
}

func TestRlSectionName_Empty(t *testing.T) {
	name := [8]byte{}
	got := rlSectionName(name)
	if got != "" {
		t.Errorf("rlSectionName = %q, want empty", got)
	}
}

func TestRlSectionName_SingleChar(t *testing.T) {
	name := [8]byte{'X', 0, 0, 0, 0, 0, 0, 0}
	got := rlSectionName(name)
	if got != "X" {
		t.Errorf("rlSectionName = %q, want X", got)
	}
}
