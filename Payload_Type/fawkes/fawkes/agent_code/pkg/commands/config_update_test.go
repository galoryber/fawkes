package commands

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateExecutable_ELF(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_elf")
	// ELF magic: 0x7f E L F
	os.WriteFile(tmp, []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, 0700)
	err := validateExecutable(tmp)
	if runtime.GOOS == "windows" {
		if err == nil {
			t.Fatal("expected error for ELF on Windows")
		}
	} else {
		if err != nil {
			t.Fatalf("unexpected error for ELF on %s: %v", runtime.GOOS, err)
		}
	}
}

func TestValidateExecutable_PE(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_pe")
	// PE magic: M Z
	os.WriteFile(tmp, []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, 0700)
	err := validateExecutable(tmp)
	if runtime.GOOS == "windows" {
		if err != nil {
			t.Fatalf("unexpected error for PE on Windows: %v", err)
		}
	} else {
		if err == nil {
			t.Fatal("expected error for PE on non-Windows")
		}
	}
}

func TestValidateExecutable_MachO64(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_macho")
	// Mach-O 64-bit magic: CF FA ED FE
	os.WriteFile(tmp, []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01}, 0700)
	err := validateExecutable(tmp)
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("unexpected error for Mach-O on darwin: %v", err)
		}
	} else {
		if err == nil {
			t.Fatal("expected error for Mach-O on non-darwin")
		}
	}
}

func TestValidateExecutable_MachO32(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_macho32")
	// Mach-O 32-bit magic: FE ED FA CE
	os.WriteFile(tmp, []byte{0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x02}, 0700)
	err := validateExecutable(tmp)
	if runtime.GOOS == "darwin" {
		if err != nil {
			t.Fatalf("unexpected error for Mach-O 32 on darwin: %v", err)
		}
	} else {
		if err == nil {
			t.Fatal("expected error for Mach-O 32 on non-darwin")
		}
	}
}

func TestValidateExecutable_InvalidFormat(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_bad")
	os.WriteFile(tmp, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0700)
	err := validateExecutable(tmp)
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestValidateExecutable_TooSmall(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_tiny")
	os.WriteFile(tmp, []byte{0x7f}, 0700)
	err := validateExecutable(tmp)
	if err == nil {
		t.Fatal("expected error for file too small")
	}
}

func TestValidateExecutable_Empty(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test_empty")
	os.WriteFile(tmp, []byte{}, 0700)
	err := validateExecutable(tmp)
	if err == nil {
		t.Fatal("expected error for empty file")
	}
}

func TestValidateExecutable_Missing(t *testing.T) {
	err := validateExecutable("/nonexistent/path/binary")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestConfigUpdateParams_EmptyFileID(t *testing.T) {
	params := configUpdateParams{Action: "update", FileID: ""}
	task := makeTestTask()
	result := configUpdate(task, params)
	if result.Status != "error" {
		t.Fatal("expected error for empty file ID")
	}
}
