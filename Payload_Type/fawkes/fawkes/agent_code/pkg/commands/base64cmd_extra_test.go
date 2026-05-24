package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReadInputDataFileError covers the os.ReadFile error path (line 143).
func TestReadInputDataFileError(t *testing.T) {
	_, err := readInputData(base64Args{File: true, Input: "/nonexistent/path/to/file.txt"})
	if err == nil {
		t.Error("expected error for nonexistent file in readInputData")
	}
}

// TestWriteOrReturnErrors covers writeOrReturn error paths (lines 154, 160).
func TestWriteOrReturnErrors(t *testing.T) {
	data := []byte("test data")

	t.Run("write to unwritable path (line 154)", func(t *testing.T) {
		result := writeOrReturn(base64Args{Output: "/nonexistent/dir/output.txt"}, data, "test", len(data))
		if result.Status != "error" {
			t.Errorf("expected error status, got %q", result.Status)
		}
	})

	t.Run("file input source shown in output (line 160)", func(t *testing.T) {
		// File=true, Output="" → uses args.Input as source label in success message
		result := writeOrReturn(base64Args{File: true, Input: "mydata.bin"}, data, "ROT13", len(data))
		if result.Status != "success" {
			t.Errorf("expected success, got %q", result.Status)
		}
		if !strings.Contains(result.Output, "mydata.bin") {
			t.Errorf("expected output to contain filename, got: %s", result.Output)
		}
	})
}

// TestEncodingXORExtraErrors covers uncovered XOR paths (lines 188, 193, 206, 214).
func TestEncodingXORExtraErrors(t *testing.T) {
	t.Run("empty key after hex parse (line 188)", func(t *testing.T) {
		// Key "0x" has the hex prefix but zero hex digits → parses to empty []byte
		result := encodingXOR(base64Args{Input: "hello", Key: "0x"})
		if result.Status != "error" {
			t.Errorf("expected error for 0x-prefixed empty key, got %q", result.Status)
		}
	})

	t.Run("readInputData error (line 193)", func(t *testing.T) {
		result := encodingXOR(base64Args{File: true, Input: "/nonexistent/file", Key: "secret"})
		if result.Status != "error" {
			t.Errorf("expected error for nonexistent XOR input file, got %q", result.Status)
		}
	})

	t.Run("file write error (line 206)", func(t *testing.T) {
		result := encodingXOR(base64Args{Input: "hello", Key: "x", Output: "/nonexistent/dir/out.bin"})
		if result.Status != "error" {
			t.Errorf("expected error writing XOR to bad path, got %q", result.Status)
		}
	})

	t.Run("XOR from file shows filename as source (line 214)", func(t *testing.T) {
		dir := t.TempDir()
		inPath := filepath.Join(dir, "input.txt")
		if err := os.WriteFile(inPath, []byte("hello"), 0644); err != nil {
			t.Fatal(err)
		}
		result := encodingXOR(base64Args{File: true, Input: inPath, Key: "x"})
		if result.Status != "success" {
			t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
		}
		if !strings.Contains(result.Output, inPath) {
			t.Errorf("expected output to contain source filename, got: %s", result.Output)
		}
	})
}

// TestEncodingFunctionsFileErrors covers readInputData error paths in multiple encoders.
func TestEncodingFunctionsFileErrors(t *testing.T) {
	badFile := base64Args{File: true, Input: "/nonexistent/path.dat"}

	t.Run("encodingHex file error (line 223)", func(t *testing.T) {
		result := encodingHex(badFile)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("encodingHexDecode file error (line 235)", func(t *testing.T) {
		result := encodingHexDecode(badFile)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("encodingROT13 file error (line 260)", func(t *testing.T) {
		result := encodingROT13(badFile)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("encodingURLEncode file error (line 287)", func(t *testing.T) {
		result := encodingURLEncode(badFile)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("encodingURLDecode file error (line 298)", func(t *testing.T) {
		result := encodingURLDecode(badFile)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})

	t.Run("encodingCaesar file error (line 323)", func(t *testing.T) {
		caesarBad := base64Args{File: true, Input: "/nonexistent/path.dat", Shift: 3}
		result := encodingCaesar(caesarBad)
		if result.Status != "error" {
			t.Errorf("expected error, got %q", result.Status)
		}
	})
}
