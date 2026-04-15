package commands

import (
	"strings"
	"testing"
)

func TestMasqueradeName(t *testing.T) {
	cmd := &MasqueradeCommand{}
	if cmd.Name() != "masquerade" {
		t.Errorf("expected masquerade, got %s", cmd.Name())
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"abc", "cba"},
		{"hello", "olleh"},
		{"", ""},
		{"x", "x"},
		{"ab", "ba"},
		{"café", "éfac"},
	}
	for _, tt := range tests {
		got := reverseString(tt.input)
		if got != tt.want {
			t.Errorf("reverseString(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGenerateMasqueradeName_DoubleExt(t *testing.T) {
	tests := []struct {
		source, disguise, want string
	}{
		{"payload.exe", "document.pdf", "document.pdf.exe"},
		{"payload.exe", "", "document.pdf.exe"}, // default disguise
		{"malware.dll", "readme.txt", "readme.txt.dll"},
		{"test.bin", "invoice.docx", "invoice.docx.bin"},
	}
	for _, tt := range tests {
		got, err := generateMasqueradeName(tt.source, "double_ext", tt.disguise)
		if err != nil {
			t.Errorf("double_ext(%q, %q) error: %v", tt.source, tt.disguise, err)
			continue
		}
		if got != tt.want {
			t.Errorf("double_ext(%q, %q) = %q, want %q", tt.source, tt.disguise, got, tt.want)
		}
	}
}

func TestGenerateMasqueradeName_RTLO(t *testing.T) {
	// RTLO should insert U+202E and reverse the disguise
	got, err := generateMasqueradeName("payload.exe", "rtlo", "txt")
	if err != nil {
		t.Fatalf("rtlo error: %v", err)
	}
	if !strings.Contains(got, "\u202e") {
		t.Error("rtlo should contain RTLO character U+202E")
	}
	if !strings.Contains(got, "txt") {
		t.Error("rtlo should contain reversed disguise")
	}
	if !strings.HasSuffix(got, ".exe") {
		t.Error("rtlo should end with original extension")
	}

	// Default disguise
	got2, _ := generateMasqueradeName("test.dll", "rtlo", "")
	if !strings.Contains(got2, "\u202e") {
		t.Error("rtlo with empty disguise should still contain RTLO")
	}
}

func TestGenerateMasqueradeName_Space(t *testing.T) {
	got, err := generateMasqueradeName("payload.exe", "space", "txt")
	if err != nil {
		t.Fatalf("space error: %v", err)
	}
	if !strings.Contains(got, ".txt") {
		t.Error("space should contain disguise extension")
	}
	if !strings.HasSuffix(got, ".exe") {
		t.Error("space should end with real extension")
	}
	// Should have exactly 30 spaces
	spaceCount := strings.Count(got, " ")
	if spaceCount != 30 {
		t.Errorf("space should have 30 spaces, got %d", spaceCount)
	}

	// Default disguise
	got2, _ := generateMasqueradeName("test.dll", "space", "")
	if !strings.Contains(got2, ".txt") {
		t.Error("space with empty disguise should default to txt")
	}
}

func TestGenerateMasqueradeName_MatchExt(t *testing.T) {
	tests := []struct {
		source, disguise, want string
	}{
		{"payload.exe", "txt", "payload.txt"},
		{"malware.dll", "doc", "malware.doc"},
		{"test.bin", "", "test.txt"}, // default
	}
	for _, tt := range tests {
		got, err := generateMasqueradeName(tt.source, "match_ext", tt.disguise)
		if err != nil {
			t.Errorf("match_ext(%q, %q) error: %v", tt.source, tt.disguise, err)
			continue
		}
		if got != tt.want {
			t.Errorf("match_ext(%q, %q) = %q, want %q", tt.source, tt.disguise, got, tt.want)
		}
	}
}

func TestGenerateMasqueradeName_UnknownTechnique(t *testing.T) {
	_, err := generateMasqueradeName("payload.exe", "bogus", "")
	if err == nil {
		t.Error("expected error for unknown technique")
	}
	if !strings.Contains(err.Error(), "unknown technique") {
		t.Errorf("error should mention 'unknown technique', got: %v", err)
	}
}
