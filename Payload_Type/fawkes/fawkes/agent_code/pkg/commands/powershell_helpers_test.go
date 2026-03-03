package commands

import (
	"encoding/base64"
	"strings"
	"testing"
	"unicode/utf16"
)

// TestBuildPSFlags_NoFullFlags is the critical OPSEC test: verifies the standard
// SIEM signature pattern ("-ExecutionPolicy Bypass -NoProfile -NonInteractive")
// never appears in output. These full flag names are matched by:
// - Sigma: proc_creation_win_powershell_suspicious_flags
// - Elastic: powershell_suspicious_execution
// - CrowdStrike: SuspiciousPowerShellFlags
func TestBuildPSFlags_NoFullFlags(t *testing.T) {
	opts := DefaultPSOptions()
	for i := 0; i < 1000; i++ {
		flags := BuildPSFlags(opts)
		joined := strings.Join(flags, " ")
		if strings.Contains(joined, "ExecutionPolicy") {
			t.Fatal("OPSEC failure: full -ExecutionPolicy flag detected")
		}
		if strings.Contains(joined, "NoProfile") {
			t.Fatal("OPSEC failure: full -NoProfile flag detected")
		}
		if strings.Contains(joined, "NonInteractive") {
			t.Fatal("OPSEC failure: full -NonInteractive flag detected")
		}
	}
}

func TestBuildPSFlags_Abbreviated(t *testing.T) {
	opts := DefaultPSOptions()
	for i := 0; i < 100; i++ {
		flags := BuildPSFlags(opts)
		if len(flags) == 0 {
			t.Fatal("expected flags, got empty slice")
		}
		// Should have: one nop variant, one noni variant, one ep variant + bypass
		// Total: 4 strings minimum (nop + noni + ep + bypass)
		if len(flags) != 4 {
			t.Errorf("expected 4 flag strings with DefaultPSOptions, got %d: %v", len(flags), flags)
		}

		// Verify each flag is from our variant lists
		joined := strings.Join(flags, " ")
		foundNop := containsAnyVariant(joined, nopVariants)
		foundNoni := containsAnyVariant(joined, noniVariants)
		foundEp := containsAnyVariant(joined, epVariants)
		foundBypass := containsAnyVariant(joined, bypassVariants)

		if !foundNop {
			t.Errorf("no -NoProfile variant found in: %v", flags)
		}
		if !foundNoni {
			t.Errorf("no -NonInteractive variant found in: %v", flags)
		}
		if !foundEp {
			t.Errorf("no -ExecutionPolicy variant found in: %v", flags)
		}
		if !foundBypass {
			t.Errorf("no Bypass variant found in: %v", flags)
		}
	}
}

func TestBuildPSFlags_Randomized(t *testing.T) {
	opts := DefaultPSOptions()
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		flags := BuildPSFlags(opts)
		key := strings.Join(flags, "|")
		seen[key] = true
	}
	// With 3 flag groups (3! = 6 orderings) * variant selection,
	// we should see many unique combinations
	if len(seen) < 5 {
		t.Errorf("expected flag randomization, but only saw %d unique combinations", len(seen))
	}
}

func TestBuildPSFlags_Empty(t *testing.T) {
	flags := BuildPSFlags(PSOptions{})
	if len(flags) != 0 {
		t.Errorf("expected 0 flags for empty options, got %d: %v", len(flags), flags)
	}
}

func TestBuildPSFlags_OnlyNoProfile(t *testing.T) {
	flags := BuildPSFlags(PSOptions{NoProfile: true})
	if len(flags) != 1 {
		t.Errorf("expected 1 flag, got %d: %v", len(flags), flags)
	}
	if !containsAnyVariant(flags[0], nopVariants) {
		t.Errorf("expected -NoProfile variant, got %s", flags[0])
	}
}

func TestBuildPSFlags_OnlyNonInteractive(t *testing.T) {
	flags := BuildPSFlags(PSOptions{NonInteractive: true})
	if len(flags) != 1 {
		t.Errorf("expected 1 flag, got %d: %v", len(flags), flags)
	}
	if !containsAnyVariant(flags[0], noniVariants) {
		t.Errorf("expected -NonInteractive variant, got %s", flags[0])
	}
}

func TestBuildPSFlags_InternalOptions(t *testing.T) {
	flags := BuildPSFlags(InternalPSOptions())
	if len(flags) != 2 {
		t.Errorf("expected 2 flags for InternalPSOptions, got %d: %v", len(flags), flags)
	}
	joined := strings.Join(flags, " ")
	if containsAnyVariant(joined, epVariants) {
		t.Error("InternalPSOptions should not include -ExecutionPolicy")
	}
}

func TestBuildPSArgs(t *testing.T) {
	args := BuildPSArgs("whoami", DefaultPSOptions())
	// Last two elements should always be -Command whoami
	if len(args) < 2 {
		t.Fatal("too few args")
	}
	if args[len(args)-2] != "-Command" {
		t.Errorf("expected -Command as second-to-last arg, got %s", args[len(args)-2])
	}
	if args[len(args)-1] != "whoami" {
		t.Errorf("expected whoami as last arg, got %s", args[len(args)-1])
	}
}

func TestBuildPSArgs_EmptyCommand(t *testing.T) {
	args := BuildPSArgs("", DefaultPSOptions())
	if args[len(args)-2] != "-Command" {
		t.Errorf("expected -Command, got %s", args[len(args)-2])
	}
	if args[len(args)-1] != "" {
		t.Errorf("expected empty command, got %s", args[len(args)-1])
	}
}

func TestBuildPSArgsEncoded(t *testing.T) {
	args := BuildPSArgsEncoded("whoami", DefaultPSOptions())
	if len(args) < 2 {
		t.Fatal("too few args")
	}
	if args[len(args)-2] != "-enc" {
		t.Errorf("expected -enc as second-to-last arg, got %s", args[len(args)-2])
	}
	// Verify the encoded value decodes to "whoami"
	encoded := args[len(args)-1]
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode failed: %v", err)
	}
	u16s := make([]uint16, len(decoded)/2)
	for i := range u16s {
		u16s[i] = uint16(decoded[i*2]) | uint16(decoded[i*2+1])<<8
	}
	result := string(utf16.Decode(u16s))
	if result != "whoami" {
		t.Errorf("decoded command: got %q, want %q", result, "whoami")
	}
}

func TestBuildPSArgsEncoded_NoPlaintextLeak(t *testing.T) {
	args := BuildPSArgsEncoded("Get-Process | Select-Object Name", DefaultPSOptions())
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "Get-Process") {
		t.Error("encoded mode should not contain plaintext command")
	}
	if strings.Contains(joined, "Select-Object") {
		t.Error("encoded mode should not contain plaintext command")
	}
}

func TestBuildPSCmdLine_Standard(t *testing.T) {
	line := BuildPSCmdLine("whoami", DefaultPSOptions(), false)
	if !strings.HasPrefix(line, "powershell.exe ") {
		t.Error("should start with powershell.exe")
	}
	if !strings.Contains(line, `"whoami"`) {
		t.Errorf("should contain quoted command, got: %s", line)
	}
	if !strings.Contains(line, "-Command") {
		t.Error("non-encoded mode should contain -Command")
	}
}

func TestBuildPSCmdLine_Encoded(t *testing.T) {
	line := BuildPSCmdLine("whoami", DefaultPSOptions(), true)
	if !strings.HasPrefix(line, "powershell.exe ") {
		t.Error("should start with powershell.exe")
	}
	if strings.Contains(line, "whoami") {
		t.Error("encoded mode should not contain plaintext command")
	}
	if !strings.Contains(line, "-enc") {
		t.Error("encoded mode should contain -enc")
	}
}

func TestBuildPSCmdLine_NoSIEMSignature(t *testing.T) {
	// The standard SIEM detection pattern
	for i := 0; i < 100; i++ {
		line := BuildPSCmdLine("test", DefaultPSOptions(), false)
		if strings.Contains(line, "-ExecutionPolicy Bypass") {
			t.Fatal("OPSEC failure: standard SIEM signature in command line")
		}
		if strings.Contains(line, "-NoProfile -NonInteractive") {
			t.Fatal("OPSEC failure: standard flag ordering detected")
		}
	}
}

func TestEncodeUTF16LEBase64(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty", "", ""},
		{"whoami", "whoami", "dwBoAG8AYQBtAGkA"},
		{"Get-Process", "Get-Process", "RwBlAHQALQBQAHIAbwBjAGUAcwBzAA=="},
		{"single char", "A", "QQA="},
		{"spaces", "a b", "YQAgAGIA"},
		{"special chars", "$env:PATH", "JABlAG4AdgA6AFAAQQBUAEgA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeUTF16LEBase64(tt.input)
			if got != tt.expected {
				t.Errorf("EncodeUTF16LEBase64(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestEncodeUTF16LEBase64_RoundTrip(t *testing.T) {
	inputs := []string{
		"whoami",
		"Get-Process | Where-Object { $_.CPU -gt 100 }",
		"[System.IO.File]::ReadAllBytes('C:\\temp\\test.txt')",
		"powershell -ep bypass -nop -c 'nested command'",
		"$x = @{Name='test'; Value=42}",
	}
	for _, input := range inputs {
		encoded := EncodeUTF16LEBase64(input)
		// Decode and verify round-trip
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Errorf("base64 decode failed for %q: %v", input, err)
			continue
		}
		u16s := make([]uint16, len(decoded)/2)
		for i := range u16s {
			u16s[i] = uint16(decoded[i*2]) | uint16(decoded[i*2+1])<<8
		}
		result := string(utf16.Decode(u16s))
		if result != input {
			t.Errorf("round-trip failed: input=%q, result=%q", input, result)
		}
	}
}

func TestDefaultPSOptions(t *testing.T) {
	opts := DefaultPSOptions()
	if !opts.NoProfile {
		t.Error("DefaultPSOptions should have NoProfile=true")
	}
	if !opts.NonInteractive {
		t.Error("DefaultPSOptions should have NonInteractive=true")
	}
	if !opts.BypassExecPolicy {
		t.Error("DefaultPSOptions should have BypassExecPolicy=true")
	}
}

func TestInternalPSOptions(t *testing.T) {
	opts := InternalPSOptions()
	if !opts.NoProfile {
		t.Error("InternalPSOptions should have NoProfile=true")
	}
	if !opts.NonInteractive {
		t.Error("InternalPSOptions should have NonInteractive=true")
	}
	if opts.BypassExecPolicy {
		t.Error("InternalPSOptions should NOT have BypassExecPolicy=true")
	}
}

// containsAnyVariant checks if s contains any of the given variants
func containsAnyVariant(s string, variants []string) bool {
	for _, v := range variants {
		if strings.Contains(s, v) {
			return true
		}
	}
	return false
}
