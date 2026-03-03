package commands

import (
	"strings"
	"testing"
)

// --- truncStr Tests ---

func TestTruncStr_Short(t *testing.T) {
	if got := truncStr("hello", 10); got != "hello" {
		t.Errorf("truncStr = %q, want %q", got, "hello")
	}
}

func TestTruncStr_ExactLength(t *testing.T) {
	if got := truncStr("hello", 5); got != "hello" {
		t.Errorf("truncStr = %q, want %q", got, "hello")
	}
}

func TestTruncStr_Truncated(t *testing.T) {
	got := truncStr("hello world", 8)
	if got != "hello..." {
		t.Errorf("truncStr = %q, want %q", got, "hello...")
	}
	if len(got) > 8 {
		t.Errorf("truncStr length = %d, should be <= 8", len(got))
	}
}

func TestTruncStr_Empty(t *testing.T) {
	if got := truncStr("", 5); got != "" {
		t.Errorf("truncStr empty = %q, want empty", got)
	}
}

func TestTruncStr_HasEllipsis(t *testing.T) {
	got := truncStr("abcdefghijklmnop", 10)
	if !strings.HasSuffix(got, "...") {
		t.Errorf("truncStr should end with '...', got %q", got)
	}
}

// --- truncate Tests ---

func TestTruncate_Short(t *testing.T) {
	if got := truncate("hello", 10); got != "hello" {
		t.Errorf("truncate = %q, want %q", got, "hello")
	}
}

func TestTruncate_ExactLength(t *testing.T) {
	if got := truncate("hello", 5); got != "hello" {
		t.Errorf("truncate = %q, want %q", got, "hello")
	}
}

func TestTruncate_Truncated(t *testing.T) {
	got := truncate("hello world", 5)
	if got != "hello" {
		t.Errorf("truncate = %q, want %q", got, "hello")
	}
}

func TestTruncate_NoEllipsis(t *testing.T) {
	got := truncate("hello world", 5)
	if strings.Contains(got, "...") {
		t.Errorf("truncate should NOT have ellipsis, got %q", got)
	}
}

func TestTruncate_Empty(t *testing.T) {
	if got := truncate("", 5); got != "" {
		t.Errorf("truncate empty = %q, want empty", got)
	}
}

// --- formatBytes Tests ---

func TestFormatBytes_Zero(t *testing.T) {
	if got := formatBytes(0); got != "0 B" {
		t.Errorf("formatBytes(0) = %q, want %q", got, "0 B")
	}
}

func TestFormatBytes_Bytes(t *testing.T) {
	if got := formatBytes(512); got != "512 B" {
		t.Errorf("formatBytes(512) = %q, want %q", got, "512 B")
	}
}

func TestFormatBytes_KB(t *testing.T) {
	if got := formatBytes(1024); got != "1.0 KB" {
		t.Errorf("formatBytes(1024) = %q, want %q", got, "1.0 KB")
	}
}

func TestFormatBytes_MB(t *testing.T) {
	if got := formatBytes(1048576); got != "1.0 MB" {
		t.Errorf("formatBytes(1048576) = %q, want %q", got, "1.0 MB")
	}
}

func TestFormatBytes_GB(t *testing.T) {
	if got := formatBytes(1073741824); got != "1.0 GB" {
		t.Errorf("formatBytes(1073741824) = %q, want %q", got, "1.0 GB")
	}
}

func TestFormatBytes_Fractional(t *testing.T) {
	if got := formatBytes(1572864); got != "1.5 MB" {
		t.Errorf("formatBytes(1572864) = %q, want %q", got, "1.5 MB")
	}
}

func TestFormatBytes_JustUnderKB(t *testing.T) {
	if got := formatBytes(1023); got != "1023 B" {
		t.Errorf("formatBytes(1023) = %q, want %q", got, "1023 B")
	}
}

// --- formatFileSize Tests ---

func TestFormatFileSize_Zero(t *testing.T) {
	if got := formatFileSize(0); got != "0 B" {
		t.Errorf("formatFileSize(0) = %q, want %q", got, "0 B")
	}
}

func TestFormatFileSize_Negative(t *testing.T) {
	if got := formatFileSize(-1); got != "0 B" {
		t.Errorf("formatFileSize(-1) = %q, want %q", got, "0 B")
	}
}

func TestFormatFileSize_MatchesFormatBytes(t *testing.T) {
	sizes := []int64{0, 100, 1024, 1048576, 1073741824, 5368709120}
	for _, s := range sizes {
		expected := formatBytes(uint64(s))
		got := formatFileSize(s)
		if got != expected {
			t.Errorf("formatFileSize(%d) = %q, formatBytes(%d) = %q — mismatch", s, got, s, expected)
		}
	}
}

func TestFormatFileSize_KB(t *testing.T) {
	if got := formatFileSize(2048); got != "2.0 KB" {
		t.Errorf("formatFileSize(2048) = %q, want %q", got, "2.0 KB")
	}
}

func TestFormatFileSize_GB(t *testing.T) {
	if got := formatFileSize(5368709120); got != "5.0 GB" {
		t.Errorf("formatFileSize(5368709120) = %q, want %q", got, "5.0 GB")
	}
}
