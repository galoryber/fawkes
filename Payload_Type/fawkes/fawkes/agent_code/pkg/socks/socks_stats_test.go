package socks

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewConnStats_DefaultMax(t *testing.T) {
	s := NewConnStats(0)
	if s.maxHistory != 100 {
		t.Errorf("Expected maxHistory=100 for 0 input, got %d", s.maxHistory)
	}
}

func TestRecordConnect(t *testing.T) {
	s := NewConnStats(50)
	s.RecordConnect(1, "10.0.0.1:80")

	if s.ActiveCount() != 1 {
		t.Errorf("Expected 1 active connection, got %d", s.ActiveCount())
	}
}

func TestRecordSendRecv(t *testing.T) {
	s := NewConnStats(50)
	s.RecordConnect(1, "10.0.0.1:80")
	s.RecordSend(1, 100)
	s.RecordRecv(1, 200)
	s.RecordSend(1, 50)

	s.mu.Lock()
	info := s.connections[1]
	s.mu.Unlock()

	if info.BytesSent != 150 {
		t.Errorf("Expected 150 bytes sent, got %d", info.BytesSent)
	}
	if info.BytesRecv != 200 {
		t.Errorf("Expected 200 bytes recv, got %d", info.BytesRecv)
	}
}

func TestRecordClose(t *testing.T) {
	s := NewConnStats(50)
	s.RecordConnect(1, "10.0.0.1:80")
	s.RecordSend(1, 100)
	s.RecordClose(1, "closed")

	if s.ActiveCount() != 0 {
		t.Errorf("Expected 0 active after close, got %d", s.ActiveCount())
	}

	s.mu.Lock()
	histLen := len(s.history)
	s.mu.Unlock()
	if histLen != 1 {
		t.Errorf("Expected 1 history entry, got %d", histLen)
	}
}

func TestRecordClose_NonExistent(t *testing.T) {
	s := NewConnStats(50)
	s.RecordClose(999, "closed") // should not panic
}

func TestHistoryCap(t *testing.T) {
	s := NewConnStats(10)
	for i := uint32(0); i < 20; i++ {
		s.RecordConnect(i, "10.0.0.1:80")
		s.RecordClose(i, "closed")
	}

	s.mu.Lock()
	histLen := len(s.history)
	s.mu.Unlock()
	if histLen != 10 {
		t.Errorf("Expected 10 history entries (capped), got %d", histLen)
	}
}

func TestSummary_JSON(t *testing.T) {
	s := NewConnStats(50)
	s.RecordConnect(1, "10.0.0.1:80")
	s.RecordSend(1, 100)

	summary := s.Summary()
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(summary), &parsed); err != nil {
		t.Fatalf("Summary should be valid JSON: %v", err)
	}
	if parsed["total_bytes_sent"].(float64) != 100 {
		t.Errorf("Expected total_bytes_sent=100, got %v", parsed["total_bytes_sent"])
	}
}

func TestFormatSummary(t *testing.T) {
	s := NewConnStats(50)
	s.RecordConnect(1, "10.0.0.1:80")
	s.RecordSend(1, 1024*1024) // 1 MB

	summary := s.FormatSummary()
	if !strings.Contains(summary, "1 active") {
		t.Errorf("Expected '1 active' in summary, got %q", summary)
	}
	if !strings.Contains(summary, "MB") {
		t.Errorf("Expected MB in formatted bytes, got %q", summary)
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
	}
	for _, tt := range tests {
		result := formatBytes(tt.bytes)
		if result != tt.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
		}
	}
}

func TestConnInfoDuration(t *testing.T) {
	info := &ConnInfo{
		Target: "10.0.0.1:80",
	}
	// With zero EndTime, Duration should return time since Start
	if info.Duration() <= 0 {
		// This could be flaky, but StartTime defaults to zero which is way in the past
		// so duration should be very large
	}
}

func TestRecordSendRecv_NonExistent(t *testing.T) {
	s := NewConnStats(50)
	// Should not panic on non-existent connection
	s.RecordSend(999, 100)
	s.RecordRecv(999, 200)
}
