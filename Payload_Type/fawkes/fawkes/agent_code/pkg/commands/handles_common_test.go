package commands

import (
	"encoding/json"
	"testing"
)

func TestFormatHandleResultEmpty(t *testing.T) {
	result := formatHandleResult(nil, nil, handlesArgs{PID: 42}, 0)
	if result.Status != "success" {
		t.Errorf("expected success, got %q", result.Status)
	}

	var out struct {
		PID     int              `json:"pid"`
		Shown   int              `json:"shown"`
		Total   int              `json:"total"`
		Summary []handleTypeCount `json:"summary"`
		Handles []handleInfo     `json:"handles"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if out.PID != 42 {
		t.Errorf("PID = %d, want 42", out.PID)
	}
	if out.Shown != 0 {
		t.Errorf("Shown = %d, want 0", out.Shown)
	}
	if out.Total != 0 {
		t.Errorf("Total = %d, want 0", out.Total)
	}
}

func TestFormatHandleResultWithHandles(t *testing.T) {
	handles := []handleInfo{
		{Handle: 1, TypeName: "File", Name: "/tmp/test"},
		{Handle: 2, TypeName: "Socket", Name: "TCP:8080"},
		{Handle: 3, TypeName: "File", Name: "/etc/passwd"},
	}
	typeCounts := map[string]int{"File": 2, "Socket": 1}

	result := formatHandleResult(handles, typeCounts, handlesArgs{PID: 100}, 3)
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	var out struct {
		PID     int               `json:"pid"`
		Shown   int               `json:"shown"`
		Total   int               `json:"total"`
		Summary []handleTypeCount `json:"summary"`
		Handles []handleInfo      `json:"handles"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if out.PID != 100 {
		t.Errorf("PID = %d, want 100", out.PID)
	}
	if out.Shown != 3 {
		t.Errorf("Shown = %d, want 3", out.Shown)
	}
	if out.Total != 3 {
		t.Errorf("Total = %d, want 3", out.Total)
	}
	if len(out.Handles) != 3 {
		t.Errorf("Handles count = %d, want 3", len(out.Handles))
	}
}

func TestFormatHandleResultSummarySortedByCount(t *testing.T) {
	typeCounts := map[string]int{
		"File":    5,
		"Socket":  10,
		"Pipe":    1,
		"Event":   3,
	}

	result := formatHandleResult(nil, typeCounts, handlesArgs{PID: 1}, 19)

	var out struct {
		Summary []handleTypeCount `json:"summary"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if len(out.Summary) != 4 {
		t.Fatalf("expected 4 summary entries, got %d", len(out.Summary))
	}

	// Should be sorted descending by count
	for i := 1; i < len(out.Summary); i++ {
		if out.Summary[i].Count > out.Summary[i-1].Count {
			t.Errorf("summary not sorted: [%d]=%d > [%d]=%d",
				i, out.Summary[i].Count, i-1, out.Summary[i-1].Count)
		}
	}

	// First should be Socket (count 10)
	if out.Summary[0].Type != "Socket" || out.Summary[0].Count != 10 {
		t.Errorf("first summary entry = {%s, %d}, want {Socket, 10}",
			out.Summary[0].Type, out.Summary[0].Count)
	}
}

func TestFormatHandleResultShownVsTotal(t *testing.T) {
	handles := []handleInfo{
		{Handle: 1, TypeName: "File"},
	}
	// Shown is 1 (from handles slice), but total is 50
	result := formatHandleResult(handles, map[string]int{"File": 1}, handlesArgs{PID: 1, MaxCount: 1}, 50)

	var out struct {
		Shown int `json:"shown"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if out.Shown != 1 {
		t.Errorf("Shown = %d, want 1", out.Shown)
	}
	if out.Total != 50 {
		t.Errorf("Total = %d, want 50", out.Total)
	}
}

func TestFormatHandleResultHandleFields(t *testing.T) {
	handles := []handleInfo{
		{Handle: 42, TypeName: "File", Name: "/test/path"},
	}

	result := formatHandleResult(handles, map[string]int{"File": 1}, handlesArgs{PID: 1}, 1)

	var out struct {
		Handles []handleInfo `json:"handles"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	h := out.Handles[0]
	if h.Handle != 42 {
		t.Errorf("Handle = %d, want 42", h.Handle)
	}
	if h.TypeName != "File" {
		t.Errorf("TypeName = %q, want File", h.TypeName)
	}
	if h.Name != "/test/path" {
		t.Errorf("Name = %q, want /test/path", h.Name)
	}
}
