//go:build linux

package commands

import (
	"encoding/json"
	"os"
	"testing"

	"fawkes/pkg/structs"
)

func TestHandlesCommand_Metadata(t *testing.T) {
	cmd := &HandlesCommand{}
	if cmd.Name() != "handles" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "handles")
	}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestHandlesCommand_NegativePID(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid": -1}`})
	if result.Status != "error" {
		t.Errorf("expected error for negative PID, got %q", result.Status)
	}
}

func TestHandlesCommand_ZeroPIDMeansSelf(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(structs.Task{Params: `{"pid": 0}`})
	if result.Status != "success" {
		t.Errorf("pid 0 should resolve to self, got status %q: %s", result.Status, result.Output)
	}
}

func TestHandlesCommand_InvalidJSON(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(structs.Task{Params: `{bad`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestHandlesCommand_SelfProcess(t *testing.T) {
	cmd := &HandlesCommand{}
	pid := os.Getpid()
	params, _ := json.Marshal(handlesArgs{PID: pid})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	// Parse the JSON output
	var out struct {
		PID     int          `json:"pid"`
		Shown   int          `json:"shown"`
		Total   int          `json:"total"`
		Summary []struct {
			Type  string `json:"type"`
			Count int    `json:"count"`
		} `json:"summary"`
		Handles []handleInfo `json:"handles"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	if out.PID != pid {
		t.Errorf("PID = %d, want %d", out.PID, pid)
	}
	if out.Shown == 0 {
		t.Error("expected at least one handle for self process")
	}
	if len(out.Handles) == 0 {
		t.Error("expected at least one handle entry")
	}
}

func TestHandlesCommand_TypeFilter(t *testing.T) {
	cmd := &HandlesCommand{}
	pid := os.Getpid()
	params, _ := json.Marshal(handlesArgs{PID: pid, TypeName: "file"})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	var out struct {
		Handles []handleInfo `json:"handles"`
	}
	if err := json.Unmarshal([]byte(result.Output), &out); err != nil {
		t.Fatalf("failed to parse output JSON: %v", err)
	}

	for _, h := range out.Handles {
		if h.TypeName != "file" {
			t.Errorf("type filter not applied: got type %q", h.TypeName)
		}
	}
}

func TestHandlesCommand_NonexistentPID(t *testing.T) {
	cmd := &HandlesCommand{}
	params, _ := json.Marshal(handlesArgs{PID: 999999999})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent PID, got %q", result.Status)
	}
}

func TestClassifyFDTarget(t *testing.T) {
	tests := []struct {
		target   string
		expected string
	}{
		{"socket:[12345]", "socket"},
		{"pipe:[67890]", "pipe"},
		{"anon_inode:[eventfd]", "eventfd"},
		{"anon_inode:[eventpoll]", "eventpoll"},
		{"anon_inode:[timerfd]", "timerfd"},
		{"anon_inode:[inotify]", "inotify"},
		{"anon_inode:", "anon_inode"},
		{"/dev/null", "device"},
		{"/dev/zero", "device"},
		{"/dev/urandom", "device"},
		{"/dev/random", "device"},
		{"/dev/pts/0", "tty"},
		{"/dev/tty1", "tty"},
		{"/dev/sda", "device"},
		{"/home/user/file.txt", "file"},
		{"/proc/self/maps", "file"},
		{"/tmp/test", "file"},
	}

	for _, tt := range tests {
		got := classifyFDTarget(tt.target)
		if got != tt.expected {
			t.Errorf("classifyFDTarget(%q) = %q, want %q", tt.target, got, tt.expected)
		}
	}
}

func TestEnumerateLinuxFDs_Self(t *testing.T) {
	handles, err := enumerateLinuxFDs(os.Getpid(), 100)
	if err != nil {
		t.Fatalf("enumerateLinuxFDs failed: %v", err)
	}

	if len(handles) == 0 {
		t.Fatal("expected at least one fd for self process")
	}

	// FDs should be sorted
	for i := 1; i < len(handles); i++ {
		if handles[i].Handle < handles[i-1].Handle {
			t.Errorf("handles not sorted: fd %d before fd %d", handles[i-1].Handle, handles[i].Handle)
		}
	}

	// Should have stdin/stdout/stderr (0, 1, 2) or at least some known fds
	foundFD := false
	for _, h := range handles {
		if h.Handle >= 0 {
			foundFD = true
			break
		}
	}
	if !foundFD {
		t.Error("expected at least one valid fd number")
	}
}

func TestEnumerateLinuxFDs_MaxCount(t *testing.T) {
	handles, err := enumerateLinuxFDs(os.Getpid(), 2)
	if err != nil {
		t.Fatalf("enumerateLinuxFDs failed: %v", err)
	}

	if len(handles) > 2 {
		t.Errorf("expected at most 2 handles, got %d", len(handles))
	}
}

func TestHandlesArgs_Unmarshal(t *testing.T) {
	input := `{"pid": 1234, "type": "File", "max_count": 100, "show_names": true}`
	var args handlesArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.PID != 1234 {
		t.Errorf("PID = %d, want 1234", args.PID)
	}
	if args.TypeName != "File" {
		t.Errorf("TypeName = %q, want %q", args.TypeName, "File")
	}
	if args.MaxCount != 100 {
		t.Errorf("MaxCount = %d, want 100", args.MaxCount)
	}
	if !args.ShowNames {
		t.Error("ShowNames = false, want true")
	}
}
