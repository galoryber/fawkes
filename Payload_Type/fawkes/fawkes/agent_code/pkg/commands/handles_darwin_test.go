//go:build darwin

package commands

import (
	"encoding/json"
	"os"
	"testing"

	"fawkes/pkg/structs"
)

func TestHandlesCommand_Metadata_Darwin(t *testing.T) {
	cmd := &HandlesCommand{}
	if cmd.Name() != "handles" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "handles")
	}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestHandlesCommand_NoPID_Darwin(t *testing.T) {
	cmd := &HandlesCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "error" {
		t.Errorf("expected error for missing PID, got %q", result.Status)
	}
}

func TestHandlesCommand_SelfProcess_Darwin(t *testing.T) {
	cmd := &HandlesCommand{}
	pid := os.Getpid()
	params, _ := json.Marshal(handlesArgs{PID: pid})
	result := cmd.Execute(structs.Task{Params: string(params)})

	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}

	var out struct {
		PID     int          `json:"pid"`
		Shown   int          `json:"shown"`
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
}

func TestParseLsofOutput(t *testing.T) {
	// Sample lsof -F ftn output
	input := `p1234
fcwd
tDIR
n/home/user
f0
tCHR
n/dev/null
f3
tREG
n/tmp/test.txt
f4
tunix
n/var/run/test.sock
f5
tPIPE
n
f6
tIPv4
n192.168.1.1:8080
`

	handles := parseLsofOutput(input, 100)

	if len(handles) != 6 {
		t.Fatalf("expected 6 handles, got %d", len(handles))
	}

	// cwd entry
	if handles[0].Handle != -1 || handles[0].TypeName != "cwd" {
		t.Errorf("cwd entry: handle=%d type=%q", handles[0].Handle, handles[0].TypeName)
	}

	// fd 0 - /dev/null
	if handles[1].Handle != 0 || handles[1].TypeName != "device" {
		t.Errorf("fd 0: handle=%d type=%q", handles[1].Handle, handles[1].TypeName)
	}

	// fd 3 - regular file
	if handles[2].Handle != 3 || handles[2].TypeName != "file" || handles[2].Name != "/tmp/test.txt" {
		t.Errorf("fd 3: handle=%d type=%q name=%q", handles[2].Handle, handles[2].TypeName, handles[2].Name)
	}

	// fd 4 - unix socket
	if handles[3].Handle != 4 || handles[3].TypeName != "socket" {
		t.Errorf("fd 4: handle=%d type=%q", handles[3].Handle, handles[3].TypeName)
	}

	// fd 5 - pipe
	if handles[4].Handle != 5 || handles[4].TypeName != "pipe" {
		t.Errorf("fd 5: handle=%d type=%q", handles[4].Handle, handles[4].TypeName)
	}

	// fd 6 - IPv4 socket
	if handles[5].Handle != 6 || handles[5].TypeName != "socket" {
		t.Errorf("fd 6: handle=%d type=%q", handles[5].Handle, handles[5].TypeName)
	}
}

func TestParseLsofOutput_MaxCount(t *testing.T) {
	input := `p1234
f0
tREG
n/file1
f1
tREG
n/file2
f2
tREG
n/file3
`
	handles := parseLsofOutput(input, 2)
	if len(handles) != 2 {
		t.Errorf("expected 2 handles with maxCount=2, got %d", len(handles))
	}
}

func TestParseLsofOutput_Empty(t *testing.T) {
	handles := parseLsofOutput("", 100)
	if len(handles) != 0 {
		t.Errorf("expected 0 handles for empty input, got %d", len(handles))
	}
}

func TestMapLsofType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"REG", "file"},
		{"DIR", "directory"},
		{"CHR", "device"},
		{"PIPE", "pipe"},
		{"FIFO", "pipe"},
		{"unix", "socket"},
		{"IPv4", "socket"},
		{"IPv6", "socket"},
		{"KQUEUE", "kqueue"},
		{"systm", "system"},
		{"PSXSHM", "shared_memory"},
		{"", "unknown"},
		{"CUSTOM", "custom"},
	}

	for _, tt := range tests {
		got := mapLsofType(tt.input)
		if got != tt.expected {
			t.Errorf("mapLsofType(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}
