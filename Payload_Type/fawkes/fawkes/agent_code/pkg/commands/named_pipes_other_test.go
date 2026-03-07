//go:build !windows

package commands

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestNamedPipesCommandMetadata(t *testing.T) {
	c := &NamedPipesCommand{}
	if c.Name() != "named-pipes" {
		t.Errorf("Name() = %q, want %q", c.Name(), "named-pipes")
	}
	if c.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestNamedPipesExecuteEmptyParams(t *testing.T) {
	c := &NamedPipesCommand{}
	result := c.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !strings.Contains(result.Output, "Unix domain sockets:") {
		t.Errorf("Output missing 'Unix domain sockets:', got: %s", result.Output[:min(len(result.Output), 200)])
	}
}

func TestNamedPipesExecuteWithFilter(t *testing.T) {
	c := &NamedPipesCommand{}
	params, _ := json.Marshal(namedPipesArgs{Filter: "docker"})
	result := c.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !strings.Contains(result.Output, "Filter: docker") {
		t.Errorf("Output missing filter info, got: %s", result.Output[:min(len(result.Output), 200)])
	}
}

func TestNamedPipesExecuteInvalidJSON(t *testing.T) {
	c := &NamedPipesCommand{}
	result := c.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("Expected error for invalid JSON, got status %q", result.Status)
	}
}

func TestFilterEntries(t *testing.T) {
	entries := []string{"/var/run/docker.sock", "/tmp/mysql.sock", "/var/run/dbus/system_bus_socket"}

	tests := []struct {
		name     string
		filter   string
		expected int
	}{
		{"match docker", "docker", 1},
		{"match sock", "sock", 3},
		{"no match", "nonexistent", 0},
		{"case insensitive", "DOCKER", 1},
		{"partial match", "dbus", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := filterEntries(entries, tt.filter)
			if len(result) != tt.expected {
				t.Errorf("filterEntries(filter=%q) returned %d entries, want %d", tt.filter, len(result), tt.expected)
			}
		})
	}
}

func TestFilterEntriesEmpty(t *testing.T) {
	result := filterEntries(nil, "test")
	if len(result) != 0 {
		t.Errorf("expected 0 entries for nil input, got %d", len(result))
	}
}

func TestEnumerateUnixSockets(t *testing.T) {
	sockets, err := enumerateUnixSockets()
	if err != nil {
		t.Fatalf("enumerateUnixSockets() error: %v", err)
	}
	// On any Linux/macOS system there should be at least a few sockets
	if runtime.GOOS == "linux" && len(sockets) == 0 {
		t.Log("Warning: no Unix sockets found on Linux (expected some)")
	}
}

func TestEnumerateUnixSocketsLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only test")
	}
	sockets, err := enumerateUnixSocketsLinux()
	if err != nil {
		t.Fatalf("enumerateUnixSocketsLinux() error: %v", err)
	}
	// /proc/net/unix should have entries on any running Linux system
	if len(sockets) == 0 {
		t.Log("Warning: no sockets found in /proc/net/unix")
	}
	// Check for common system sockets
	hasSystemSocket := false
	for _, s := range sockets {
		if strings.Contains(s, "dbus") || strings.Contains(s, "systemd") || strings.Contains(s, "run") {
			hasSystemSocket = true
			break
		}
	}
	if !hasSystemSocket {
		t.Log("Warning: no common system sockets (dbus/systemd) found")
	}
}

func TestEnumerateFIFOs(t *testing.T) {
	// Just verify it doesn't crash — FIFOs may or may not exist
	fifos := enumerateFIFOs()
	_ = fifos // result is system-dependent
}

func TestNamedPipesArgsUnmarshal(t *testing.T) {
	var args namedPipesArgs
	err := json.Unmarshal([]byte(`{"filter":"test"}`), &args)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if args.Filter != "test" {
		t.Errorf("Filter = %q, want %q", args.Filter, "test")
	}
}

