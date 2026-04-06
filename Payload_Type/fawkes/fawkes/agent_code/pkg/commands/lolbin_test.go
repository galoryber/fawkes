//go:build linux || darwin
// +build linux darwin

package commands

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"testing"

	"fawkes/pkg/structs"
)

func TestLolbinCommand_Name(t *testing.T) {
	cmd := &LolbinCommand{}
	if cmd.Name() != "lolbin" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "lolbin")
	}
}

func TestLolbinCommand_Description(t *testing.T) {
	cmd := &LolbinCommand{}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestLolbinCommand_EmptyAction(t *testing.T) {
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for empty action, got status=%s", result.Status)
	}
}

func TestLolbinCommand_UnknownAction(t *testing.T) {
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "nonexistent"}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for unknown action, got status=%s", result.Status)
	}
}

func TestLolbinCommand_InvalidJSON(t *testing.T) {
	cmd := &LolbinCommand{}
	task := structs.Task{Params: "not json"}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for invalid JSON, got status=%s", result.Status)
	}
}

func TestLolbinCommand_PythonMissingCode(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-Unix platform")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "python", Path: "", Args: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	// Either error (no python) or error (no code provided)
	if result.Status != "error" {
		t.Errorf("Expected error for python with no code, got status=%s", result.Status)
	}
}

func TestLolbinCommand_PythonInlineExecution(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-Unix platform")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		if _, err := exec.LookPath("python"); err != nil {
			t.Skip("python3/python not available")
		}
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "python", Path: "print('hello lolbin test')"}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got status=%s output=%s", result.Status, result.Output)
	}
	if result.Output == "" {
		t.Error("Expected non-empty output from python")
	}
}

func TestLolbinCommand_CurlMissingURL(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-Unix platform")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "curl", Path: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for curl with no URL, got status=%s", result.Status)
	}
}

func TestLolbinCommand_AwkMissingProgram(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-Unix platform")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "awk", Path: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for awk with no program, got status=%s", result.Status)
	}
}

func TestLolbinCommand_AwkExecution(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("Skipping on non-Unix platform")
	}
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("awk not available")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "awk", Path: `BEGIN{print "awk test"}`}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Expected success, got status=%s output=%s", result.Status, result.Output)
	}
}

func TestFindBinary(t *testing.T) {
	// Test with a binary that definitely exists
	path := findBinary("sh", "bash")
	if path == "" {
		t.Error("findBinary should find sh or bash")
	}

	// Test with a binary that doesn't exist
	path = findBinary("totally_nonexistent_binary_xyz")
	if path != "" {
		t.Errorf("findBinary should return empty for nonexistent binary, got %q", path)
	}
}

func TestLolbinCommand_GCCMissingCode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GCC test only on Linux")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "gcc", Path: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for gcc with no code, got status=%s", result.Status)
	}
}

func TestLolbinCommand_PerlMissingCode(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Perl test only on Linux")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "perl", Path: "", Args: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for perl with no code, got status=%s", result.Status)
	}
}

func TestLolbinCommand_WgetMissingURL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Wget test only on Linux")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "wget", Path: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for wget with no URL, got status=%s", result.Status)
	}
}

func TestLolbinCommand_OsascriptDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("osascript only on macOS")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "osascript", Path: "", Args: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for osascript with no code, got status=%s", result.Status)
	}
}

func TestLolbinCommand_SwiftDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("swift only on macOS")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "swift", Path: "", Args: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for swift with no code, got status=%s", result.Status)
	}
}

func TestLolbinCommand_OpenDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("open only on macOS")
	}
	cmd := &LolbinCommand{}
	args := lolbinArgs{Action: "open", Path: ""}
	params, _ := json.Marshal(args)
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if result.Status != "error" {
		t.Errorf("Expected error for open with no app, got status=%s", result.Status)
	}
}
