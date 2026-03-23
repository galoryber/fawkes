//go:build !windows
// +build !windows

package commands

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestXattrCommandName(t *testing.T) {
	cmd := &XattrCommand{}
	if cmd.Name() != "xattr" {
		t.Errorf("expected 'xattr', got '%s'", cmd.Name())
	}
}

func TestXattrEmptyParams(t *testing.T) {
	cmd := &XattrCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestXattrMissingPath(t *testing.T) {
	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "list"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestXattrNonexistentFile(t *testing.T) {
	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "list", Path: "/nonexistent/file/path"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent file, got %s", result.Status)
	}
}

func TestXattrListEmpty(t *testing.T) {
	// Create temp file
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "list", Path: f.Name()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "no extended attributes") {
		t.Errorf("expected 'no extended attributes', got: %s", result.Output)
	}
}

func TestXattrSetGetDelete(t *testing.T) {
	if runtime.GOOS == "darwin" {
		// macOS may require special prefix; skip if it fails
		t.Log("Testing on macOS — xattr name prefixes may differ")
	}

	// Create temp file
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}

	// Set attribute
	setParams, _ := json.Marshal(xattrArgs{
		Action: "set",
		Path:   f.Name(),
		Name:   "user.test",
		Value:  "hello world",
	})
	result := cmd.Execute(structs.Task{Params: string(setParams)})
	if result.Status != "success" {
		t.Skipf("xattr set failed (filesystem may not support xattrs): %s", result.Output)
	}
	if !strings.Contains(result.Output, "Set xattr") {
		t.Errorf("expected 'Set xattr' in output, got: %s", result.Output)
	}

	// Get attribute
	getParams, _ := json.Marshal(xattrArgs{
		Action: "get",
		Path:   f.Name(),
		Name:   "user.test",
	})
	result = cmd.Execute(structs.Task{Params: string(getParams)})
	if result.Status != "success" {
		t.Errorf("expected success on get, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "hello world") {
		t.Errorf("expected 'hello world' in output, got: %s", result.Output)
	}

	// List attributes
	listParams, _ := json.Marshal(xattrArgs{Action: "list", Path: f.Name()})
	result = cmd.Execute(structs.Task{Params: string(listParams)})
	if result.Status != "success" {
		t.Errorf("expected success on list, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "user.test") {
		t.Errorf("expected 'user.test' in list, got: %s", result.Output)
	}

	// Delete attribute
	delParams, _ := json.Marshal(xattrArgs{
		Action: "delete",
		Path:   f.Name(),
		Name:   "user.test",
	})
	result = cmd.Execute(structs.Task{Params: string(delParams)})
	if result.Status != "success" {
		t.Errorf("expected success on delete, got %s: %s", result.Status, result.Output)
	}

	// Verify deleted
	result = cmd.Execute(structs.Task{Params: string(listParams)})
	if !strings.Contains(result.Output, "no extended attributes") {
		t.Errorf("expected no attrs after delete, got: %s", result.Output)
	}
}

func TestXattrSetHex(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_hex_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	setParams, _ := json.Marshal(xattrArgs{
		Action: "set",
		Path:   f.Name(),
		Name:   "user.bindata",
		Value:  "48656c6c6f", // "Hello" in hex
		Hex:    true,
	})
	result := cmd.Execute(structs.Task{Params: string(setParams)})
	if result.Status != "success" {
		t.Skipf("xattr set failed (filesystem may not support xattrs): %s", result.Output)
	}

	// Get without hex
	getParams, _ := json.Marshal(xattrArgs{
		Action: "get",
		Path:   f.Name(),
		Name:   "user.bindata",
	})
	result = cmd.Execute(structs.Task{Params: string(getParams)})
	if result.Status != "success" {
		t.Errorf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Hello") {
		t.Errorf("expected 'Hello' in output, got: %s", result.Output)
	}
}

func TestXattrGetMissingName(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "get", Path: f.Name()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error when name missing, got %s", result.Status)
	}
}

func TestXattrUnknownAction(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "invalid", Path: f.Name()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
}

// --- Non-JSON parameter parsing tests ---

func TestXattrPlainTextListAction(t *testing.T) {
	// Non-JSON params: "list /path" should parse as action=list, path=/path
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	result := cmd.Execute(structs.Task{Params: "list " + f.Name()})
	if result.Status != "success" {
		t.Errorf("expected success for plain text 'list path', got %s: %s", result.Status, result.Output)
	}
}

func TestXattrPlainTextPathOnly(t *testing.T) {
	// Single token (just a path) should default to list action
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	result := cmd.Execute(structs.Task{Params: f.Name()})
	if result.Status != "success" {
		t.Errorf("expected success for single path param, got %s: %s", result.Status, result.Output)
	}
}

func TestXattrPlainTextSetAction(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	// "set /path user.test myvalue" parsed as action=set, path=f.Name(), name=user.test, value=myvalue
	result := cmd.Execute(structs.Task{Params: "set " + f.Name() + " user.test myvalue"})
	// May succeed or fail depending on xattr support
	if result.Status != "success" && result.Status != "error" {
		t.Errorf("unexpected status: %s", result.Status)
	}
}

func TestXattrDeleteMissingName(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "delete", Path: f.Name()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error when name missing for delete, got %s", result.Status)
	}
}

func TestXattrSetMissingName(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "set", Path: f.Name(), Value: "test"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error when name missing for set, got %s", result.Status)
	}
}

func TestXattrSetHexInvalid(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "set", Path: f.Name(), Name: "user.test", Value: "not-valid-hex!", Hex: true})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for invalid hex value, got %s", result.Status)
	}
}

func TestXattrGetNonexistentAttr(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "get", Path: f.Name(), Name: "user.nonexistent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for nonexistent attr, got %s", result.Status)
	}
}

func TestXattrDeleteNonexistentAttr(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "delete", Path: f.Name(), Name: "user.nonexistent"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for deleting nonexistent attr, got %s", result.Status)
	}
}

func TestXattrActionCaseInsensitive(t *testing.T) {
	f, err := os.CreateTemp("", "xattr_test_*")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(f.Name())
	f.Close()

	cmd := &XattrCommand{}
	params, _ := json.Marshal(xattrArgs{Action: "LIST", Path: f.Name()})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Errorf("expected success for uppercase LIST action, got %s: %s", result.Status, result.Output)
	}
}
