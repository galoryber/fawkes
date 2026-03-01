package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestFileAttrCommand_Name(t *testing.T) {
	cmd := &FileAttrCommand{}
	if cmd.Name() != "file-attr" {
		t.Errorf("expected 'file-attr', got '%s'", cmd.Name())
	}
}

func makeFileAttrTask(args fileAttrArgs) structs.Task {
	b, _ := json.Marshal(args)
	return structs.Task{Params: string(b)}
}

func TestFileAttrCommand_EmptyParams(t *testing.T) {
	cmd := &FileAttrCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Error("expected error for empty params")
	}
}

func TestFileAttrCommand_MissingPath(t *testing.T) {
	cmd := &FileAttrCommand{}
	result := cmd.Execute(makeFileAttrTask(fileAttrArgs{}))
	if result.Status != "error" {
		t.Error("expected error for missing path")
	}
}

func TestFileAttrCommand_NonExistentFile(t *testing.T) {
	cmd := &FileAttrCommand{}
	result := cmd.Execute(makeFileAttrTask(fileAttrArgs{Path: "/nonexistent/file"}))
	if result.Status != "error" {
		t.Error("expected error for non-existent file")
	}
}

func TestFileAttrCommand_InvalidJSON(t *testing.T) {
	cmd := &FileAttrCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseAttrChanges_Add(t *testing.T) {
	add, remove, err := parseAttrChanges("+hidden,+readonly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(add) != 2 || add[0] != "hidden" || add[1] != "readonly" {
		t.Errorf("expected [hidden, readonly], got %v", add)
	}
	if len(remove) != 0 {
		t.Errorf("expected no removals, got %v", remove)
	}
}

func TestParseAttrChanges_Remove(t *testing.T) {
	add, remove, err := parseAttrChanges("-hidden,-system")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(add) != 0 {
		t.Errorf("expected no additions, got %v", add)
	}
	if len(remove) != 2 || remove[0] != "hidden" || remove[1] != "system" {
		t.Errorf("expected [hidden, system], got %v", remove)
	}
}

func TestParseAttrChanges_Mixed(t *testing.T) {
	add, remove, err := parseAttrChanges("+immutable,-readonly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(add) != 1 || add[0] != "immutable" {
		t.Errorf("expected [immutable], got %v", add)
	}
	if len(remove) != 1 || remove[0] != "readonly" {
		t.Errorf("expected [readonly], got %v", remove)
	}
}

func TestParseAttrChanges_Invalid(t *testing.T) {
	_, _, err := parseAttrChanges("hidden")
	if err == nil {
		t.Error("expected error for attribute without +/- prefix")
	}
}

func TestParseAttrChanges_Empty(t *testing.T) {
	_, _, err := parseAttrChanges("")
	if err == nil {
		t.Error("expected error for empty string")
	}
}

func TestParseAttrChanges_CaseInsensitive(t *testing.T) {
	add, _, err := parseAttrChanges("+HIDDEN,+ReadOnly")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if add[0] != "hidden" || add[1] != "readonly" {
		t.Errorf("expected lowercase, got %v", add)
	}
}

func TestAttrContains(t *testing.T) {
	slice := []string{"hidden", "readonly", "system"}
	if !attrContains(slice, "hidden") {
		t.Error("expected to find 'hidden'")
	}
	if attrContains(slice, "immutable") {
		t.Error("should not find 'immutable'")
	}
	if attrContains(nil, "hidden") {
		t.Error("nil slice should return false")
	}
}
