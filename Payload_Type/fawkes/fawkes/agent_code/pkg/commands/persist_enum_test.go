//go:build windows

package commands

import (
	"reflect"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistEnumName(t *testing.T) {
	cmd := &PersistEnumCommand{}
	if cmd.Name() != "persist-enum" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "persist-enum")
	}
}

func TestPersistEnumDescription(t *testing.T) {
	cmd := &PersistEnumCommand{}
	if cmd.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestParseCSVLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple", "a,b,c", []string{"a", "b", "c"}},
		{"quoted", `"hello",world`, []string{"hello", "world"}},
		{"quoted with comma", `"hello, world",test`, []string{"hello, world", "test"}},
		{"empty fields", "a,,c", []string{"a", "", "c"}},
		{"single field", "alone", []string{"alone"}},
		{"empty", "", []string{""}},
		{"trailing comma", "a,b,", []string{"a", "b", ""}},
		{"quoted empty", `"",b`, []string{"", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseCSVLine(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseCSVLine(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestPersistEnumExecute(t *testing.T) {
	cmd := &PersistEnumCommand{}
	task := structs.Task{Params: ""}
	result := cmd.Execute(task)
	if result.Status != "success" {
		t.Errorf("Status = %q, want %q", result.Status, "success")
	}
	if !result.Completed {
		t.Error("Completed should be true")
	}
}
