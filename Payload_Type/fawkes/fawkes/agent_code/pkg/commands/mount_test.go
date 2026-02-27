package commands

import (
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestMountBasic(t *testing.T) {
	cmd := &MountCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "mount points") {
		t.Fatalf("expected mount points header, got: %s", result.Output)
	}
}

func TestMountHasEntries(t *testing.T) {
	cmd := &MountCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Device") {
		t.Fatalf("expected Device header, got: %s", result.Output)
	}
	if !strings.Contains(result.Output, "Type") {
		t.Fatalf("expected Type header, got: %s", result.Output)
	}
}

func TestMountHasRootFS(t *testing.T) {
	cmd := &MountCommand{}
	result := cmd.Execute(structs.Task{Params: ""})

	if result.Status != "success" {
		t.Fatalf("expected success, got %s: %s", result.Status, result.Output)
	}
	// Linux should have / mount, Windows should have C:\
	lines := strings.Split(result.Output, "\n")
	found := false
	for _, line := range lines {
		if strings.Contains(line, "/") || strings.Contains(line, "C:\\") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected root filesystem, got: %s", result.Output)
	}
}
