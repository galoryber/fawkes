//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestNetEnumSessionsEmptyTarget(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "sessions"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestNetEnumSessionsRemoteTarget(t *testing.T) {
	cmd := &NetEnumCommand{}
	params, _ := json.Marshal(netEnumArgs{Action: "sessions", Target: "127.0.0.1"})
	task := structs.Task{Params: string(params)}
	result := cmd.Execute(task)
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestNeFormatDuration(t *testing.T) {
	tests := []struct {
		seconds  uint32
		expected string
	}{
		{0, "0s"},
		{30, "30s"},
		{59, "59s"},
		{60, "1m0s"},
		{90, "1m30s"},
		{3600, "1h0m"},
		{3661, "1h1m"},
		{7200, "2h0m"},
	}
	for _, tt := range tests {
		result := neFormatDuration(tt.seconds)
		if result != tt.expected {
			t.Errorf("neFormatDuration(%d) = %s, want %s", tt.seconds, result, tt.expected)
		}
	}
}
