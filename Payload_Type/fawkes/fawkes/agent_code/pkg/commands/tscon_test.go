//go:build windows
// +build windows

package commands

import (
	"strings"
	"testing"
)

func TestTsconStateName_AllStates(t *testing.T) {
	tests := []struct {
		state uint32
		want  string
	}{
		{tsconStateActive, "Active"},
		{tsconStateConn, "Connected"},
		{tsconStateConnQ, "ConnectQuery"},
		{tsconStateShadow, "Shadow"},
		{tsconStateDisconn, "Disconnected"},
		{tsconStateIdle, "Idle"},
		{tsconStateListen, "Listen"},
		{tsconStateReset, "Reset"},
		{tsconStateDown, "Down"},
		{tsconStateInit, "Init"},
	}

	for _, tt := range tests {
		got := tsconStateName(tt.state)
		if got != tt.want {
			t.Errorf("tsconStateName(%d) = %q, want %q", tt.state, got, tt.want)
		}
	}
}

func TestTsconStateName_Unknown(t *testing.T) {
	got := tsconStateName(99)
	if !strings.HasPrefix(got, "Unknown") {
		t.Errorf("tsconStateName(99) = %q, want prefix \"Unknown\"", got)
	}
}

func TestTsconStateName_CoverAllConstants(t *testing.T) {
	// Verify all constants 0-9 are handled (no gaps)
	for i := uint32(0); i <= 9; i++ {
		got := tsconStateName(i)
		if strings.HasPrefix(got, "Unknown") {
			t.Errorf("tsconStateName(%d) returned Unknown — missing case", i)
		}
	}
}
