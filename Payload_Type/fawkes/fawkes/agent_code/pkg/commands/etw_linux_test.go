//go:build linux
// +build linux

package commands

import (
	"testing"
)

func TestEtwLinux_KnownSIEMAgentList(t *testing.T) {
	if len(knownSIEMAgents) == 0 {
		t.Error("knownSIEMAgents should not be empty")
	}
	for _, agent := range knownSIEMAgents {
		if agent.Name == "" {
			t.Error("Agent name should not be empty")
		}
		if len(agent.ProcessName) == 0 {
			t.Errorf("Agent %q should have at least one process name", agent.Name)
		}
		if len(agent.InstallPath) == 0 {
			t.Errorf("Agent %q should have at least one install path", agent.Name)
		}
	}
}
