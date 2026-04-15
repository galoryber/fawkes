package agentfunctions

import (
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// TestFilterCommandAvailability_SingleOS verifies that all single-OS commands
// have FilterCommandAvailabilityByAgentBuildParameters set to filter by selected_os.
func TestFilterCommandAvailability_SingleOS(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()
	if len(commands) == 0 {
		t.Fatal("No commands registered — init() may not have run")
	}

	for _, cmd := range commands {
		os := cmd.CommandAttributes.SupportedOS
		filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters

		// Skip commands with no OS restriction or multi-OS support
		if len(os) != 1 {
			continue
		}

		expectedOS := os[0]
		t.Run(cmd.Name, func(t *testing.T) {
			if filter == nil {
				t.Errorf("command %q supports only %q but has no FilterCommandAvailabilityByAgentBuildParameters", cmd.Name, expectedOS)
				return
			}
			if got, ok := filter["selected_os"]; !ok {
				t.Errorf("command %q: filter map missing 'selected_os' key", cmd.Name)
			} else if got != expectedOS {
				t.Errorf("command %q: filter selected_os = %q, want %q", cmd.Name, got, expectedOS)
			}
		})
	}
}

// TestFilterCommandAvailability_MultiOS verifies that multi-OS commands do NOT
// have a selected_os filter (which would incorrectly restrict them to one OS).
func TestFilterCommandAvailability_MultiOS(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	for _, cmd := range commands {
		os := cmd.CommandAttributes.SupportedOS
		filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters

		// Only check commands with 2+ OS support
		if len(os) < 2 {
			continue
		}

		t.Run(cmd.Name, func(t *testing.T) {
			if filter != nil {
				if _, hasOS := filter["selected_os"]; hasOS {
					t.Errorf("command %q supports %d OSes but has selected_os filter — would restrict to single OS", cmd.Name, len(os))
				}
			}
		})
	}
}

// TestFilterCommandAvailability_WindowsOnlyCount verifies the expected number
// of Windows-only commands have the filter set.
func TestFilterCommandAvailability_WindowsOnlyCount(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	windowsFiltered := 0
	for _, cmd := range commands {
		filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters
		if filter != nil && filter["selected_os"] == "Windows" {
			windowsFiltered++
		}
	}

	// We added filters to Windows-only commands (count may drift as commands evolve)
	if windowsFiltered < 45 {
		t.Errorf("expected at least 45 Windows-only filtered commands, got %d", windowsFiltered)
	}
}

// TestFilterCommandAvailability_LinuxOnlyCount verifies Linux-only commands.
func TestFilterCommandAvailability_LinuxOnlyCount(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	linuxFiltered := 0
	for _, cmd := range commands {
		filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters
		if filter != nil && filter["selected_os"] == "Linux" {
			linuxFiltered++
		}
	}

	if linuxFiltered < 5 {
		t.Errorf("expected at least 5 Linux-only filtered commands, got %d", linuxFiltered)
	}
}

// TestFilterCommandAvailability_MacOSOnlyCount verifies macOS-only commands.
func TestFilterCommandAvailability_MacOSOnlyCount(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	macFiltered := 0
	for _, cmd := range commands {
		filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters
		if filter != nil && filter["selected_os"] == "macOS" {
			macFiltered++
		}
	}

	if macFiltered < 4 {
		t.Errorf("expected at least 4 macOS-only filtered commands, got %d", macFiltered)
	}
}

// TestFilterCommandAvailability_SpecificCommands checks known commands have the right filter.
func TestFilterCommandAvailability_SpecificCommands(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	cmdMap := make(map[string]agentstructs.Command)
	for _, cmd := range commands {
		cmdMap[cmd.Name] = cmd
	}

	tests := []struct {
		name       string
		expectedOS string
	}{
		// Windows-only
		{"apc-injection", "Windows"},
		{"hollow", "Windows"},
		{"reg", "Windows"},
		{"uac-bypass", "Windows"},
		{"hashdump", ""}, // hashdump is cross-platform, no filter
		// Linux-only
		{"ptrace-inject", "Linux"},
		{"container-escape", "Linux"},
		{"iptables", "Linux"},
		// macOS-only
		{"jxa", "macOS"},
		{"keychain", "macOS"},
		{"tcc-check", "macOS"},
		// Cross-platform (no filter)
		{"ls", ""},
		{"ps", ""},
		{"whoami", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, ok := cmdMap[tt.name]
			if !ok {
				t.Skipf("command %q not registered", tt.name)
				return
			}

			filter := cmd.CommandAttributes.FilterCommandAvailabilityByAgentBuildParameters
			if tt.expectedOS == "" {
				// Should not have a selected_os filter
				if filter != nil {
					if os, has := filter["selected_os"]; has {
						t.Errorf("command %q should not have selected_os filter, got %q", tt.name, os)
					}
				}
			} else {
				if filter == nil {
					t.Errorf("command %q should have selected_os=%q filter, got nil", tt.name, tt.expectedOS)
					return
				}
				if got := filter["selected_os"]; got != tt.expectedOS {
					t.Errorf("command %q selected_os = %q, want %q", tt.name, got, tt.expectedOS)
				}
			}
		})
	}
}
