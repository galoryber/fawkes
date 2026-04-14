package agentfunctions

import (
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// TestMaketokenAutoVerifyRegistered verifies make-token has the auto-verify action
// and completion functions registered.
func TestMaketokenAutoVerifyRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "make-token" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("make-token command not found")
	}

	// Check action parameter has auto-verify choice
	foundAutoVerify := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, c := range p.Choices {
				if c == "auto-verify" {
					foundAutoVerify = true
				}
			}
		}
	}
	if !foundAutoVerify {
		t.Error("make-token action parameter missing 'auto-verify' choice")
	}

	// Check completion functions
	expectedFuncs := []string{
		"maketokenAutoVerifyDone",
		"maketokenAutoWhoamiDone",
		"maketokenAutoGetprivsDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("make-token missing TaskCompletionFunction %q", name)
		}
	}
}

// TestWinrmAutoVerifyRegistered verifies winrm has the auto_verify parameter
// and completion functions registered.
func TestWinrmAutoVerifyRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "winrm" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("winrm command not found")
	}

	// Check auto_verify parameter exists and is boolean
	foundAutoVerify := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "auto_verify" {
			foundAutoVerify = true
			if p.ParameterType != agentstructs.COMMAND_PARAMETER_TYPE_BOOLEAN {
				t.Errorf("auto_verify should be BOOLEAN, got %s", p.ParameterType)
			}
			if p.DefaultValue != false {
				t.Errorf("auto_verify default should be false, got %v", p.DefaultValue)
			}
		}
	}
	if !foundAutoVerify {
		t.Error("winrm missing 'auto_verify' parameter")
	}

	// Check completion functions
	expectedFuncs := []string{
		"winrmAutoVerifyWhoamiDone",
		"winrmAutoVerifyGetprivsDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("winrm missing TaskCompletionFunction %q", name)
		}
	}
}

// TestSysinfoChainActionsRegistered verifies sysinfo has all chain actions.
func TestSysinfoChainActionsRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "sysinfo" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("sysinfo command not found")
	}

	// Check action parameter has expected choices
	expectedActions := []string{"info", "full-profile", "recon-full"}
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, expected := range expectedActions {
				found := false
				for _, c := range p.Choices {
					if c == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("sysinfo action parameter missing choice %q", expected)
				}
			}
		}
	}

	// Check completion functions for full-profile chain
	expectedFuncs := []string{
		"hostProfileSysinfoDone",
		"hostProfilePsDone",
		"hostProfileSecurityDone",
		"hostProfilePrivescDone",
		"hostProfilePersistDone",
		"reconFullDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("sysinfo missing TaskCompletionFunction %q", name)
		}
	}
}

// TestStealthTokenAutoEscalateRegistered verifies steal-token chains.
func TestStealTokenAutoEscalateRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "steal-token" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("steal-token command not found")
	}

	expectedFuncs := []string{
		"autoEscalateEnumDone",
		"autoEscalateStealDone",
		"autoEscalateWhoamiDone",
		"autoEscalateGetprivDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("steal-token missing TaskCompletionFunction %q", name)
		}
	}
}
