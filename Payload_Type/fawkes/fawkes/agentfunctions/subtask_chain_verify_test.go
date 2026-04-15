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

// TestStealTokenAutoEscalateRegistered verifies steal-token chains.
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

// TestHashdumpAutoSprayRegistered verifies hashdump has the auto-spray action
// and completion functions registered.
func TestHashdumpAutoSprayRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "hashdump" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("hashdump command not found")
	}

	// Check action parameter has auto-spray choice
	foundAutoSpray := false
	foundDump := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, c := range p.Choices {
				if c == "auto-spray" {
					foundAutoSpray = true
				}
				if c == "dump" {
					foundDump = true
				}
			}
		}
	}
	if !foundAutoSpray {
		t.Error("hashdump action parameter missing 'auto-spray' choice")
	}
	if !foundDump {
		t.Error("hashdump action parameter missing 'dump' choice")
	}

	// Check targets parameter exists
	foundTargets := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "targets" {
			foundTargets = true
		}
	}
	if !foundTargets {
		t.Error("hashdump missing 'targets' parameter")
	}

	// Check completion functions
	expectedFuncs := []string{
		"hashdumpDumpDone",
		"hashdumpSprayGroupDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("hashdump missing TaskCompletionFunction %q", name)
		}
	}
}

// TestDcsyncDomainTakeoverRegistered verifies dcsync has the domain-takeover action
// and completion functions registered.
func TestDcsyncDomainTakeoverRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "dcsync" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("dcsync command not found")
	}

	// Check action parameter has domain-takeover choice
	foundAction := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, c := range p.Choices {
				if c == "domain-takeover" {
					foundAction = true
				}
			}
		}
	}
	if !foundAction {
		t.Error("dcsync action parameter missing 'domain-takeover' choice")
	}

	// Check completion functions
	if _, ok := cmd.TaskCompletionFunctions["domainTakeoverDone"]; !ok {
		t.Error("dcsync missing TaskCompletionFunction 'domainTakeoverDone'")
	}
}

// TestPrivescCheckAutoEscalateRegistered verifies privesc-check has the auto-escalate
// action and completion functions registered.
func TestPrivescCheckAutoEscalateRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "privesc-check" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("privesc-check command not found")
	}

	// Check action parameter has auto-escalate choice
	foundAction := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, c := range p.Choices {
				if c == "auto-escalate" {
					foundAction = true
				}
			}
		}
	}
	if !foundAction {
		t.Error("privesc-check action parameter missing 'auto-escalate' choice")
	}

	// Check has completion functions registered
	if len(cmd.TaskCompletionFunctions) == 0 {
		t.Error("privesc-check has no TaskCompletionFunctions registered")
	}
}

// TestFindAdminAutoMoveRegistered verifies find-admin has the auto-move action
// and completion functions registered.
func TestFindAdminAutoMoveRegistered(t *testing.T) {
	commands := agentstructs.AllPayloadData.Get("fawkes").GetCommands()

	var cmd *agentstructs.Command
	for i := range commands {
		if commands[i].Name == "find-admin" {
			cmd = &commands[i]
			break
		}
	}
	if cmd == nil {
		t.Fatal("find-admin command not found")
	}

	// Check action parameter has auto-move choice
	foundAction := false
	for _, p := range cmd.CommandParameters {
		if p.Name == "action" {
			for _, c := range p.Choices {
				if c == "auto-move" {
					foundAction = true
				}
			}
		}
	}
	if !foundAction {
		t.Error("find-admin action parameter missing 'auto-move' choice")
	}

	// Check completion functions
	expectedFuncs := []string{
		"autoMoveFindDone",
		"autoMoveLateralDone",
	}
	for _, name := range expectedFuncs {
		if _, ok := cmd.TaskCompletionFunctions[name]; !ok {
			t.Errorf("find-admin missing TaskCompletionFunction %q", name)
		}
	}
}
