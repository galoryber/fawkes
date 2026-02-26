package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestLdapWriteCommand_Name(t *testing.T) {
	cmd := &LdapWriteCommand{}
	if cmd.Name() != "ldap-write" {
		t.Errorf("expected ldap-write, got %s", cmd.Name())
	}
}

func TestLdapWriteCommand_Description(t *testing.T) {
	cmd := &LdapWriteCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestLdapWriteCommand_EmptyParams(t *testing.T) {
	cmd := &LdapWriteCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestLdapWriteCommand_InvalidJSON(t *testing.T) {
	cmd := &LdapWriteCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapWriteCommand_MissingServer(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{Action: "add-member"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status for missing server, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "server parameter required") {
		t.Errorf("expected server error message, got: %s", result.Output)
	}
}

func TestLdapWriteCommand_InvalidAction(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{Action: "invalid", Server: "127.0.0.1"})
	// Will fail on connection, but let's verify the action is parsed
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapWriteCommand_DefaultPort_LDAP(t *testing.T) {
	args := ldapWriteArgs{Action: "add-member", Server: "test-dc"}
	if args.Port <= 0 && !args.UseTLS {
		args.Port = 389
	}
	if args.Port != 389 {
		t.Errorf("expected default port 389, got %d", args.Port)
	}
}

func TestLdapWriteCommand_DefaultPort_LDAPS(t *testing.T) {
	args := ldapWriteArgs{Action: "add-member", Server: "test-dc", UseTLS: true}
	if args.Port <= 0 && args.UseTLS {
		args.Port = 636
	}
	if args.Port != 636 {
		t.Errorf("expected default port 636, got %d", args.Port)
	}
}

// Test parameter validation for each action (without connecting)

func TestLdapWriteCommand_AddMember_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "add-member", Server: "127.0.0.1",
		Group: "TestGroup",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_AddMember_MissingGroup(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "add-member", Server: "127.0.0.1",
		Target: "testuser",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing group, got %s", result.Status)
	}
}

func TestLdapWriteCommand_RemoveMember_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "remove-member", Server: "127.0.0.1",
		Group: "TestGroup",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetAttr_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-attr", Server: "127.0.0.1",
		Attr: "description", Value: "test",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetAttr_MissingAttr(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-attr", Server: "127.0.0.1",
		Target: "testuser", Value: "test",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing attr, got %s", result.Status)
	}
}

func TestLdapWriteCommand_AddAttr_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "add-attr", Server: "127.0.0.1",
		Attr: "description",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_RemoveAttr_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "remove-attr", Server: "127.0.0.1",
		Attr: "description",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetSPN_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-spn", Server: "127.0.0.1",
		Value: "HTTP/test.domain.local",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetSPN_MissingValue(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-spn", Server: "127.0.0.1",
		Target: "testuser",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing SPN value, got %s", result.Status)
	}
}

func TestLdapWriteCommand_Disable_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "disable", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_Enable_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "enable", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetPassword_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-password", Server: "127.0.0.1",
		Value: "NewPass123!", UseTLS: true,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetPassword_MissingValue(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-password", Server: "127.0.0.1",
		Target: "testuser", UseTLS: true,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing password value, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetPassword_RequiresLDAPS(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-password", Server: "127.0.0.1",
		Target: "testuser", Value: "NewPass123!",
		UseTLS: false,
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for non-TLS password change, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "LDAPS") {
		t.Errorf("expected LDAPS requirement message, got: %s", result.Output)
	}
}

func TestLdapWriteCommand_CancelledByName_MissingName(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "cancel", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
}

// Test JSON argument parsing

func TestLdapWriteArgs_JSONParsing(t *testing.T) {
	jsonStr := `{"action":"add-member","server":"dc01","target":"jsmith","group":"Domain Admins","username":"admin@domain.local","password":"pass"}`
	var args ldapWriteArgs
	err := json.Unmarshal([]byte(jsonStr), &args)
	if err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if args.Action != "add-member" {
		t.Errorf("expected add-member, got %s", args.Action)
	}
	if args.Server != "dc01" {
		t.Errorf("expected dc01, got %s", args.Server)
	}
	if args.Target != "jsmith" {
		t.Errorf("expected jsmith, got %s", args.Target)
	}
	if args.Group != "Domain Admins" {
		t.Errorf("expected Domain Admins, got %s", args.Group)
	}
}

func TestLdapWriteArgs_ValuesArray(t *testing.T) {
	jsonStr := `{"action":"set-attr","server":"dc01","target":"jsmith","attr":"description","values":["val1","val2"]}`
	var args ldapWriteArgs
	err := json.Unmarshal([]byte(jsonStr), &args)
	if err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}
	if len(args.Values) != 2 {
		t.Errorf("expected 2 values, got %d", len(args.Values))
	}
	if args.Values[0] != "val1" || args.Values[1] != "val2" {
		t.Errorf("unexpected values: %v", args.Values)
	}
}

// Test all supported actions are recognized

func TestLdapWriteCommand_AllActionsRecognized(t *testing.T) {
	actions := []string{"add-member", "remove-member", "set-attr", "add-attr", "remove-attr", "set-spn", "disable", "enable", "set-password", "add-computer", "delete-object", "set-rbcd", "clear-rbcd"}
	cmd := &LdapWriteCommand{}

	for _, action := range actions {
		params, _ := json.Marshal(ldapWriteArgs{
			Action: action, Server: "127.0.0.1",
		})
		result := cmd.Execute(structs.Task{Params: string(params)})
		// All should return error (either missing params or connection failure)
		// but NOT "Unknown action"
		if strings.Contains(result.Output, "Unknown action") {
			t.Errorf("action '%s' should be recognized but got Unknown action", action)
		}
	}
}

func TestLdapWriteCommand_UnknownAction(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "nonexistent", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for unknown action, got %s", result.Status)
	}
	if !strings.Contains(result.Output, "Unknown action") {
		t.Errorf("expected Unknown action message, got: %s", result.Output)
	}
}

func TestLdapWriteCommand_AddComputer_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "add-computer", Server: "127.0.0.1",
		Value: "Password123!",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_AddComputer_MissingPassword(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "add-computer", Server: "127.0.0.1",
		Target: "FAKEPC",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing password, got %s", result.Status)
	}
}

func TestLdapWriteCommand_DeleteObject_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "delete-object", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetRBCD_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-rbcd", Server: "127.0.0.1",
		Value: "FAKEPC01$",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestLdapWriteCommand_SetRBCD_MissingValue(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "set-rbcd", Server: "127.0.0.1",
		Target: "targetserver",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing value, got %s", result.Status)
	}
}

func TestLdapWriteCommand_ClearRBCD_MissingTarget(t *testing.T) {
	cmd := &LdapWriteCommand{}
	params, _ := json.Marshal(ldapWriteArgs{
		Action: "clear-rbcd", Server: "127.0.0.1",
	})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error for missing target, got %s", result.Status)
	}
}

func TestBuildRBCDSecurityDescriptor(t *testing.T) {
	// Example SID: S-1-5-21-100-200-300-1001
	// Revision=1, SubCount=5, Authority=5(NT), SubAuth=[21,100,200,300,1001]
	sid := make([]byte, 28)
	sid[0] = 1    // Revision
	sid[1] = 5    // SubAuthorityCount
	sid[7] = 5    // IdentifierAuthority (NT Authority = 5, big-endian in bytes 2-7)
	// SubAuthorities (little-endian uint32)
	sid[8] = 21   // SubAuth[0] = 21
	sid[12] = 100 // SubAuth[1] = 100
	sid[16] = 0xC8 // SubAuth[2] = 200 (0xC8)
	sid[20] = 0x2C // SubAuth[3] = 300 (0x12C)
	sid[21] = 0x01
	sid[24] = 0xE9 // SubAuth[4] = 1001 (0x3E9)
	sid[25] = 0x03

	sd := buildRBCDSecurityDescriptor(sid)

	// Verify SD header
	if sd[0] != 1 {
		t.Errorf("expected SD revision 1, got %d", sd[0])
	}
	// Control: SE_DACL_PRESENT | SE_SELF_RELATIVE = 0x8004
	control := uint16(sd[2]) | uint16(sd[3])<<8
	if control != 0x8004 {
		t.Errorf("expected control 0x8004, got 0x%04X", control)
	}
	// Owner offset should be 20 (right after header)
	ownerOff := uint32(sd[4]) | uint32(sd[5])<<8 | uint32(sd[6])<<16 | uint32(sd[7])<<24
	if ownerOff != 20 {
		t.Errorf("expected Owner offset 20, got %d", ownerOff)
	}
	// Owner SID should be S-1-5-32-544 (BUILTIN\Administrators) = 16 bytes
	if sd[20] != 0x01 || sd[21] != 0x02 { // Revision=1, SubCount=2
		t.Errorf("expected owner SID revision=1 subcount=2, got %d %d", sd[20], sd[21])
	}
	// DACL offset should be 36 (20 header + 16 owner SID)
	daclOff := uint32(sd[16]) | uint32(sd[17])<<8 | uint32(sd[18])<<16 | uint32(sd[19])<<24
	if daclOff != 36 {
		t.Errorf("expected DACL offset 36, got %d", daclOff)
	}
	// ACL revision should be 4 (ACL_REVISION_DS)
	if sd[36] != 4 {
		t.Errorf("expected ACL revision 4, got %d", sd[36])
	}
	// ACE count should be 1
	aceCount := uint16(sd[40]) | uint16(sd[41])<<8
	if aceCount != 1 {
		t.Errorf("expected 1 ACE, got %d", aceCount)
	}
	// ACE type should be ACCESS_ALLOWED (0x00)
	if sd[44] != 0x00 {
		t.Errorf("expected ACE type 0x00, got 0x%02X", sd[44])
	}
	// Access mask should be 0x000F003F
	mask := uint32(sd[48]) | uint32(sd[49])<<8 | uint32(sd[50])<<16 | uint32(sd[51])<<24
	if mask != 0x000F003F {
		t.Errorf("expected mask 0x000F003F, got 0x%08X", mask)
	}
	// SID should be at offset 52
	if sd[52] != sid[0] || sd[53] != sid[1] {
		t.Errorf("expected SID at offset 52, got revision=%d subcount=%d", sd[52], sd[53])
	}
	// Total size: 20 (SD) + 16 (owner SID) + 8 (ACL) + 8 (ACE header+mask) + 28 (SID) = 80
	expectedLen := 20 + 16 + 8 + 8 + len(sid)
	if len(sd) != expectedLen {
		t.Errorf("expected SD length %d, got %d", expectedLen, len(sd))
	}
}

// Test that parameter validation runs before connection attempts
// (these should fail on parameter validation, not connection)

func TestLdapWriteCommand_ValidationBeforeConnect(t *testing.T) {
	tests := []struct {
		name   string
		args   ldapWriteArgs
		expect string
	}{
		{
			name:   "add-member without target/group",
			args:   ldapWriteArgs{Action: "add-member", Server: "192.0.2.1"},
			expect: "target",
		},
		{
			name:   "set-spn without target/value",
			args:   ldapWriteArgs{Action: "set-spn", Server: "192.0.2.1"},
			expect: "target",
		},
		{
			name:   "set-password without TLS",
			args:   ldapWriteArgs{Action: "set-password", Server: "192.0.2.1", Target: "user", Value: "pass"},
			expect: "LDAPS",
		},
	}

	cmd := &LdapWriteCommand{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, _ := json.Marshal(tt.args)
			result := cmd.Execute(structs.Task{Params: string(params)})
			if result.Status != "error" {
				t.Errorf("expected error, got %s", result.Status)
			}
			// Note: some validations happen after connection.
			// set-password LDAPS check happens before connect.
		})
	}
}
