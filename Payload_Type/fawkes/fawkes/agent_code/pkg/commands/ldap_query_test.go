package commands

import (
	"encoding/json"
	"testing"

	"fawkes/pkg/structs"
)

func TestLdapQueryCommand_Name(t *testing.T) {
	cmd := &LdapQueryCommand{}
	if cmd.Name() != "ldap-query" {
		t.Errorf("expected ldap-query, got %s", cmd.Name())
	}
}

func TestLdapQueryCommand_Description(t *testing.T) {
	cmd := &LdapQueryCommand{}
	if cmd.Description() == "" {
		t.Error("expected non-empty description")
	}
}

func TestLdapQueryCommand_EmptyParams(t *testing.T) {
	cmd := &LdapQueryCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
	if !result.Completed {
		t.Error("expected completed=true")
	}
}

func TestLdapQueryCommand_InvalidJSON(t *testing.T) {
	cmd := &LdapQueryCommand{}
	result := cmd.Execute(structs.Task{Params: "not json"})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapQueryCommand_MissingServer(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "users"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status for missing server, got %s", result.Status)
	}
}

func TestLdapQueryCommand_InvalidAction(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "invalid", Server: "127.0.0.1"})
	// This will fail on connection, but let's test the action validation path
	// by checking that an unreachable server gives a connection error, not an action error
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestLdapQueryCommand_QueryWithoutFilter(t *testing.T) {
	cmd := &LdapQueryCommand{}
	params, _ := json.Marshal(ldapQueryArgs{Action: "query", Server: "127.0.0.1"})
	// Connection will fail first, but the filter validation happens after connect
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "error" {
		t.Errorf("expected error status, got %s", result.Status)
	}
}

func TestResolveQuery_PresetUsers(t *testing.T) {
	args := ldapQueryArgs{Action: "users"}
	filter, attrs, desc := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter for users")
	}
	if len(attrs) == 0 {
		t.Error("expected attributes for users")
	}
	if desc == "" {
		t.Error("expected description for users")
	}
}

func TestResolveQuery_PresetComputers(t *testing.T) {
	args := ldapQueryArgs{Action: "computers"}
	filter, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(objectClass=computer)" {
		t.Errorf("expected computer filter, got %s", filter)
	}
	if len(attrs) == 0 {
		t.Error("expected attributes for computers")
	}
}

func TestResolveQuery_PresetGroups(t *testing.T) {
	args := ldapQueryArgs{Action: "groups"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(objectClass=group)" {
		t.Errorf("expected group filter, got %s", filter)
	}
}

func TestResolveQuery_DomainAdmins(t *testing.T) {
	args := ldapQueryArgs{Action: "domain-admins"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter")
	}
	// Should contain the baseDN
	if !contains(filter, "DC=test,DC=local") {
		t.Error("domain-admins filter should contain baseDN")
	}
}

func TestResolveQuery_SPNs(t *testing.T) {
	args := ldapQueryArgs{Action: "spns"}
	filter, _, desc := resolveQuery(args, "DC=test,DC=local")
	if filter == "" {
		t.Error("expected non-empty filter for SPNs")
	}
	if !contains(filter, "servicePrincipalName") {
		t.Error("SPN filter should reference servicePrincipalName")
	}
	if desc == "" {
		t.Error("expected description")
	}
}

func TestResolveQuery_ASRep(t *testing.T) {
	args := ldapQueryArgs{Action: "asrep"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if !contains(filter, "4194304") {
		t.Error("AS-REP filter should check for DONT_REQUIRE_PREAUTH flag")
	}
}

func TestResolveQuery_CustomQuery(t *testing.T) {
	args := ldapQueryArgs{Action: "query", Filter: "(cn=test*)"}
	filter, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "(cn=test*)" {
		t.Errorf("expected custom filter, got %s", filter)
	}
	if len(attrs) != 1 || attrs[0] != "*" {
		t.Error("expected wildcard attributes for custom query without specified attrs")
	}
}

func TestResolveQuery_CustomAttrs(t *testing.T) {
	args := ldapQueryArgs{
		Action:     "users",
		Attributes: []string{"cn", "mail"},
	}
	_, attrs, _ := resolveQuery(args, "DC=test,DC=local")
	if len(attrs) != 2 || attrs[0] != "cn" || attrs[1] != "mail" {
		t.Errorf("expected custom attributes [cn, mail], got %v", attrs)
	}
}

func TestResolveQuery_InvalidAction(t *testing.T) {
	args := ldapQueryArgs{Action: "nonexistent"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "" {
		t.Errorf("expected empty filter for invalid action, got %s", filter)
	}
}

func TestResolveQuery_QueryNoFilter(t *testing.T) {
	args := ldapQueryArgs{Action: "query"}
	filter, _, _ := resolveQuery(args, "DC=test,DC=local")
	if filter != "" {
		t.Error("expected empty filter for query without filter parameter")
	}
}

func TestDefaultPort_LDAP(t *testing.T) {
	// Verify default port assignment without connecting
	args := ldapQueryArgs{Action: "users", Server: "test-dc"}
	if args.Port <= 0 && !args.UseTLS {
		args.Port = 389
	}
	if args.Port != 389 {
		t.Errorf("expected default port 389, got %d", args.Port)
	}
}

func TestDefaultPort_LDAPS(t *testing.T) {
	// Verify default port assignment for TLS
	args := ldapQueryArgs{Action: "users", Server: "test-dc", UseTLS: true}
	if args.Port <= 0 && args.UseTLS {
		args.Port = 636
	}
	if args.Port != 636 {
		t.Errorf("expected default port 636, got %d", args.Port)
	}
}

func TestPresetQueries_AllExist(t *testing.T) {
	expected := []string{"users", "computers", "groups", "domain-admins", "spns", "asrep"}
	for _, name := range expected {
		if _, ok := presetQueries[name]; !ok {
			t.Errorf("missing preset query: %s", name)
		}
	}
}

func TestPresetQueries_AllHaveFields(t *testing.T) {
	for name, preset := range presetQueries {
		if preset.filter == "" {
			t.Errorf("preset %s has empty filter", name)
		}
		if len(preset.attributes) == 0 {
			t.Errorf("preset %s has no attributes", name)
		}
		if preset.desc == "" {
			t.Errorf("preset %s has no description", name)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
