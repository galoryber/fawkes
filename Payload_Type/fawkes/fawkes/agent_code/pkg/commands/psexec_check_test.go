//go:build windows

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPsexecCheckResult_JSONStructure(t *testing.T) {
	result := psexecCheckResult{
		Host:           "192.168.1.1",
		SMBPort:        "open",
		SCMAccess:      "pass",
		ServiceCreate:  "pass (45 services visible)",
		AdminShareC:    "likely accessible (SCM confirmed admin)",
		AdminShareADM:  "likely accessible (SCM confirmed admin)",
		OverallStatus:  "pass",
		Recommendation: "Target is ready for psexec lateral movement.",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	required := []string{"host", "smb_port", "scm_access", "service_create", "admin_share_c", "admin_share_admin", "overall_status", "recommendation"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing required field: %s", key)
		}
	}
}

func TestWmiCheckResult_JSONStructure(t *testing.T) {
	result := wmiCheckResult{
		Host:           "192.168.1.1",
		RPCPort:        "open",
		WMIConnect:     "pass",
		WMIQuery:       "pass (Name = Windows 10)",
		ProcessCreate:  "pass (Win32_Process accessible)",
		OverallStatus:  "pass",
		Recommendation: "Target is ready for WMI lateral movement.",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("JSON marshal failed: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("JSON unmarshal failed: %v", err)
	}

	required := []string{"host", "rpc_port", "wmi_connect", "wmi_query", "process_create", "overall_status", "recommendation"}
	for _, key := range required {
		if _, ok := parsed[key]; !ok {
			t.Errorf("Missing required field: %s", key)
		}
	}
}

func TestPsexecCheck_EmptyHost(t *testing.T) {
	result := psexecCheck("", 5)
	if result.Status != "error" {
		t.Errorf("Empty host should error, got status=%q", result.Status)
	}
}

func TestWmiCheck_EmptyTarget(t *testing.T) {
	result := wmiCheck("", 5)
	if result.Status != "error" {
		t.Errorf("Empty target should error, got status=%q", result.Status)
	}
}

func TestPsexecCheck_UnreachableHost(t *testing.T) {
	result := psexecCheck("192.0.2.1", 2)
	if result.Status != "success" {
		t.Errorf("Unreachable host should still return success status with check data, got %q", result.Status)
	}
	var checkData psexecCheckResult
	if err := json.Unmarshal([]byte(result.Output), &checkData); err != nil {
		t.Fatalf("Failed to parse check result: %v", err)
	}
	if checkData.OverallStatus == "pass" {
		t.Error("Unreachable host should not pass")
	}
	if !strings.Contains(checkData.SMBPort, "closed") && !strings.Contains(checkData.SMBPort, "timeout") {
		t.Errorf("SMB port should be closed or timeout, got %q", checkData.SMBPort)
	}
}

func TestPsexecAction_CheckRoutes(t *testing.T) {
	cmd := &PsExecCommand{}
	result := cmd.Execute(structs.Task{Params: `{"action":"check","host":""}`})
	if result.Status != "error" {
		t.Errorf("Check with empty host should error, got %q", result.Status)
	}
}

func TestPsexecAction_DefaultExecuteRequiresCommand(t *testing.T) {
	cmd := &PsExecCommand{}
	result := cmd.Execute(structs.Task{Params: `{"host":"192.168.1.1"}`})
	if result.Status != "error" {
		t.Errorf("Execute without command should error, got %q", result.Status)
	}
	if !strings.Contains(result.Output, "command is required") {
		t.Errorf("Should mention command is required, got %q", result.Output)
	}
}
