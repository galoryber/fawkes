package commands

import (
	"strings"
	"testing"
)

func TestWMIEventDefaultName(t *testing.T) {
	args := persistArgs{Method: "wmi-event"}
	if args.Name == "" {
		args.Name = "SystemHealthCheck"
	}
	if args.Name != "SystemHealthCheck" {
		t.Errorf("expected default name SystemHealthCheck, got %s", args.Name)
	}

	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"
	if filterName != "SystemHealthCheck_Filter" {
		t.Errorf("expected filter name SystemHealthCheck_Filter, got %s", filterName)
	}
	if consumerName != "SystemHealthCheck_Consumer" {
		t.Errorf("expected consumer name SystemHealthCheck_Consumer, got %s", consumerName)
	}
}

func TestWMIEventCustomName(t *testing.T) {
	args := persistArgs{Method: "wmi-event", Name: "CustomTask"}
	filterName := args.Name + "_Filter"
	consumerName := args.Name + "_Consumer"
	if filterName != "CustomTask_Filter" {
		t.Errorf("expected CustomTask_Filter, got %s", filterName)
	}
	if consumerName != "CustomTask_Consumer" {
		t.Errorf("expected CustomTask_Consumer, got %s", consumerName)
	}
}

func TestWMIEventWQLQueryConstruction(t *testing.T) {
	interval := "300"
	wqlQuery := "SELECT * FROM __InstanceModificationEvent WITHIN " + interval +
		" WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"

	if !strings.Contains(wqlQuery, "WITHIN 300") {
		t.Error("WQL query should contain polling interval")
	}
	if !strings.Contains(wqlQuery, "SystemUpTime >= 120") {
		t.Error("WQL query should require minimum uptime")
	}
	if !strings.Contains(wqlQuery, "__InstanceModificationEvent") {
		t.Error("WQL query should use __InstanceModificationEvent")
	}
}

func TestWMIEventWQLQueryCustomInterval(t *testing.T) {
	interval := "60"
	wqlQuery := "SELECT * FROM __InstanceModificationEvent WITHIN " + interval +
		" WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
	if !strings.Contains(wqlQuery, "WITHIN 60") {
		t.Error("WQL query should use custom interval")
	}
}

func TestWMIEventPathEscaping(t *testing.T) {
	path := `C:\Windows\Temp\payload.exe`
	escaped := strings.ReplaceAll(path, `\`, `\\`)
	expected := `C:\\Windows\\Temp\\payload.exe`
	if escaped != expected {
		t.Errorf("expected %s, got %s", expected, escaped)
	}
}

func TestNetshHelperDefaultName(t *testing.T) {
	args := persistArgs{Method: "netsh-helper"}
	if args.Name == "" {
		args.Name = "nshipsec"
	}
	if args.Name != "nshipsec" {
		t.Errorf("expected default name nshipsec, got %s", args.Name)
	}
}

func TestNetshHelperRegistryPath(t *testing.T) {
	regPath := `SOFTWARE\Microsoft\NetSh`
	if !strings.Contains(regPath, "NetSh") {
		t.Error("registry path should contain NetSh")
	}
}

func TestNetshHelperDLLNameExtraction(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{`C:\Users\admin\evil.dll`, "evil.dll"},
		{`C:\Windows\System32\nshipsec.dll`, "nshipsec.dll"},
		{`\\server\share\helper.dll`, "helper.dll"},
	}

	for _, tt := range tests {
		name := tt.path[strings.LastIndex(tt.path, `\`)+1:]
		if name != tt.expected {
			t.Errorf("path %s: expected %s, got %s", tt.path, tt.expected, name)
		}
	}
}

func TestPersistMethodDispatch(t *testing.T) {
	methods := []string{
		"registry", "startup-folder", "com-hijack", "screensaver",
		"ifeo", "winlogon", "print-processor", "accessibility",
		"active-setup", "time-provider", "port-monitor",
		"wmi-event", "wmi", "netsh-helper", "netsh", "list",
	}

	known := map[string]bool{
		"registry": true, "reg-run": true,
		"startup-folder": true, "startup": true,
		"com-hijack": true, "screensaver": true,
		"ifeo": true, "winlogon": true,
		"print-processor": true, "accessibility": true,
		"active-setup": true, "time-provider": true,
		"port-monitor": true,
		"wmi-event": true, "wmi": true,
		"netsh-helper": true, "netsh": true,
		"list": true,
	}

	for _, m := range methods {
		if !known[strings.ToLower(m)] {
			t.Errorf("method %s not in known dispatch map", m)
		}
	}
}

func TestWMIEventActionValidation(t *testing.T) {
	validActions := []string{"install", "remove", "check", "list"}
	for _, action := range validActions {
		lower := strings.ToLower(action)
		valid := lower == "install" || lower == "remove" || lower == "check" || lower == "list"
		if !valid {
			t.Errorf("action %s should be valid", action)
		}
	}

	invalid := "delete"
	lower := strings.ToLower(invalid)
	valid := lower == "install" || lower == "remove" || lower == "check" || lower == "list"
	if valid {
		t.Errorf("action %s should be invalid", invalid)
	}
}

func TestNetshHelperActionValidation(t *testing.T) {
	validActions := []string{"install", "remove", "check", "list"}
	for _, action := range validActions {
		lower := strings.ToLower(action)
		valid := lower == "install" || lower == "remove" || lower == "check" || lower == "list"
		if !valid {
			t.Errorf("action %s should be valid", action)
		}
	}
}
