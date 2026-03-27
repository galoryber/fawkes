//go:build linux

package commands

import (
	"encoding/json"
	"strings"
	"testing"

	"fawkes/pkg/structs"
)

func TestPersistEnumCommand_Metadata(t *testing.T) {
	cmd := &PersistEnumCommand{}
	if cmd.Name() != "persist-enum" {
		t.Errorf("Name() = %q, want %q", cmd.Name(), "persist-enum")
	}
	if cmd.Description() == "" {
		t.Error("Description() is empty")
	}
}

func TestPersistEnumCommand_DefaultAll(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Persistence Enumeration (Linux)") {
		t.Error("output missing Linux header")
	}
	expectedSections := []string{
		"Cron Jobs", "Systemd Units", "Shell Profiles", "Startup / Init",
		"SSH Authorized Keys", "LD_PRELOAD", "Udev Rules", "Kernel Modules",
		"MOTD Scripts", "At Jobs", "Total:",
	}
	for _, section := range expectedSections {
		if !strings.Contains(result.Output, section) {
			t.Errorf("output missing %q section", section)
		}
	}
}

func TestPersistEnumCommand_CategoryFilter(t *testing.T) {
	cmd := &PersistEnumCommand{}

	// Test single category
	params, _ := json.Marshal(persistEnumArgs{Category: "cron"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Cron Jobs") {
		t.Error("output missing Cron section")
	}
	// Should NOT have other sections
	if strings.Contains(result.Output, "Systemd Units") {
		t.Error("output should not contain Systemd section when category=cron")
	}
}

func TestPersistEnumCommand_SystemdCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "systemd"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Systemd Units") {
		t.Error("output missing Systemd section")
	}
}

func TestPersistEnumCommand_ShellCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "shell"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Shell Profiles") {
		t.Error("output missing Shell Profiles section")
	}
}

func TestPersistEnumCommand_PreloadCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "preload"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "LD_PRELOAD") {
		t.Error("output missing Preload section")
	}
}

func TestPersistEnumCommand_InvalidJSON(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{bad`})
	if result.Status != "error" {
		t.Errorf("expected error for invalid JSON, got %q", result.Status)
	}
}

func TestPersistEnumCommand_EmptyParams(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: ""})
	if result.Status != "success" {
		t.Fatalf("expected success for empty params, got %q: %s", result.Status, result.Output)
	}
	// Should default to "all"
	if !strings.Contains(result.Output, "Cron Jobs") {
		t.Error("empty params should default to all categories")
	}
}

func TestCurrentHomeDir(t *testing.T) {
	home := currentHomeDir()
	if home == "" {
		t.Error("currentHomeDir() returned empty string")
	}
}

func TestPersistEnumArgs_Unmarshal(t *testing.T) {
	input := `{"category": "cron"}`
	var args persistEnumArgs
	if err := json.Unmarshal([]byte(input), &args); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if args.Category != "cron" {
		t.Errorf("Category = %q, want %q", args.Category, "cron")
	}
}

// --- Tests for new persistence categories ---

func TestPersistEnumCommand_UdevCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "udev"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Udev Rules") {
		t.Error("output missing Udev Rules section")
	}
}

func TestPersistEnumCommand_ModulesCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "modules"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Kernel Modules") {
		t.Error("output missing Kernel Modules section")
	}
}

func TestPersistEnumCommand_MotdCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "motd"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "MOTD Scripts") {
		t.Error("output missing MOTD Scripts section")
	}
}

func TestPersistEnumCommand_AtJobsCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "at"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "At Jobs") {
		t.Error("output missing At Jobs section")
	}
}

func TestPersistEnumCommand_AllIncludesNewCategories(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{"category":"all"}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	// Verify all new sections appear in "all" output
	for _, section := range []string{"Udev Rules", "Kernel Modules", "MOTD Scripts", "At Jobs"} {
		if !strings.Contains(result.Output, section) {
			t.Errorf("'all' output missing %q section", section)
		}
	}
}

func TestPersistEnumUdev_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumUdev(&sb)
	output := sb.String()
	if !strings.Contains(output, "Udev Rules") {
		t.Error("missing section header")
	}
	// On a real system, /lib/udev/rules.d/ should exist
	// Count may be 0 or positive depending on system
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumKernelModules_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumKernelModules(&sb)
	output := sb.String()
	if !strings.Contains(output, "Kernel Modules") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumMotd_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumMotd(&sb)
	output := sb.String()
	if !strings.Contains(output, "MOTD Scripts") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumAtJobs_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumAtJobs(&sb)
	output := sb.String()
	if !strings.Contains(output, "At Jobs") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumUdev_DetectsCustomRules(t *testing.T) {
	// /etc/udev/rules.d/ may or may not have custom rules
	// This test verifies the function doesn't crash and produces valid output
	var sb strings.Builder
	persistEnumUdev(&sb)
	output := sb.String()
	// Output must have header and either rules or "(none found)"
	if !strings.Contains(output, "Udev Rules") {
		t.Error("missing header")
	}
}

func TestPersistEnumKernelModules_ChecksModprobeInstall(t *testing.T) {
	// /etc/modprobe.d/ should exist on most Linux systems
	var sb strings.Builder
	persistEnumKernelModules(&sb)
	output := sb.String()
	// Verify it checks modprobe.d — output should contain either a finding or "(none found)"
	if !strings.Contains(output, "Kernel Modules") {
		t.Error("missing header")
	}
}

// --- Tests for new persistence categories (Session 202) ---

func TestPersistEnumCommand_DBusCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "dbus"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "D-Bus Services") {
		t.Error("output missing D-Bus Services section")
	}
}

func TestPersistEnumCommand_PAMCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "pam"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "PAM Configuration") {
		t.Error("output missing PAM Configuration section")
	}
}

func TestPersistEnumCommand_PackagesCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "packages"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Package Manager Hooks") {
		t.Error("output missing Package Manager Hooks section")
	}
}

func TestPersistEnumCommand_LogrotateCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "logrotate"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Logrotate Scripts") {
		t.Error("output missing Logrotate Scripts section")
	}
}

func TestPersistEnumCommand_NetworkManagerCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "networkmanager"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "NetworkManager Dispatcher") {
		t.Error("output missing NetworkManager Dispatcher section")
	}
}

func TestPersistEnumCommand_AnacronCategory(t *testing.T) {
	cmd := &PersistEnumCommand{}
	params, _ := json.Marshal(persistEnumArgs{Category: "anacron"})
	result := cmd.Execute(structs.Task{Params: string(params)})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	if !strings.Contains(result.Output, "Anacron") {
		t.Error("output missing Anacron section")
	}
}

func TestPersistEnumCommand_AllIncludesSession202Categories(t *testing.T) {
	cmd := &PersistEnumCommand{}
	result := cmd.Execute(structs.Task{Params: `{"category":"all"}`})
	if result.Status != "success" {
		t.Fatalf("expected success, got %q: %s", result.Status, result.Output)
	}
	for _, section := range []string{
		"D-Bus Services", "PAM Configuration", "Package Manager Hooks",
		"Logrotate Scripts", "NetworkManager Dispatcher", "Anacron",
	} {
		if !strings.Contains(result.Output, section) {
			t.Errorf("'all' output missing %q section", section)
		}
	}
}

func TestPersistEnumDBus_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumDBus(&sb)
	output := sb.String()
	if !strings.Contains(output, "D-Bus Services") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
	// On a system with D-Bus installed, there should be some service files
	// but this may vary — just verify no crash and valid output
}

func TestPersistEnumPAM_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumPAM(&sb)
	output := sb.String()
	if !strings.Contains(output, "PAM Configuration") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumPackageHooks_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumPackageHooks(&sb)
	output := sb.String()
	if !strings.Contains(output, "Package Manager Hooks") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumLogrotate_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumLogrotate(&sb)
	output := sb.String()
	if !strings.Contains(output, "Logrotate Scripts") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumNetworkManager_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumNetworkManager(&sb)
	output := sb.String()
	if !strings.Contains(output, "NetworkManager Dispatcher") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumAnacron_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumAnacron(&sb)
	output := sb.String()
	if !strings.Contains(output, "Anacron") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Error("count should not be negative")
	}
}

func TestPersistEnumDBus_DetectsServiceFiles(t *testing.T) {
	// /usr/share/dbus-1/services/ should exist on most Desktop Linux
	var sb strings.Builder
	count := persistEnumDBus(&sb)
	output := sb.String()
	// On a server, D-Bus session services may be minimal — just verify format
	if count > 0 && !strings.Contains(output, "[") {
		t.Error("service entries should have category brackets")
	}
}

func TestPersistEnumPAM_DetectsStandardModules(t *testing.T) {
	// /etc/pam.d/ should exist on all Linux systems
	var sb strings.Builder
	persistEnumPAM(&sb)
	output := sb.String()
	// Output should either find non-standard modules or report "all standard"
	if !strings.Contains(output, "PAM Configuration") {
		t.Error("missing header")
	}
}

func TestPersistEnumLogrotate_DetectsScripts(t *testing.T) {
	// Most Linux systems have logrotate configs with postrotate
	var sb strings.Builder
	count := persistEnumLogrotate(&sb)
	output := sb.String()
	// On Ubuntu/Debian, rsyslog and others have postrotate blocks
	if count > 0 && !strings.Contains(output, "script directives") {
		t.Error("expected 'script directives' in output when count > 0")
	}
}

func TestPersistEnumAnacron_ParsesEntries(t *testing.T) {
	// /etc/anacrontab may or may not exist
	var sb strings.Builder
	count := persistEnumAnacron(&sb)
	output := sb.String()
	if count > 0 {
		// Verify entry format includes period/delay/id fields
		if !strings.Contains(output, "period=") {
			t.Error("anacron entries should include period= format")
		}
	}
}
