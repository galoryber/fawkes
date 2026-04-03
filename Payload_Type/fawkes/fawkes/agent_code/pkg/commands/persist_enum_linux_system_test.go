//go:build linux

package commands

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistEnumPreload_OutputFormat(t *testing.T) {
	var sb strings.Builder
	count := persistEnumPreload(&sb)
	output := sb.String()

	if !strings.Contains(output, "--- LD_PRELOAD / ld.so.preload ---") {
		t.Error("missing section header")
	}
	if count < 0 {
		t.Errorf("count should be >= 0, got %d", count)
	}
}

func TestLdSoPreloadLineParsing(t *testing.T) {
	// persistEnumPreload filters /etc/ld.so.preload: skip empty and comments
	content := "# preload config\n/usr/lib/libcustom.so\n\n# another comment\n/usr/lib/libhook.so\n"
	var libs []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		libs = append(libs, line)
	}
	if len(libs) != 2 {
		t.Errorf("expected 2 preloaded libs, got %d: %v", len(libs), libs)
	}
}

func TestEnvironmentLdPreloadDetection(t *testing.T) {
	// persistEnumPreload checks /etc/environment for LD_PRELOAD lines
	content := `PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LD_PRELOAD=/usr/lib/libevil.so
LANG=en_US.UTF-8
`
	var ldLines []string
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "LD_PRELOAD") {
			ldLines = append(ldLines, strings.TrimSpace(line))
		}
	}
	if len(ldLines) != 1 {
		t.Errorf("expected 1 LD_PRELOAD line, got %d: %v", len(ldLines), ldLines)
	}
	if ldLines[0] != "LD_PRELOAD=/usr/lib/libevil.so" {
		t.Errorf("unexpected line: %q", ldLines[0])
	}
}

func TestUdevRunDirectiveDetection(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		hasRun bool
	}{
		{"RUN+=", `SUBSYSTEM=="usb", RUN+="/usr/local/bin/usb-handler"`, true},
		{"RUN=", `ACTION=="add", RUN="/sbin/modprobe driver"`, true},
		{"PROGRAM=", `PROGRAM="/sbin/check_device"`, true},
		{"no run", `SUBSYSTEM=="net", ATTR{address}=="00:11:22:*", NAME="eth0"`, false},
		{"comment", `# RUN+="/usr/bin/something"`, false},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := strings.TrimSpace(tc.line)
			if line == "" || strings.HasPrefix(line, "#") {
				if tc.hasRun {
					t.Error("expected hasRun but line was filtered out")
				}
				return
			}
			hasRun := strings.Contains(line, "RUN+=") || strings.Contains(line, "RUN=") ||
				strings.Contains(line, "PROGRAM=")
			if hasRun != tc.hasRun {
				t.Errorf("got hasRun=%v, want %v", hasRun, tc.hasRun)
			}
		})
	}
}

func TestKernelModulesLineParsing(t *testing.T) {
	// /etc/modules format: module names, skip comments and empty
	content := "# /etc/modules: kernel modules to load at boot time.\n\nvfio\nvfio_iommu_type1\nvfio_pci\n"
	var modules []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		modules = append(modules, line)
	}
	if len(modules) != 3 {
		t.Errorf("expected 3 modules, got %d: %v", len(modules), modules)
	}
}

func TestModulesLoadDParsing(t *testing.T) {
	// modules-load.d also skips lines starting with ;
	content := "# Load vfio modules\n; disabled module\nvfio\nvfio_pci\n\n"
	var modules []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		modules = append(modules, line)
	}
	if len(modules) != 2 {
		t.Errorf("expected 2 modules (vfio, vfio_pci), got %d: %v", len(modules), modules)
	}
}

func TestModprobeInstallDirectiveDetection(t *testing.T) {
	// modprobe.d: flag "install" directives (arbitrary command execution)
	lines := []string{
		"options snd_hda_intel model=generic",
		"blacklist nouveau",
		"install usb-storage /bin/true",
		"install cramfs /bin/true",
		"# install comment",
		"alias eth0 e1000",
	}
	var installLines []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "install ") {
			installLines = append(installLines, line)
		}
	}
	if len(installLines) != 2 {
		t.Errorf("expected 2 install directives, got %d: %v", len(installLines), installLines)
	}
}

func TestPAMModuleDetection(t *testing.T) {
	// Mirror the standardModules map from persistEnumPAM for testing
	testStandardModules := map[string]bool{
		"pam_unix.so": true, "pam_deny.so": true, "pam_permit.so": true,
		"pam_env.so": true, "pam_limits.so": true, "pam_nologin.so": true,
		"pam_succeed_if.so": true, "pam_pwquality.so": true, "pam_faillock.so": true,
		"pam_systemd.so": true, "pam_systemd_home.so": true, "pam_keyinit.so": true,
		"pam_loginuid.so": true, "pam_selinux.so": true, "pam_namespace.so": true,
		"pam_console.so": true, "pam_tally2.so": true, "pam_securetty.so": true,
		"pam_access.so": true, "pam_time.so": true, "pam_motd.so": true,
		"pam_mail.so": true, "pam_lastlog.so": true, "pam_shells.so": true,
		"pam_cap.so": true, "pam_wheel.so": true, "pam_xauth.so": true,
		"pam_gnome_keyring.so": true, "pam_kwallet5.so": true, "pam_fprintd.so": true,
		"pam_sss.so": true, "pam_winbind.so": true, "pam_krb5.so": true,
		"pam_ldap.so": true, "pam_cracklib.so": true, "pam_ecryptfs.so": true,
		"pam_google_authenticator.so": true, "pam_umask.so": true,
	}

	// Verify map has expected entries
	if len(testStandardModules) < 20 {
		t.Errorf("standardModules has %d entries, expected at least 20", len(testStandardModules))
	}
	for _, mod := range []string{"pam_unix.so", "pam_deny.so", "pam_systemd.so", "pam_wheel.so", "pam_krb5.so"} {
		if !testStandardModules[mod] {
			t.Errorf("expected standard module %q not found", mod)
		}
	}

	// Test PAM line parsing: type control module-path [args]
	tests := []struct {
		line       string
		moduleName string
		isStandard bool
		isRelevant bool
	}{
		{"auth required pam_unix.so", "pam_unix.so", true, true},
		{"auth required pam_backdoor.so", "pam_backdoor.so", false, true},
		{"account required pam_permit.so", "pam_permit.so", true, true},
		{"session optional pam_evil.so debug", "pam_evil.so", false, true},
		{"# auth required pam_unix.so", "", false, false},
		{"@include common-auth", "", false, false},
		{"auth required", "", false, false},
		{"auth required /lib/security/pam_custom.so", "pam_custom.so", false, true},
	}
	for _, tc := range tests {
		line := strings.TrimSpace(tc.line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "@") {
			if tc.isRelevant {
				t.Errorf("line %q: should not be filtered", tc.line)
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			if tc.isRelevant {
				t.Errorf("line %q: expected relevant but only %d fields", tc.line, len(fields))
			}
			continue
		}
		moduleName := filepath.Base(fields[2])
		if moduleName != tc.moduleName {
			t.Errorf("line %q: moduleName = %q, want %q", tc.line, moduleName, tc.moduleName)
		}
		isStandard := testStandardModules[moduleName]
		if isStandard != tc.isStandard {
			t.Errorf("line %q: isStandard = %v, want %v", tc.line, isStandard, tc.isStandard)
		}
	}
}

func TestPackageHookPatterns(t *testing.T) {
	hookPatterns := []string{
		"Pre-Invoke", "Post-Invoke", "Pre-Install-Pkgs",
		"Post-Install-Pkgs", "DPkg::Pre-Invoke", "DPkg::Post-Invoke",
		"APT::Update::Post-Invoke", "APT::Update::Pre-Invoke",
	}

	tests := []struct {
		name    string
		content string
		hasHook bool
	}{
		{
			"apt pre-invoke hook",
			`DPkg::Pre-Invoke { "/usr/bin/backup-dpkg-state"; };`,
			true,
		},
		{
			"apt post-invoke hook",
			`APT::Update::Post-Invoke { "rm -f /var/cache/apt/archives/partial/*.deb"; };`,
			true,
		},
		{
			"no hook directives",
			`APT::Get::Show-Upgraded "true";`,
			false,
		},
		{
			"empty file",
			"",
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hasHook := false
			for _, pattern := range hookPatterns {
				if strings.Contains(tc.content, pattern) {
					hasHook = true
					break
				}
			}
			if hasHook != tc.hasHook {
				t.Errorf("got hasHook=%v, want %v", hasHook, tc.hasHook)
			}
		})
	}
}

func TestLogrotateScriptDetection(t *testing.T) {
	directives := []string{"postrotate", "prerotate", "firstaction", "lastaction"}

	tests := []struct {
		name      string
		content   string
		hasScript bool
	}{
		{
			"postrotate block",
			"/var/log/syslog {\n  rotate 7\n  daily\n  postrotate\n    /usr/bin/systemctl restart rsyslog\n  endscript\n}",
			true,
		},
		{
			"prerotate block",
			"/var/log/mysql/*.log {\n  prerotate\n    test -x /usr/bin/mysqladmin\n  endscript\n}",
			true,
		},
		{
			"no script blocks",
			"/var/log/apt/*.log {\n  rotate 12\n  monthly\n  compress\n  missingok\n}",
			false,
		},
		{
			"firstaction block",
			"/var/log/nginx/*.log {\n  firstaction\n    /usr/bin/notify\n  endscript\n}",
			true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hasScript := false
			for _, directive := range directives {
				if strings.Contains(tc.content, directive) {
					hasScript = true
					break
				}
			}
			if hasScript != tc.hasScript {
				t.Errorf("got hasScript=%v, want %v", hasScript, tc.hasScript)
			}
		})
	}
}
