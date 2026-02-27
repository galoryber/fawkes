package commands

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// PkgListCommand lists installed packages/software.
type PkgListCommand struct{}

func (c *PkgListCommand) Name() string        { return "pkg-list" }
func (c *PkgListCommand) Description() string { return "List installed packages and software" }

func (c *PkgListCommand) Execute(task structs.Task) structs.CommandResult {
	var output string

	switch runtime.GOOS {
	case "linux":
		output = pkgListLinux()
	case "darwin":
		output = pkgListDarwin()
	case "windows":
		output = pkgListWindows()
	default:
		output = fmt.Sprintf("Unsupported platform: %s", runtime.GOOS)
	}

	return structs.CommandResult{
		Output:    output,
		Status:    "success",
		Completed: true,
	}
}

func pkgListLinux() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Packages (Linux)\n\n")

	found := false

	// Try dpkg (Debian/Ubuntu)
	output := runQuietCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n")
	if output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		installed := 0
		for _, line := range lines {
			if strings.Contains(line, "install ok installed") {
				installed++
			}
		}
		sb.WriteString(fmt.Sprintf("  Package Manager: dpkg (%d installed)\n", installed))
		// Show first 50 packages to avoid huge output
		count := 0
		for _, line := range lines {
			if !strings.Contains(line, "install ok installed") {
				continue
			}
			parts := strings.SplitN(line, "\t", 3)
			if len(parts) >= 2 {
				sb.WriteString(fmt.Sprintf("    %-40s %s\n", parts[0], parts[1]))
			}
			count++
			if count >= 100 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", installed-100))
				break
			}
		}
		found = true
	}

	// Try rpm (RHEL/CentOS/Fedora)
	if !found {
		output = runQuietCommand("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
		if output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			sb.WriteString(fmt.Sprintf("  Package Manager: rpm (%d installed)\n", len(lines)))
			for i, line := range lines {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) >= 2 {
					sb.WriteString(fmt.Sprintf("    %-40s %s\n", parts[0], parts[1]))
				}
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
					break
				}
			}
			found = true
		}
	}

	// Try apk (Alpine)
	if !found {
		output = runQuietCommand("apk", "list", "--installed")
		if output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			sb.WriteString(fmt.Sprintf("  Package Manager: apk (%d installed)\n", len(lines)))
			for i, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
					break
				}
			}
			found = true
		}
	}

	// Try snap
	snapOutput := runQuietCommand("snap", "list")
	if snapOutput != "" {
		lines := strings.Split(strings.TrimSpace(snapOutput), "\n")
		if len(lines) > 1 {
			sb.WriteString(fmt.Sprintf("\n  Snap packages: %d\n", len(lines)-1))
			for _, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	// Try flatpak
	flatpakOutput := runQuietCommand("flatpak", "list", "--columns=application,version")
	if flatpakOutput != "" {
		lines := strings.Split(strings.TrimSpace(flatpakOutput), "\n")
		if len(lines) > 0 {
			sb.WriteString(fmt.Sprintf("\n  Flatpak apps: %d\n", len(lines)))
			for _, line := range lines {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	if !found && snapOutput == "" && flatpakOutput == "" {
		sb.WriteString("  No supported package manager found (tried: dpkg, rpm, apk)\n")
	}

	return sb.String()
}

func pkgListDarwin() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (macOS)\n\n")

	// Homebrew
	brewOutput := runQuietCommand("brew", "list", "--versions")
	if brewOutput != "" {
		lines := strings.Split(strings.TrimSpace(brewOutput), "\n")
		sb.WriteString(fmt.Sprintf("  Homebrew packages: %d\n", len(lines)))
		for i, line := range lines {
			sb.WriteString(fmt.Sprintf("    %s\n", line))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(lines)-100))
				break
			}
		}
	} else {
		sb.WriteString("  Homebrew: not installed\n")
	}

	// Homebrew casks
	caskOutput := runQuietCommand("brew", "list", "--cask", "--versions")
	if caskOutput != "" {
		lines := strings.Split(strings.TrimSpace(caskOutput), "\n")
		sb.WriteString(fmt.Sprintf("\n  Homebrew casks: %d\n", len(lines)))
		for i, line := range lines {
			sb.WriteString(fmt.Sprintf("    %s\n", line))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(lines)-100))
				break
			}
		}
	}

	// Applications directory
	sb.WriteString("\n  /Applications:\n")
	entries, err := os.ReadDir("/Applications")
	if err == nil {
		count := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".app") {
				sb.WriteString(fmt.Sprintf("    %s\n", entry.Name()))
				count++
			}
		}
		sb.WriteString(fmt.Sprintf("  Total .app bundles: %d\n", count))
	}

	return sb.String()
}

func pkgListWindows() string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (Windows)\n\n")

	// Use PowerShell to query installed programs from registry
	psCmd := "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object { \"$($_.DisplayName)\t$($_.DisplayVersion)\" }"
	output := runQuietCommand("powershell", "-NoProfile", "-NonInteractive", "-Command", psCmd)
	if output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		sb.WriteString(fmt.Sprintf("  Installed programs: %d\n\n", len(lines)))
		sb.WriteString(fmt.Sprintf("  %-55s %s\n", "Name", "Version"))
		sb.WriteString("  " + strings.Repeat("-", 70) + "\n")
		for i, line := range lines {
			parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
			if len(parts) == 2 {
				sb.WriteString(fmt.Sprintf("  %-55s %s\n", parts[0], parts[1]))
			} else {
				sb.WriteString(fmt.Sprintf("  %s\n", strings.TrimSpace(line)))
			}
			if i >= 199 {
				sb.WriteString(fmt.Sprintf("  ... and %d more (showing first 200)\n", len(lines)-200))
				break
			}
		}
	} else {
		sb.WriteString("  Failed to enumerate installed programs\n")
	}

	return sb.String()
}

// runQuietCommand runs a command and returns stdout, or empty string on error.
func runQuietCommand(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}
