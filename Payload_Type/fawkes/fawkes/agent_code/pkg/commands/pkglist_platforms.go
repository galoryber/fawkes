package commands

import (
	"fmt"
	"os"
	"strings"
)

func pkgListLinux(filter string) string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Packages (Linux)\n\n")

	found := false

	// Try dpkg (Debian/Ubuntu) — native file parsing first, then subprocess fallback
	if pkgs := parseDpkgStatus(); len(pkgs) > 0 {
		filtered := filterPkgPairs(pkgs, filter)
		sb.WriteString(fmt.Sprintf("  Package Manager: dpkg (%d installed", len(pkgs)))
		if filter != "" {
			sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
		}
		sb.WriteString(")\n")
		writePkgPairs(&sb, filtered, 100)
		found = true
	} else if output := runQuietCommand("dpkg-query", "-W", "-f", "${Package}\t${Version}\t${Status}\n"); output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		var pkgs [][2]string
		for _, line := range lines {
			if !strings.Contains(line, "install ok installed") {
				continue
			}
			parts := strings.SplitN(line, "\t", 3)
			if len(parts) >= 2 {
				pkgs = append(pkgs, [2]string{parts[0], parts[1]})
			}
		}
		filtered := filterPkgPairs(pkgs, filter)
		sb.WriteString(fmt.Sprintf("  Package Manager: dpkg (%d installed", len(pkgs)))
		if filter != "" {
			sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
		}
		sb.WriteString(")\n")
		writePkgPairs(&sb, filtered, 100)
		found = true
	}

	// Try rpm (RHEL/CentOS/Fedora) — native SQLite first, then subprocess fallback
	if !found {
		if pkgs := parseRpmDB(); len(pkgs) > 0 {
			filtered := filterPkgPairs(pkgs, filter)
			sb.WriteString(fmt.Sprintf("  Package Manager: rpm (%d installed", len(pkgs)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
			}
			sb.WriteString(")\n")
			writePkgPairs(&sb, filtered, 100)
			found = true
		} else if output := runQuietCommand("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n"); output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			var pkgs [][2]string
			for _, line := range lines {
				parts := strings.SplitN(line, "\t", 2)
				if len(parts) >= 2 {
					pkgs = append(pkgs, [2]string{parts[0], parts[1]})
				}
			}
			filtered := filterPkgPairs(pkgs, filter)
			sb.WriteString(fmt.Sprintf("  Package Manager: rpm (%d installed", len(pkgs)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
			}
			sb.WriteString(")\n")
			writePkgPairs(&sb, filtered, 100)
			found = true
		}
	}

	// Try apk (Alpine) — native file parsing first, then subprocess fallback
	if !found {
		if pkgs := parseApkInstalled(); len(pkgs) > 0 {
			filtered := filterPkgPairs(pkgs, filter)
			sb.WriteString(fmt.Sprintf("  Package Manager: apk (%d installed", len(pkgs)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
			}
			sb.WriteString(")\n")
			writePkgPairs(&sb, filtered, 100)
			found = true
		} else if output := runQuietCommand("apk", "list", "--installed"); output != "" {
			lines := strings.Split(strings.TrimSpace(output), "\n")
			var filtered []string
			for _, line := range lines {
				if pkgMatchesFilter(line, filter) {
					filtered = append(filtered, line)
				}
			}
			sb.WriteString(fmt.Sprintf("  Package Manager: apk (%d installed", len(lines)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(", %d matching", len(filtered)))
			}
			sb.WriteString(")\n")
			for i, line := range filtered {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(filtered)-100))
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
			var filtered []string
			// Keep header (line 0), filter the rest
			for _, line := range lines[1:] {
				if pkgMatchesFilter(line, filter) {
					filtered = append(filtered, line)
				}
			}
			if filter == "" || len(filtered) > 0 {
				sb.WriteString(fmt.Sprintf("\n  Snap packages: %d", len(lines)-1))
				if filter != "" {
					sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
				}
				sb.WriteString("\n")
				sb.WriteString(fmt.Sprintf("    %s\n", lines[0])) // header
				for _, line := range filtered {
					sb.WriteString(fmt.Sprintf("    %s\n", line))
				}
			}
		}
	}

	// Try flatpak
	flatpakOutput := runQuietCommand("flatpak", "list", "--columns=application,version")
	if flatpakOutput != "" {
		lines := strings.Split(strings.TrimSpace(flatpakOutput), "\n")
		var filtered []string
		for _, line := range lines {
			if pkgMatchesFilter(line, filter) {
				filtered = append(filtered, line)
			}
		}
		if filter == "" || len(filtered) > 0 {
			sb.WriteString(fmt.Sprintf("\n  Flatpak apps: %d", len(lines)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
			}
			sb.WriteString("\n")
			for _, line := range filtered {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
			}
		}
	}

	if !found && snapOutput == "" && flatpakOutput == "" {
		sb.WriteString("  No supported package manager found (tried: dpkg, rpm, apk)\n")
	}

	return sb.String()
}

func pkgListDarwin(filter string) string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (macOS)\n\n")

	// Homebrew
	brewOutput := runQuietCommand("brew", "list", "--versions")
	if brewOutput != "" {
		lines := strings.Split(strings.TrimSpace(brewOutput), "\n")
		var filtered []string
		for _, line := range lines {
			if pkgMatchesFilter(line, filter) {
				filtered = append(filtered, line)
			}
		}
		sb.WriteString(fmt.Sprintf("  Homebrew packages: %d", len(lines)))
		if filter != "" {
			sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
		}
		sb.WriteString("\n")
		for i, line := range filtered {
			sb.WriteString(fmt.Sprintf("    %s\n", line))
			if i >= 99 {
				sb.WriteString(fmt.Sprintf("    ... and %d more (showing first 100)\n", len(filtered)-100))
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
		var filtered []string
		for _, line := range lines {
			if pkgMatchesFilter(line, filter) {
				filtered = append(filtered, line)
			}
		}
		if filter == "" || len(filtered) > 0 {
			sb.WriteString(fmt.Sprintf("\n  Homebrew casks: %d", len(lines)))
			if filter != "" {
				sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
			}
			sb.WriteString("\n")
			for i, line := range filtered {
				sb.WriteString(fmt.Sprintf("    %s\n", line))
				if i >= 99 {
					sb.WriteString(fmt.Sprintf("    ... and %d more\n", len(filtered)-100))
					break
				}
			}
		}
	}

	// Applications directory
	sb.WriteString("\n  /Applications:\n")
	entries, err := os.ReadDir("/Applications")
	if err == nil {
		count := 0
		matched := 0
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".app") {
				count++
				if pkgMatchesFilter(entry.Name(), filter) {
					sb.WriteString(fmt.Sprintf("    %s\n", entry.Name()))
					matched++
				}
			}
		}
		sb.WriteString(fmt.Sprintf("  Total .app bundles: %d", count))
		if filter != "" {
			sb.WriteString(fmt.Sprintf(" (%d matching)", matched))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func pkgListWindows(filter string) string {
	var sb strings.Builder
	sb.WriteString("[*] Installed Software (Windows)\n\n")

	// Try native registry reading first (no subprocess spawned)
	if native := pkgListWindowsNative(filter); native != "" {
		sb.WriteString(native)
		return sb.String()
	}

	// Fall back to PowerShell
	psCmd := "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | Sort-Object DisplayName | ForEach-Object { \"$($_.DisplayName)\t$($_.DisplayVersion)\" }"
	output := runQuietCommand("powershell", BuildPSArgs(psCmd, InternalPSOptions())...)
	if output != "" {
		lines := strings.Split(strings.TrimSpace(output), "\n")
		var filtered [][2]string
		for _, line := range lines {
			parts := strings.SplitN(strings.TrimSpace(line), "\t", 2)
			name := strings.TrimSpace(line)
			version := ""
			if len(parts) == 2 {
				name = parts[0]
				version = parts[1]
			}
			if pkgMatchesFilter(name, filter) {
				filtered = append(filtered, [2]string{name, version})
			}
		}
		sb.WriteString(fmt.Sprintf("  Installed programs: %d", len(lines)))
		if filter != "" {
			sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
		}
		sb.WriteString("\n\n")
		sb.WriteString(fmt.Sprintf("  %-55s %s\n", "Name", "Version"))
		sb.WriteString("  " + strings.Repeat("-", 70) + "\n")
		for i, pkg := range filtered {
			sb.WriteString(fmt.Sprintf("  %-55s %s\n", pkg[0], pkg[1]))
			if i >= 199 {
				sb.WriteString(fmt.Sprintf("  ... and %d more (showing first 200)\n", len(filtered)-200))
				break
			}
		}
	} else {
		sb.WriteString("  Failed to enumerate installed programs\n")
	}

	return sb.String()
}
