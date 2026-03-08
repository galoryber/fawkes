//go:build windows

package commands

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// pkgListWindowsNative enumerates installed software by reading the Windows
// registry directly — no PowerShell subprocess spawned.
// Reads from both Uninstall keys (64-bit and 32-bit/WOW6432Node).
func pkgListWindowsNative(filter string) string {
	type installedPkg struct {
		name    string
		version string
	}

	uninstallPaths := []string{
		`Software\Microsoft\Windows\CurrentVersion\Uninstall`,
		`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
	}

	seen := make(map[string]bool)
	var pkgs []installedPkg

	for _, path := range uninstallPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.READ)
		if err != nil {
			continue
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		key.Close()
		if err != nil {
			continue
		}

		for _, subkeyName := range subkeys {
			subkey, err := registry.OpenKey(registry.LOCAL_MACHINE, path+`\`+subkeyName, registry.READ)
			if err != nil {
				continue
			}

			displayName, _, err := subkey.GetStringValue("DisplayName")
			if err != nil || displayName == "" {
				subkey.Close()
				continue
			}

			version, _, _ := subkey.GetStringValue("DisplayVersion")
			subkey.Close()

			// Deduplicate (WOW6432Node may contain same entries)
			if seen[displayName] {
				continue
			}
			seen[displayName] = true

			pkgs = append(pkgs, installedPkg{name: displayName, version: version})
		}
	}

	if len(pkgs) == 0 {
		return ""
	}

	// Sort by name
	sort.Slice(pkgs, func(i, j int) bool {
		return strings.ToLower(pkgs[i].name) < strings.ToLower(pkgs[j].name)
	})

	// Apply filter
	var filtered []installedPkg
	for _, pkg := range pkgs {
		if pkgMatchesFilter(pkg.name, filter) {
			filtered = append(filtered, pkg)
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  Installed programs: %d", len(pkgs)))
	if filter != "" {
		sb.WriteString(fmt.Sprintf(" (%d matching)", len(filtered)))
	}
	sb.WriteString("\n\n")
	sb.WriteString(fmt.Sprintf("  %-55s %s\n", "Name", "Version"))
	sb.WriteString("  " + strings.Repeat("-", 70) + "\n")
	for i, pkg := range filtered {
		sb.WriteString(fmt.Sprintf("  %-55s %s\n", pkg.name, pkg.version))
		if i >= 199 {
			sb.WriteString(fmt.Sprintf("  ... and %d more (showing first 200)\n", len(filtered)-200))
			break
		}
	}
	return sb.String()
}
