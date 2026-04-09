//go:build windows

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

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "Windows privilege escalation enumeration: token privileges, unquoted service paths, modifiable services, AlwaysInstallElevated, auto-logon, UAC config, writable PATH dirs (T1548)"
}

type privescCheckArgs struct {
	Action    string `json:"action"`
	Source    string `json:"source"`
	TargetDir string `json:"target_dir"`
	DLLName   string `json:"dll_name"`
	Timestomp *bool  `json:"timestomp,omitempty"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args privescCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return winPrivescCheckAll()
	case "privileges":
		return winPrivescCheckPrivileges()
	case "services":
		return winPrivescCheckServices()
	case "registry":
		return winPrivescCheckRegistry()
	case "writable":
		return winPrivescCheckWritable()
	case "unattend":
		return winPrivescCheckUnattend()
	case "uac":
		return winPrivescCheckUAC()
	case "dll-hijack":
		return winPrivescCheckDLLHijack()
	case "dll-plant":
		return winDLLPlant(args)
	case "dll-sideload":
		return winPrivescCheckDLLSideLoad()
	case "service-registry":
		return winPrivescCheckServiceRegistryPerms()
	default:
		return errorf("Unknown action: %s. Use: all, privileges, services, registry, writable, unattend, uac, dll-hijack, dll-plant, dll-sideload, service-registry", args.Action)
	}
}

func winPrivescCheckAll() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== WINDOWS PRIVILEGE ESCALATION CHECK ===\n\n")

	sb.WriteString("--- Token Privileges ---\n")
	sb.WriteString(winPrivescCheckPrivileges().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- UAC Configuration ---\n")
	sb.WriteString(winPrivescCheckUAC().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Service Misconfigurations ---\n")
	sb.WriteString(winPrivescCheckServices().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Registry Checks ---\n")
	sb.WriteString(winPrivescCheckRegistry().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Writable PATH Directories ---\n")
	sb.WriteString(winPrivescCheckWritable().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Unattended Install Files ---\n")
	sb.WriteString(winPrivescCheckUnattend().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- DLL Search Order Hijacking ---\n")
	sb.WriteString(winPrivescCheckDLLHijack().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- DLL Side-Loading ---\n")
	sb.WriteString(winPrivescCheckDLLSideLoad().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Service Registry Permissions ---\n")
	sb.WriteString(winPrivescCheckServiceRegistryPerms().Output)

	return successResult(sb.String())
}

// winPrivescCheckPrivileges enumerates exploitable token privileges
func winPrivescCheckPrivileges() structs.CommandResult {
	var sb strings.Builder

	token, _, err := getCurrentToken()
	if err != nil {
		return errorf("Failed to get current token: %v", err)
	}
	defer token.Close()

	privs, err := getTokenPrivileges(token)
	if err != nil {
		return errorf("Failed to enumerate privileges: %v", err)
	}

	// Privileges exploitable for privilege escalation
	exploitable := map[string]string{
		"SeImpersonatePrivilege":          "Potato attacks (JuicyPotato, PrintSpoofer, GodPotato) → SYSTEM",
		"SeAssignPrimaryTokenPrivilege":   "Potato attacks → SYSTEM (alternative to SeImpersonate)",
		"SeDebugPrivilege":                "Inject into/dump any process including LSASS",
		"SeBackupPrivilege":               "Read any file (SAM, SYSTEM hives, NTDS.dit)",
		"SeRestorePrivilege":              "Write any file, modify services, DLL hijack",
		"SeTakeOwnershipPrivilege":        "Take ownership of any securable object",
		"SeLoadDriverPrivilege":           "Load vulnerable kernel driver → arbitrary kernel code",
		"SeCreateTokenPrivilege":          "Forge access tokens",
		"SeTcbPrivilege":                  "Act as part of the OS — full SYSTEM access",
		"SeManageVolumePrivilege":         "Read any file on NTFS (USN journal trick)",
		"SeRelabelPrivilege":              "Modify integrity labels on objects",
		"SeTrustedCredManAccessPrivilege": "Access Credential Manager store",
	}

	var found []string
	var all []string
	for _, p := range privs {
		line := fmt.Sprintf("  %-40s [%s]", p.name, p.status)
		all = append(all, line)

		if desc, ok := exploitable[p.name]; ok {
			flag := "[!]"
			if p.status == "Disabled" {
				flag = "[*]" // present but disabled — can be enabled
			}
			found = append(found, fmt.Sprintf("  %s %-40s [%s] → %s", flag, p.name, p.status, desc))
		}
	}

	sb.WriteString(fmt.Sprintf("Token privileges (%d total):\n", len(all)))
	sb.WriteString(strings.Join(all, "\n"))

	if len(found) > 0 {
		sb.WriteString(fmt.Sprintf("\n\n[!] EXPLOITABLE privileges (%d):\n", len(found)))
		sb.WriteString(strings.Join(found, "\n"))
		sb.WriteString("\n\nNote: Disabled privileges can be enabled with 'getprivs -action enable -privilege <name>'")
	} else {
		sb.WriteString("\n\nNo exploitable privileges found.")
	}

	// Check integrity level
	integrity, err := getTokenIntegrityLevel(token)
	if err == nil {
		sb.WriteString(fmt.Sprintf("\n\nIntegrity Level: %s", integrity))
		if strings.Contains(integrity, "Medium") {
			sb.WriteString(" (not elevated — UAC bypass may be needed)")
		} else if strings.Contains(integrity, "High") {
			sb.WriteString(" (elevated admin)")
		} else if strings.Contains(integrity, "System") {
			sb.WriteString(" (SYSTEM)")
		}
	}

	return successResult(sb.String())
}

// --- Windows-specific helper functions ---

func isFileWritable(path string) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}

func readRegDWORD(root windows.Handle, path, name string) uint32 {
	var key windows.Handle
	pathUTF16, _ := windows.UTF16PtrFromString(path)
	err := windows.RegOpenKeyEx(root, pathUTF16, 0, windows.KEY_READ, &key)
	if err != nil {
		return 0xFFFFFFFF // sentinel for "not found"
	}
	defer windows.RegCloseKey(key)

	var dataType uint32
	var data [4]byte
	dataLen := uint32(4)
	nameUTF16, _ := windows.UTF16PtrFromString(name)
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, &data[0], &dataLen)
	if err != nil {
		return 0xFFFFFFFF
	}

	return *(*uint32)(unsafe.Pointer(&data[0]))
}

// countRegValues returns the number of values under a registry key, or -1 on error
func countRegValues(root windows.Handle, path string) int {
	var key windows.Handle
	pathUTF16, _ := windows.UTF16PtrFromString(path)
	err := windows.RegOpenKeyEx(root, pathUTF16, 0, windows.KEY_READ, &key)
	if err != nil {
		return -1
	}
	defer windows.RegCloseKey(key)

	var valueCount uint32
	// RegQueryInfoKey to get value count
	procRegQueryInfoKey := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegQueryInfoKeyW")
	r1, _, _ := procRegQueryInfoKey.Call(
		uintptr(key),
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&valueCount)),
		0, 0, 0, 0,
	)
	if r1 != 0 {
		return -1
	}
	return int(valueCount)
}

func readRegString(root windows.Handle, path, name string) string {
	var key windows.Handle
	pathUTF16, _ := windows.UTF16PtrFromString(path)
	err := windows.RegOpenKeyEx(root, pathUTF16, 0, windows.KEY_READ, &key)
	if err != nil {
		return ""
	}
	defer windows.RegCloseKey(key)

	var dataType uint32
	var dataLen uint32
	nameUTF16, _ := windows.UTF16PtrFromString(name)
	// First call to get the size
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, nil, &dataLen)
	if err != nil || dataLen == 0 {
		return ""
	}

	buf := make([]uint16, dataLen/2)
	err = windows.RegQueryValueEx(key, nameUTF16, nil, &dataType, (*byte)(unsafe.Pointer(&buf[0])), &dataLen)
	if err != nil {
		return ""
	}

	return windows.UTF16ToString(buf)
}
