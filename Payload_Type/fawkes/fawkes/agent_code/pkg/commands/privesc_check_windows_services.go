//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// winPrivescCheckServices checks for unquoted service paths and modifiable service binaries
func winPrivescCheckServices() structs.CommandResult {
	var sb strings.Builder

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Failed to connect to SCM: %v", err)
	}
	defer m.Disconnect()

	services, err := m.ListServices()
	if err != nil {
		return errorf("Failed to list services: %v", err)
	}

	var unquoted []string
	var modifiable []string
	var writableDir []string
	checked := 0

	for _, name := range services {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		cfg, err := s.Config()
		s.Close()
		if err != nil {
			continue
		}
		checked++

		binPath := cfg.BinaryPathName
		if binPath == "" {
			continue
		}

		// Check for unquoted service paths
		if isUnquotedServicePath(binPath) {
			unquoted = append(unquoted, fmt.Sprintf("  %s\n    Path: %s\n    Start: %s", name, binPath, startTypeString(cfg.StartType)))
		}

		// Check if the service binary is writable
		exePath := extractExePath(binPath)
		if exePath != "" {
			if isFileWritable(exePath) {
				modifiable = append(modifiable, fmt.Sprintf("  [!!] %s\n    Path: %s (WRITABLE)", name, exePath))
			}
			// Check if the directory containing the binary is writable
			dir := filepath.Dir(exePath)
			if isDirWritable(dir) {
				writableDir = append(writableDir, fmt.Sprintf("  [!] %s\n    Dir: %s (WRITABLE — DLL planting possible)", name, dir))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("Checked %d services:\n\n", checked))

	sb.WriteString(fmt.Sprintf("Unquoted service paths (%d):\n", len(unquoted)))
	if len(unquoted) > 0 {
		sb.WriteString(strings.Join(unquoted, "\n"))
		sb.WriteString("\n[!] Unquoted paths with spaces allow binary planting in intermediate directories")
	} else {
		sb.WriteString("  (none found)")
	}

	sb.WriteString(fmt.Sprintf("\n\nModifiable service binaries (%d):\n", len(modifiable)))
	if len(modifiable) > 0 {
		sb.WriteString(strings.Join(modifiable, "\n"))
		sb.WriteString("\n[!!] Replace the binary to execute as the service account (often SYSTEM)")
	} else {
		sb.WriteString("  (none found)")
	}

	if len(writableDir) > 0 {
		sb.WriteString(fmt.Sprintf("\n\nWritable service binary directories (%d):\n", len(writableDir)))
		sb.WriteString(strings.Join(writableDir, "\n"))
	}

	return successResult(sb.String())
}

// winPrivescCheckServiceRegistryPerms checks service registry key permissions (T1574.011).
// If a non-admin user can write to a service's registry key, they can modify the ImagePath
// to point to a malicious binary, achieving privilege escalation when the service restarts.
func winPrivescCheckServiceRegistryPerms() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Service Registry Permissions Check (T1574.011) ===\n\n")

	servicesKeyPath := `SYSTEM\CurrentControlSet\Services`

	var servicesKey windows.Handle
	err := windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(servicesKeyPath), 0, windows.KEY_READ, &servicesKey)
	if err != nil {
		return errorf("Failed to open Services registry key: %v", err)
	}
	defer windows.RegCloseKey(servicesKey)

	// Enumerate service subkeys
	var writable []string
	checked := 0
	maxNameLen := uint32(256)

	for i := uint32(0); ; i++ {
		nameBuffer := make([]uint16, maxNameLen)
		nameLen := maxNameLen
		err := windows.RegEnumKeyEx(servicesKey, i, &nameBuffer[0], &nameLen, nil, nil, nil, nil)
		if err != nil {
			break
		}
		serviceName := windows.UTF16ToString(nameBuffer[:nameLen])

		// Try to open the service key with write permissions
		subKeyPath := servicesKeyPath + `\` + serviceName
		var subKey windows.Handle
		err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(subKeyPath), 0, windows.KEY_SET_VALUE, &subKey)
		if err == nil {
			// We have write access — this is a privilege escalation vector
			windows.RegCloseKey(subKey)

			// Read the current ImagePath to show what service this is
			imagePath := readRegString(windows.HKEY_LOCAL_MACHINE, subKeyPath, "ImagePath")
			startType := readRegDWORD(windows.HKEY_LOCAL_MACHINE, subKeyPath, "Start")
			objectName := readRegString(windows.HKEY_LOCAL_MACHINE, subKeyPath, "ObjectName")

			if imagePath != "" {
				startStr := "unknown"
				switch startType {
				case 0:
					startStr = "Boot"
				case 1:
					startStr = "System"
				case 2:
					startStr = "Auto"
				case 3:
					startStr = "Manual"
				case 4:
					startStr = "Disabled"
				}

				runAs := objectName
				if runAs == "" {
					runAs = "LocalSystem"
				}

				severity := "[!]"
				if strings.EqualFold(runAs, "LocalSystem") || strings.EqualFold(runAs, "NT AUTHORITY\\SYSTEM") {
					severity = "[!!]"
				}

				writable = append(writable, fmt.Sprintf("  %s %s\n       ImagePath: %s\n       Start: %s | RunAs: %s\n       Registry: HKLM\\%s (WRITABLE)",
					severity, serviceName, imagePath, startStr, runAs, subKeyPath))
			}
		}
		checked++
	}

	sb.WriteString(fmt.Sprintf("Checked %d service registry keys\n\n", checked))

	if len(writable) > 0 {
		sb.WriteString(fmt.Sprintf("--- Writable Service Registry Keys (%d) ---\n", len(writable)))
		sb.WriteString(strings.Join(writable, "\n\n"))
		sb.WriteString("\n\n[!!] Modify ImagePath to point to your payload, then restart the service.\n")
		sb.WriteString("     Services running as SYSTEM provide full privilege escalation.\n")
		sb.WriteString("     Use: reg write -path \"HKLM\\...\\ImagePath\" -value \"C:\\path\\to\\payload.exe\"\n")
	} else {
		sb.WriteString("[*] No writable service registry keys found with current permissions.\n")
		sb.WriteString("    This is expected for standard user accounts.\n")
	}

	return successResult(sb.String())
}

// winPrivescCheckWritable checks for writable directories in PATH
func winPrivescCheckWritable() structs.CommandResult {
	var sb strings.Builder

	pathDirs := strings.Split(os.Getenv("PATH"), ";")
	var writablePATH []string

	for _, dir := range pathDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if isDirWritable(dir) {
			writablePATH = append(writablePATH, "  "+dir)
		}
	}

	sb.WriteString(fmt.Sprintf("Writable PATH directories (%d of %d):\n", len(writablePATH), len(pathDirs)))
	if len(writablePATH) > 0 {
		sb.WriteString(strings.Join(writablePATH, "\n"))
		sb.WriteString("\n[!] Writable PATH directories enable DLL hijacking and binary planting")
		sb.WriteString("\n    Place a malicious DLL/EXE with a commonly-loaded name to hijack execution")
	} else {
		sb.WriteString("  (none — PATH is clean)")
	}

	// Check common DLL hijack target directories
	sb.WriteString("\n\nDLL Hijack Target Directories:\n")
	hijackDirs := []struct {
		path string
		desc string
	}{
		{`C:\Python27`, "Python 2.7 (common DLL hijack target)"},
		{`C:\Python36`, "Python 3.6"},
		{`C:\Python37`, "Python 3.7"},
		{`C:\Python38`, "Python 3.8"},
		{`C:\Python39`, "Python 3.9"},
		{`C:\Python310`, "Python 3.10"},
		{`C:\Python311`, "Python 3.11"},
		{`C:\Python312`, "Python 3.12"},
		{os.Getenv("TEMP"), "Current user TEMP directory"},
	}

	for _, d := range hijackDirs {
		if d.path == "" {
			continue
		}
		if isDirWritable(d.path) {
			sb.WriteString(fmt.Sprintf("  [!] %s — %s (WRITABLE)\n", d.path, d.desc))
		}
	}

	return successResult(sb.String())
}
