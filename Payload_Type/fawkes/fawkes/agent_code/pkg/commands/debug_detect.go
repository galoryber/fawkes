package commands

import (
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/shirou/gopsutil/v3/process"
)

// DebugDetectCommand detects debuggers and analysis tools.
type DebugDetectCommand struct{}

func (c *DebugDetectCommand) Name() string { return "debug-detect" }
func (c *DebugDetectCommand) Description() string {
	return "Detect attached debuggers and analysis tools"
}

// debugCheck represents a single anti-debug check result.
type debugCheck struct {
	Name    string
	Status  string // "CLEAN", "DETECTED", "WARNING", "ERROR"
	Details string
}

// knownDebuggerProcesses maps lowercase process names to debugger/analysis tool info.
var knownDebuggerProcesses = map[string]string{
	// Windows debuggers
	"windbg.exe":           "WinDbg (Microsoft)",
	"windbgx.exe":          "WinDbg Preview (Microsoft)",
	"x64dbg.exe":           "x64dbg",
	"x32dbg.exe":           "x32dbg",
	"ollydbg.exe":          "OllyDbg",
	"ida.exe":              "IDA Pro (Hex-Rays)",
	"ida64.exe":            "IDA Pro 64-bit (Hex-Rays)",
	"idag.exe":             "IDA GUI (Hex-Rays)",
	"idag64.exe":           "IDA GUI 64-bit (Hex-Rays)",
	"idaq.exe":             "IDA Qt (Hex-Rays)",
	"idaq64.exe":           "IDA Qt 64-bit (Hex-Rays)",
	"idaw.exe":             "IDA (Hex-Rays)",
	"idaw64.exe":           "IDA 64-bit (Hex-Rays)",
	"immunitydebugger.exe": "Immunity Debugger",
	"devenv.exe":           "Visual Studio",
	"dnspy.exe":            "dnSpy (.NET Decompiler)",
	"dotpeek.exe":          "dotPeek (JetBrains)",
	"processhacker.exe":    "Process Hacker",
	"procmon.exe":          "Process Monitor (Sysinternals)",
	"procmon64.exe":        "Process Monitor 64-bit (Sysinternals)",
	"procexp.exe":          "Process Explorer (Sysinternals)",
	"procexp64.exe":        "Process Explorer 64-bit (Sysinternals)",
	"apimonitor.exe":       "API Monitor",
	"apimonitor-x64.exe":   "API Monitor 64-bit",
	"fiddler.exe":          "Fiddler (HTTP Debugger)",
	"wireshark.exe":        "Wireshark (Network Analyzer)",
	"dumpcap.exe":          "Dumpcap (Wireshark)",
	"tcpdump.exe":          "tcpdump",
	"pestudio.exe":         "PEStudio",
	"die.exe":              "Detect It Easy",
	"ghidra.exe":           "Ghidra (NSA)",
	"ghidrarun.exe":        "Ghidra (NSA)",
	"cutter.exe":           "Cutter (Rizin)",
	"binaryninja.exe":      "Binary Ninja",
	"hiew.exe":             "Hiew (Hex Editor)",
	"lordpe.exe":           "LordPE",
	"petools.exe":          "PE Tools",
	"scylla.exe":           "Scylla (Import Reconstructor)",
	"regmon.exe":           "Registry Monitor (Sysinternals)",
	"filemon.exe":          "File Monitor (Sysinternals)",
	"autoruns.exe":         "Autoruns (Sysinternals)",
	"autoruns64.exe":       "Autoruns 64-bit (Sysinternals)",

	// Linux/macOS debuggers
	"gdb":          "GDB (GNU Debugger)",
	"lldb":         "LLDB (LLVM Debugger)",
	"strace":       "strace (Syscall Tracer)",
	"ltrace":       "ltrace (Library Call Tracer)",
	"radare2":      "Radare2",
	"r2":           "Radare2",
	"rizin":        "Rizin",
	"rz-bin":       "Rizin",
	"edb":          "edb (Evan's Debugger)",
	"valgrind":     "Valgrind",
	"tcpdump":      "tcpdump",
	"tshark":       "tshark (Wireshark CLI)",
	"dtrace":       "DTrace",
	"frida":        "Frida",
	"frida-server": "Frida Server",
}

func (c *DebugDetectCommand) Execute(task structs.Task) structs.CommandResult {
	var checks []debugCheck

	// Platform-specific checks
	checks = append(checks, runPlatformDebugChecks()...)

	// Cross-platform: scan for known debugger processes
	checks = append(checks, scanForDebuggerProcesses()...)

	// Format output
	var sb strings.Builder
	sb.WriteString("Debug Detection Results\n")
	sb.WriteString("=======================\n\n")

	detections := 0
	warnings := 0
	errors := 0

	for _, check := range checks {
		indicator := "  "
		switch check.Status {
		case "DETECTED":
			indicator = "!!"
			detections++
		case "WARNING":
			indicator = "??"
			warnings++
		case "ERROR":
			indicator = "xx"
			errors++
		}
		sb.WriteString(fmt.Sprintf("  %s %-35s %-10s %s\n", indicator, check.Name, check.Status, check.Details))
	}

	sb.WriteString("\n")
	if detections > 0 {
		sb.WriteString(fmt.Sprintf("[!] %d DETECTION(s), %d WARNING(s) — debugger/analysis activity likely\n", detections, warnings))
	} else if warnings > 0 {
		sb.WriteString(fmt.Sprintf("[?] %d WARNING(s) — possible analysis activity\n", warnings))
	} else {
		sb.WriteString("[+] All checks CLEAN — no debugger/analysis activity detected\n")
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// scanForDebuggerProcesses scans running processes for known debugger/analysis tools.
func scanForDebuggerProcesses() []debugCheck {
	procs, err := process.Processes()
	if err != nil {
		return []debugCheck{{Name: "Debugger Process Scan", Status: "ERROR", Details: fmt.Sprintf("Failed: %v", err)}}
	}

	var found []string
	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}
		nameLower := strings.ToLower(name)
		if product, ok := knownDebuggerProcesses[nameLower]; ok {
			found = append(found, fmt.Sprintf("%s (PID %d) — %s", name, p.Pid, product))
		}
	}

	if len(found) > 0 {
		return []debugCheck{{
			Name:    "Debugger Process Scan",
			Status:  "DETECTED",
			Details: fmt.Sprintf("%d found: %s", len(found), strings.Join(found, "; ")),
		}}
	}
	return []debugCheck{{Name: "Debugger Process Scan", Status: "CLEAN", Details: "No known debugger processes found"}}
}
