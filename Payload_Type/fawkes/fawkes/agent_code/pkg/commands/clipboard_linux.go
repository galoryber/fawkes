//go:build linux

package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

// clipboardTools lists clipboard read/write tools in preference order.
// X11: xclip, xsel. Wayland: wl-paste/wl-copy.
var clipboardReadTools = []struct {
	name string
	args []string
}{
	{"wl-paste", []string{"--no-newline"}},
	{"xclip", []string{"-selection", "clipboard", "-o"}},
	{"xsel", []string{"--clipboard", "--output"}},
}

var clipboardWriteTools = []struct {
	name string
	args []string
}{
	{"wl-copy", nil},
	{"xclip", []string{"-selection", "clipboard"}},
	{"xsel", []string{"--clipboard", "--input"}},
}

func readClipboard() structs.CommandResult {
	text, tool, err := clipReadWithTool()
	if err != nil {
		return errorf("Failed to read clipboard: %v\nEnsure xclip, xsel (X11) or wl-paste (Wayland) is installed.", err)
	}

	if text == "" {
		return successf("Clipboard is empty (via %s)", tool)
	}

	return successf("Clipboard contents (%d chars, via %s):\n%s", len(text), tool, text)
}

func writeClipboard(text string) structs.CommandResult {
	for _, tool := range clipboardWriteTools {
		path, err := exec.LookPath(tool.name)
		if err != nil {
			continue
		}
		cmd, cancel := execCmdCtx(path, tool.args...)
		cmd.Stdin = strings.NewReader(text)
		err = cmd.Run()
		cancel()
		if err != nil {
			continue
		}
		return successf("Successfully wrote %d characters to clipboard (via %s)", len(text), tool.name)
	}

	return errorResult("Failed to write to clipboard: no clipboard tool found. Install xclip, xsel (X11) or wl-copy (Wayland).")
}

func clipReadText() string {
	text, _, err := clipReadWithTool()
	if err != nil {
		return ""
	}
	return text
}

// clipReadWithTool tries each clipboard read tool and returns the text + tool name.
func clipReadWithTool() (string, string, error) {
	var lastErr error
	for _, tool := range clipboardReadTools {
		path, err := exec.LookPath(tool.name)
		if err != nil {
			lastErr = err
			continue
		}
		out, err := execCmdTimeoutOutput(path, tool.args...)
		if err != nil {
			lastErr = err
			continue
		}
		return string(out), tool.name, nil
	}
	if lastErr != nil {
		return "", "", lastErr
	}
	return "", "", fmt.Errorf("no clipboard tool available")
}
