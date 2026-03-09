//go:build darwin

package commands

import (
	"strings"

	"fawkes/pkg/structs"
)

func readClipboard() structs.CommandResult {
	out, err := execCmdTimeoutOutput("pbpaste")
	if err != nil {
		return errorf("Failed to read clipboard: %v", err)
	}

	text := string(out)
	if text == "" {
		return successResult("Clipboard is empty")
	}

	return successf("Clipboard contents (%d chars):\n%s", len(text), text)
}

func writeClipboard(text string) structs.CommandResult {
	cmd, cancel := execCmdCtx("pbcopy")
	defer cancel()
	cmd.Stdin = strings.NewReader(text)
	if err := cmd.Run(); err != nil {
		return errorf("Failed to write to clipboard: %v", err)
	}

	return successf("Successfully wrote %d characters to clipboard", len(text))
}

func clipReadText() string {
	out, err := execCmdTimeoutOutput("pbpaste")
	if err != nil {
		return ""
	}
	return string(out)
}
