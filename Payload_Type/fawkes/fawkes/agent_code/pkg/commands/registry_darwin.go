//go:build darwin

package commands

// registerPlatformCommands registers macOS-specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
	RegisterCommand(&LaunchAgentCommand{})
}
