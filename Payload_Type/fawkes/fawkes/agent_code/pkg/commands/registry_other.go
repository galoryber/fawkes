//go:build !windows

package commands

// registerPlatformCommands registers non-Windows (Linux/macOS) specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
}
