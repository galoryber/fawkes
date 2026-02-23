//go:build linux

package commands

// registerPlatformCommands registers Linux-specific commands.
func registerPlatformCommands() {
	RegisterCommand(&CrontabCommand{})
	RegisterCommand(&SSHKeysCommand{})
	RegisterCommand(&PrivescCheckCommand{})
	RegisterCommand(&ProcInfoCommand{})
	RegisterCommand(&SystemdPersistCommand{})
	RegisterCommand(&ShellConfigCommand{})
}
