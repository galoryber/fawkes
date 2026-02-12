//go:build !windows

package commands

// registerPlatformCommands is a no-op on non-Windows platforms.
// All cross-platform commands are registered in registry.go.
func registerPlatformCommands() {}
