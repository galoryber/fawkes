//go:build !windows

package commands

func InitAPISpoofing() error  { return nil }
func APISpoofAvailable() bool { return false }
func CleanupAPISpoofing()     {}
