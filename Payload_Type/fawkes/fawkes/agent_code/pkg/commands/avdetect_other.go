//go:build !linux

package commands

// avDeepScan is a stub on non-Linux platforms.
// Deep scanning currently only supports Linux (kernel modules, systemd units, config dirs).
func avDeepScan() []detectedProduct {
	return nil
}
