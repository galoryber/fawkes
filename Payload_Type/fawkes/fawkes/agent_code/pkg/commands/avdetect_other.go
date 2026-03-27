//go:build !linux && !darwin

package commands

// avDeepScan is a stub on platforms without deep scanning support.
// Deep scanning is implemented for Linux (kernel modules, systemd units, config dirs)
// and macOS (kexts, system extensions, LaunchDaemons, apps, config dirs).
func avDeepScan() []detectedProduct {
	return nil
}
