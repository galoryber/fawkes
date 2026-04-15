//go:build linux

package commands

// setHiddenFlag is a no-op on Linux. Linux uses dot-prefix convention only.
// The chattr +i (immutable) attribute requires root and is too invasive for hide.
func setHiddenFlag(path string, hidden bool) error {
	// Linux has no filesystem-level hidden attribute.
	// Dot-prefix renaming (handled by masquerade_hide.go) is the standard mechanism.
	return nil
}
