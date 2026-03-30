//go:build linux

package commands

import (
	"fmt"
	"runtime"

	"fawkes/pkg/structs"
)

// browserChromiumCookies is not supported on Linux (requires DPAPI or Keychain).
func browserChromiumCookies(args browserArgs) structs.CommandResult {
	return errorf("Chromium cookie decryption requires DPAPI (Windows) or Keychain (macOS). Not supported on %s. Use -browser firefox for Firefox cookies.", runtime.GOOS)
}

// browserChromiumPasswords is not supported on Linux (requires DPAPI or Keychain).
func browserChromiumPasswords(args browserArgs) structs.CommandResult {
	return errorf("Chromium password decryption requires DPAPI (Windows) or Keychain (macOS). Not supported on %s.", runtime.GOOS)
}

// chromeDecryptValue is a stub on Linux — returns an error.
func chromeDecryptValue(encrypted []byte, key []byte) (string, error) {
	return "", fmt.Errorf("Chrome decryption not supported on Linux")
}
