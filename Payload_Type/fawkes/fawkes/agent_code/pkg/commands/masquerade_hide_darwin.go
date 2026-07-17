//go:build darwin

package commands

import (
)

// setHiddenFlag sets or clears the macOS UF_HIDDEN flag via chflags.
func setHiddenFlag(path string, hidden bool) error {
	flag := "hidden"
	if !hidden {
		flag = "nohidden"
	}
	return safeCmd("chflags", flag, path).Run()
}
