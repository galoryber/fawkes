//go:build darwin

package commands

import (
	"os/exec"
)

// setHiddenFlag sets or clears the macOS UF_HIDDEN flag via chflags.
func setHiddenFlag(path string, hidden bool) error {
	flag := "hidden"
	if !hidden {
		flag = "nohidden"
	}
	return exec.Command("chflags", flag, path).Run()
}
