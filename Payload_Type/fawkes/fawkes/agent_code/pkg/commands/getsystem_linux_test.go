//go:build linux
// +build linux

package commands

import (
	"os"
	"testing"
)

func TestGetsystemLinux_ExploitableSUIDs(t *testing.T) {
	result := findExploitableSUID()
	_ = result // Just verify it doesn't panic
}

func TestGetsystemLinux_CheckWritablePasswd(t *testing.T) {
	result := checkWritablePasswd()
	if os.Getuid() != 0 && result {
		t.Error("Non-root user should not have writable /etc/passwd")
	}
}

func TestGetsystemLinux_CheckDockerGroup(t *testing.T) {
	_ = checkDockerGroup()
}

func TestGetsystemLinux_GetCurrentIdentity(t *testing.T) {
	identity := getCurrentLinuxIdentity()
	if identity == "" {
		t.Error("getCurrentLinuxIdentity should not return empty")
	}
}

func TestGetsystemLinux_ExploitableSUIDList(t *testing.T) {
	if len(exploitableSUIDs) == 0 {
		t.Error("exploitableSUIDs list should not be empty")
	}
}
