//go:build !windows
// +build !windows

package commands

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type WhoamiCommand struct{}

func (c *WhoamiCommand) Name() string {
	return "whoami"
}

func (c *WhoamiCommand) Description() string {
	return "Display current user identity and security context"
}

func (c *WhoamiCommand) Execute(task structs.Task) structs.CommandResult {
	var lines []string

	u, err := user.Current()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Failed to get current user: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	lines = append(lines, fmt.Sprintf("User:     %s", u.Username))
	lines = append(lines, fmt.Sprintf("UID:      %s", u.Uid))
	lines = append(lines, fmt.Sprintf("GID:      %s", u.Gid))
	if u.HomeDir != "" {
		lines = append(lines, fmt.Sprintf("Home:     %s", u.HomeDir))
	}

	// Check for root
	if u.Uid == "0" {
		lines = append(lines, "Privilege: root")
	}

	// Effective vs real UID (detect suid)
	euid := os.Geteuid()
	ruid := os.Getuid()
	if euid != ruid {
		lines = append(lines, fmt.Sprintf("EUID:     %d (differs from UID — possible SUID)", euid))
	}

	// Supplementary groups
	gids, err := os.Getgroups()
	if err == nil && len(gids) > 0 {
		lines = append(lines, "")
		lines = append(lines, "Groups:")
		for _, gid := range gids {
			g, gErr := user.LookupGroupId(strconv.Itoa(gid))
			if gErr == nil {
				lines = append(lines, fmt.Sprintf("  %s (gid=%d)", g.Name, gid))
			} else {
				lines = append(lines, fmt.Sprintf("  gid=%d", gid))
			}
		}
	}

	return structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
}
