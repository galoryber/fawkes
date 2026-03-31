//go:build linux

package commands

import (
	"encoding/json"
	"fmt"
	"os/user"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// PersistEnumCommand enumerates Linux persistence mechanisms.
type PersistEnumCommand struct{}

func (c *PersistEnumCommand) Name() string { return "persist-enum" }
func (c *PersistEnumCommand) Description() string {
	return "Enumerate Linux persistence mechanisms — cron, systemd, shell profiles, SSH keys, init scripts, udev rules, kernel modules, motd, at jobs, D-Bus, PAM, package hooks, logrotate, NetworkManager, anacron (T1547/T1546/T1556/T1053)"
}

func (c *PersistEnumCommand) Execute(task structs.Task) structs.CommandResult {
	var args persistEnumArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Error parsing parameters: %v", err)
		}
	}
	if args.Category == "" {
		args.Category = "all"
	}

	var sb strings.Builder
	sb.WriteString("=== Persistence Enumeration (Linux) ===\n\n")

	cat := strings.ToLower(args.Category)
	found := 0

	if cat == "all" || cat == "cron" {
		found += persistEnumCron(&sb)
	}
	if cat == "all" || cat == "systemd" {
		found += persistEnumSystemd(&sb)
	}
	if cat == "all" || cat == "shell" {
		found += persistEnumShellProfiles(&sb)
	}
	if cat == "all" || cat == "startup" {
		found += persistEnumStartup(&sb)
	}
	if cat == "all" || cat == "ssh" {
		found += persistEnumSSHKeys(&sb)
	}
	if cat == "all" || cat == "preload" {
		found += persistEnumPreload(&sb)
	}
	if cat == "all" || cat == "udev" {
		found += persistEnumUdev(&sb)
	}
	if cat == "all" || cat == "modules" {
		found += persistEnumKernelModules(&sb)
	}
	if cat == "all" || cat == "motd" {
		found += persistEnumMotd(&sb)
	}
	if cat == "all" || cat == "at" {
		found += persistEnumAtJobs(&sb)
	}
	if cat == "all" || cat == "dbus" {
		found += persistEnumDBus(&sb)
	}
	if cat == "all" || cat == "pam" {
		found += persistEnumPAM(&sb)
	}
	if cat == "all" || cat == "packages" {
		found += persistEnumPackageHooks(&sb)
	}
	if cat == "all" || cat == "logrotate" {
		found += persistEnumLogrotate(&sb)
	}
	if cat == "all" || cat == "networkmanager" {
		found += persistEnumNetworkManager(&sb)
	}
	if cat == "all" || cat == "anacron" {
		found += persistEnumAnacron(&sb)
	}

	sb.WriteString(fmt.Sprintf("\n=== Total: %d persistence items found ===\n", found))

	return successResult(sb.String())
}

func currentHomeDir() string {
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	return "/root"
}
