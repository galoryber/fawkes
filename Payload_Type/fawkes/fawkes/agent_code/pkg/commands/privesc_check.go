//go:build linux

package commands

import (
	"encoding/json"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "Linux privilege escalation enumeration: SUID/SGID binaries, capabilities, sudo rules, writable paths, container detection, cron script hijacking, NFS no_root_squash, systemd unit hijacking, sudo token reuse, PATH hijacking, docker group, ld.so.preload, security modules (T1548)"
}

type privescCheckArgs struct {
	Action string `json:"action"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	var args privescCheckArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			// Plain text fallback: "suid", "capabilities", "sudo", "writable", "container", "all"
			args.Action = strings.TrimSpace(task.Params)
		}
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return privescCheckAll()
	case "suid":
		return privescCheckSUID()
	case "capabilities":
		return privescCheckCapabilities()
	case "sudo":
		return privescCheckSudo()
	case "writable":
		return privescCheckWritable()
	case "container":
		return privescCheckContainer()
	case "cron":
		return privescCheckCronScripts()
	case "nfs":
		return privescCheckNFS()
	case "systemd":
		return privescCheckSystemdUnits()
	case "sudo-token":
		return privescCheckSudoToken()
	case "path-hijack":
		return privescCheckPathHijack()
	case "docker-group":
		return privescCheckDockerGroup()
	case "group":
		return privescCheckDangerousGroups()
	case "polkit":
		return privescCheckPolkit()
	case "modprobe":
		return privescCheckModprobe()
	case "ld-preload":
		return privescCheckLdPreload()
	case "security":
		return privescCheckSecurityModules()
	default:
		return errorf("Unknown action: %s. Use: all, suid, capabilities, sudo, writable, container, cron, nfs, systemd, sudo-token, path-hijack, docker-group, group, polkit, modprobe, ld-preload, security", args.Action)
	}
}

// privescCheckAll runs all checks and returns a combined report
func privescCheckAll() structs.CommandResult {
	var sb strings.Builder

	sb.WriteString("=== LINUX PRIVILEGE ESCALATION CHECK ===\n\n")

	// SUID/SGID
	sb.WriteString("--- SUID/SGID Binaries ---\n")
	suidResult := privescCheckSUID()
	sb.WriteString(suidResult.Output)
	sb.WriteString("\n\n")

	// Capabilities
	sb.WriteString("--- File Capabilities ---\n")
	capResult := privescCheckCapabilities()
	sb.WriteString(capResult.Output)
	sb.WriteString("\n\n")

	// Sudo
	sb.WriteString("--- Sudo Rules ---\n")
	sudoResult := privescCheckSudo()
	sb.WriteString(sudoResult.Output)
	sb.WriteString("\n\n")

	// Writable paths
	sb.WriteString("--- Writable Paths ---\n")
	writableResult := privescCheckWritable()
	sb.WriteString(writableResult.Output)
	sb.WriteString("\n\n")

	// Container detection
	sb.WriteString("--- Container Detection ---\n")
	containerResult := privescCheckContainer()
	sb.WriteString(containerResult.Output)
	sb.WriteString("\n\n")

	// Writable cron scripts
	sb.WriteString("--- Cron Script Hijacking ---\n")
	cronResult := privescCheckCronScripts()
	sb.WriteString(cronResult.Output)
	sb.WriteString("\n\n")

	// NFS no_root_squash
	sb.WriteString("--- NFS Shares ---\n")
	nfsResult := privescCheckNFS()
	sb.WriteString(nfsResult.Output)
	sb.WriteString("\n\n")

	// Writable systemd units
	sb.WriteString("--- Systemd Unit Hijacking ---\n")
	systemdResult := privescCheckSystemdUnits()
	sb.WriteString(systemdResult.Output)
	sb.WriteString("\n\n")

	// Sudo token reuse
	sb.WriteString("--- Sudo Token Reuse ---\n")
	sudoTokenResult := privescCheckSudoToken()
	sb.WriteString(sudoTokenResult.Output)
	sb.WriteString("\n\n")

	// PATH hijacking
	sb.WriteString("--- PATH Hijacking ---\n")
	pathResult := privescCheckPathHijack()
	sb.WriteString(pathResult.Output)
	sb.WriteString("\n\n")

	// Docker group
	sb.WriteString("--- Docker Group ---\n")
	dockerResult := privescCheckDockerGroup()
	sb.WriteString(dockerResult.Output)
	sb.WriteString("\n\n")

	// Dangerous group memberships
	sb.WriteString("--- Dangerous Groups ---\n")
	groupResult := privescCheckDangerousGroups()
	sb.WriteString(groupResult.Output)
	sb.WriteString("\n\n")

	// Polkit rules
	sb.WriteString("--- Polkit Rules ---\n")
	polkitResult := privescCheckPolkit()
	sb.WriteString(polkitResult.Output)
	sb.WriteString("\n\n")

	// Modprobe hooks
	sb.WriteString("--- Modprobe Hooks ---\n")
	modprobeResult := privescCheckModprobe()
	sb.WriteString(modprobeResult.Output)
	sb.WriteString("\n\n")

	// ld.so.preload library injection
	sb.WriteString("--- ld.so.preload ---\n")
	ldResult := privescCheckLdPreload()
	sb.WriteString(ldResult.Output)
	sb.WriteString("\n\n")

	// Security modules (AppArmor / SELinux)
	sb.WriteString("--- Security Modules ---\n")
	secResult := privescCheckSecurityModules()
	sb.WriteString(secResult.Output)

	return successResult(sb.String())
}

// isWritable checks if the current user can write to a path
func isWritable(path string) bool {
	f, err := os.CreateTemp(path, "")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	secureRemove(name)
	return true
}

// isReadable checks if the current user can read a path
func isReadable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	f.Close()
	return true
}
