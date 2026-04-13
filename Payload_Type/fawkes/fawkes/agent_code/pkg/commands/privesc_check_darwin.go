//go:build darwin

package commands

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type PrivescCheckCommand struct{}

func (c *PrivescCheckCommand) Name() string {
	return "privesc-check"
}

func (c *PrivescCheckCommand) Description() string {
	return "macOS privilege escalation enumeration: SUID/SGID binaries, sudo rules, writable LaunchDaemons/Agents, TCC database, dylib hijacking, SIP status (T1548)"
}

type privescCheckArgs struct {
	Action string `json:"action"`
}

func (c *PrivescCheckCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[privescCheckArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Action == "" {
		args.Action = "all"
	}

	switch strings.ToLower(args.Action) {
	case "all":
		return macPrivescCheckAll()
	case "suid":
		return macPrivescCheckSUID()
	case "sudo":
		return macPrivescCheckSudo()
	case "launchdaemons":
		return macPrivescCheckLaunchDaemons()
	case "tcc":
		return macPrivescCheckTCC()
	case "dylib":
		return macPrivescCheckDylib()
	case "sip":
		return macPrivescCheckSIP()
	case "writable":
		return macPrivescCheckWritable()
	default:
		return errorf("Unknown action: %s. Use: all, suid, sudo, launchdaemons, tcc, dylib, sip, writable", args.Action)
	}
}

func macPrivescCheckAll() structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== macOS PRIVILEGE ESCALATION CHECK ===\n\n")

	sb.WriteString("--- SIP Status ---\n")
	sb.WriteString(macPrivescCheckSIP().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- SUID/SGID Binaries ---\n")
	sb.WriteString(macPrivescCheckSUID().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Sudo Rules ---\n")
	sb.WriteString(macPrivescCheckSudo().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- LaunchDaemons / LaunchAgents ---\n")
	sb.WriteString(macPrivescCheckLaunchDaemons().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- TCC Database ---\n")
	sb.WriteString(macPrivescCheckTCC().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Dylib Hijacking ---\n")
	sb.WriteString(macPrivescCheckDylib().Output)
	sb.WriteString("\n\n")

	sb.WriteString("--- Writable Paths ---\n")
	sb.WriteString(macPrivescCheckWritable().Output)

	return successResult(sb.String())
}

// nativeIDString produces output similar to `id` using native Go APIs.
// Returns "uid=501(gary) gid=20(staff) groups=20(staff),80(admin),..."
func nativeIDString() string {
	uid := os.Getuid()
	gid := os.Getgid()

	uidName := strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		uidName = u.Username
	}

	gidName := strconv.Itoa(gid)
	if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
		gidName = g.Name
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("uid=%d(%s) gid=%d(%s)", uid, uidName, gid, gidName))

	groupIDs, err := os.Getgroups()
	if err == nil && len(groupIDs) > 0 {
		sb.WriteString(" groups=")
		for i, gidNum := range groupIDs {
			if i > 0 {
				sb.WriteByte(',')
			}
			name := strconv.Itoa(gidNum)
			if g, err := user.LookupGroupId(strconv.Itoa(gidNum)); err == nil {
				name = g.Name
			}
			sb.WriteString(fmt.Sprintf("%d(%s)", gidNum, name))
		}
	}

	return sb.String()
}

// macIsWritable checks if the current user can write to a path
func macIsWritable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if info.IsDir() {
		f, err := os.CreateTemp(path, "")
		if err != nil {
			return false
		}
		name := f.Name()
		f.Close()
		secureRemove(name)
		return true
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	return true
}
