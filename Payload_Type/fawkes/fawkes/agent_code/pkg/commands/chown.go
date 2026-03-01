package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type ChownCommand struct{}

func (c *ChownCommand) Name() string        { return "chown" }
func (c *ChownCommand) Description() string { return "Change file and directory ownership (T1222)" }

type chownArgs struct {
	Path      string `json:"path"`      // file or directory
	Owner     string `json:"owner"`     // username or UID
	Group     string `json:"group"`     // group name or GID (optional)
	Recursive bool   `json:"recursive"` // apply recursively
}

func (c *ChownCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -path <file> -owner <user> [-group <group>] [-recursive true]",
			Status:    "error",
			Completed: true,
		}
	}

	var args chownArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		// Parse "owner:group path" or "owner path"
		parts := strings.Fields(task.Params)
		if len(parts) >= 2 {
			ownerGroup := parts[0]
			args.Path = parts[1]
			if idx := strings.IndexByte(ownerGroup, ':'); idx >= 0 {
				args.Owner = ownerGroup[:idx]
				args.Group = ownerGroup[idx+1:]
			} else {
				args.Owner = ownerGroup
			}
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path parameter is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Owner == "" && args.Group == "" {
		return structs.CommandResult{
			Output:    "Error: at least one of owner or group is required",
			Status:    "error",
			Completed: true,
		}
	}

	if runtime.GOOS == "windows" {
		return structs.CommandResult{
			Output:    "Error: chown is not supported on Windows. Use icacls or Windows ACL tools instead.",
			Status:    "error",
			Completed: true,
		}
	}

	// Resolve path
	path := args.Path
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Resolve UID
	uid := -1
	if args.Owner != "" {
		uid, err = chownResolveUID(args.Owner)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error resolving owner '%s': %v", args.Owner, err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	// Resolve GID
	gid := -1
	if args.Group != "" {
		gid, err = chownResolveGID(args.Group)
		if err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error resolving group '%s': %v", args.Group, err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if !args.Recursive || !info.IsDir() {
		// Single file
		if err := os.Chown(path, uid, gid); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    chownFormatResult(path, args.Owner, args.Group, uid, gid),
			Status:    "success",
			Completed: true,
		}
	}

	// Recursive
	var sb strings.Builder
	changed := 0
	errors := 0

	walkErr := filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			errors++
			sb.WriteString(fmt.Sprintf("[-] %s — %v\n", p, err))
			return nil
		}
		if err := os.Chown(p, uid, gid); err != nil {
			errors++
			sb.WriteString(fmt.Sprintf("[-] %s — %v\n", p, err))
			return nil
		}
		changed++
		return nil
	})

	if walkErr != nil {
		sb.WriteString(fmt.Sprintf("[-] Walk error: %v\n", walkErr))
	}

	ownerStr := chownFormatOwnership(args.Owner, args.Group, uid, gid)
	sb.WriteString(fmt.Sprintf("[*] %d items changed to %s", changed, ownerStr))
	if errors > 0 {
		sb.WriteString(fmt.Sprintf(", %d errors", errors))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func chownResolveUID(owner string) (int, error) {
	// Try as numeric UID first
	if uid, err := strconv.Atoi(owner); err == nil {
		return uid, nil
	}
	// Look up by username
	u, err := user.Lookup(owner)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(u.Uid)
}

func chownResolveGID(group string) (int, error) {
	// Try as numeric GID first
	if gid, err := strconv.Atoi(group); err == nil {
		return gid, nil
	}
	// Look up by group name
	g, err := user.LookupGroup(group)
	if err != nil {
		return -1, err
	}
	return strconv.Atoi(g.Gid)
}

func chownFormatResult(path, owner, group string, uid, gid int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] %s\n", path))
	sb.WriteString(fmt.Sprintf("    Owner: %s\n", chownFormatOwnership(owner, group, uid, gid)))
	return sb.String()
}

func chownFormatOwnership(owner, group string, uid, gid int) string {
	parts := []string{}
	if owner != "" {
		parts = append(parts, fmt.Sprintf("%s (uid=%d)", owner, uid))
	}
	if group != "" {
		parts = append(parts, fmt.Sprintf("%s (gid=%d)", group, gid))
	}
	return strings.Join(parts, ", ")
}
