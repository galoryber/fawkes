package commands

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// PkgListCommand lists installed packages/software.
type PkgListCommand struct{}

func (c *PkgListCommand) Name() string        { return "pkg-list" }
func (c *PkgListCommand) Description() string { return "List installed packages and software" }

type pkgListArgs struct {
	Filter string `json:"filter"`
}

func (c *PkgListCommand) Execute(task structs.Task) structs.CommandResult {
	var args pkgListArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args) // best-effort; proceed with defaults on error
	}
	filter := strings.ToLower(args.Filter)

	var output string

	switch runtime.GOOS {
	case "linux":
		output = pkgListLinux(filter)
	case "darwin":
		output = pkgListDarwin(filter)
	case "windows":
		output = pkgListWindows(filter)
	default:
		output = fmt.Sprintf("Unsupported platform: %s", runtime.GOOS)
	}

	return successResult(output)
}

// pkgMatchesFilter returns true if the package name matches the filter (case-insensitive substring).
func pkgMatchesFilter(name, filter string) bool {
	if filter == "" {
		return true
	}
	return strings.Contains(strings.ToLower(name), filter)
}

// filterPkgPairs filters [name, version] pairs by name using the filter.
func filterPkgPairs(pkgs [][2]string, filter string) [][2]string {
	if filter == "" {
		return pkgs
	}
	var result [][2]string
	for _, pkg := range pkgs {
		if pkgMatchesFilter(pkg[0], filter) {
			result = append(result, pkg)
		}
	}
	return result
}

// writePkgPairs writes [name, version] pairs to the builder with a limit.
func writePkgPairs(sb *strings.Builder, pkgs [][2]string, limit int) {
	for i, pkg := range pkgs {
		sb.WriteString(fmt.Sprintf("    %-40s %s\n", pkg[0], pkg[1]))
		if i >= limit-1 {
			sb.WriteString(fmt.Sprintf("    ... and %d more (showing first %d)\n", len(pkgs)-limit, limit))
			break
		}
	}
}

// runQuietCommand runs a command with a timeout and returns stdout, or empty string on error.
func runQuietCommand(name string, args ...string) string {
	out, err := execCmdTimeoutOutput(name, args...)
	if err != nil {
		return ""
	}
	return string(out)
}
