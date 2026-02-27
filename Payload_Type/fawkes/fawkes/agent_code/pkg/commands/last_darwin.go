//go:build darwin

package commands

import (
	"fmt"
	"os/exec"
	"strings"
)

func lastPlatform(args lastArgs) string {
	var sb strings.Builder
	sb.WriteString("=== Login History ===\n\n")

	// macOS has the `last` command built-in
	cmdArgs := []string{"-n", fmt.Sprintf("%d", args.Count)}
	if args.User != "" {
		cmdArgs = append(cmdArgs, args.User)
	}

	out, err := exec.Command("last", cmdArgs...).CombinedOutput()
	if err != nil {
		sb.WriteString(fmt.Sprintf("Error running last: %v\n", err))
		return sb.String()
	}

	sb.Write(out)
	return sb.String()
}
