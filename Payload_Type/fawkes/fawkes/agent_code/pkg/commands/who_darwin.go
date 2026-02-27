//go:build darwin
// +build darwin

package commands

import (
	"fmt"
	"os/exec"
	"strings"
)

func whoPlatform(args whoArgs) string {
	var sb strings.Builder
	sb.WriteString(whoHeader())

	// macOS has the `who` command built-in
	cmdArgs := []string{}
	if args.All {
		cmdArgs = append(cmdArgs, "-a")
	}

	out, err := exec.Command("who", cmdArgs...).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error running who: %v", err)
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return ""
	}

	// Parse `who` output: user tty date time (host)
	count := 0
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		user := fields[0]
		tty := fields[1]
		loginTime := strings.Join(fields[2:], " ")
		host := ""

		// Extract host from parentheses if present
		if idx := strings.Index(loginTime, "("); idx != -1 {
			endIdx := strings.Index(loginTime, ")")
			if endIdx > idx {
				host = loginTime[idx+1 : endIdx]
				loginTime = strings.TrimSpace(loginTime[:idx])
			}
		}

		sb.WriteString(whoEntry(user, tty, loginTime, host, "active"))
		count++
	}

	if count == 0 {
		return ""
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d active session(s)", count))
	return sb.String()
}
