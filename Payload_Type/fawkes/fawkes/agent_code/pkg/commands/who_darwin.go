//go:build darwin
// +build darwin

package commands

import (
	"os/exec"
	"strings"
)

func whoPlatform(args whoArgs) []whoSessionEntry {
	cmdArgs := []string{}
	if args.All {
		cmdArgs = append(cmdArgs, "-a")
	}

	out, err := exec.Command("who", cmdArgs...).CombinedOutput()
	if err != nil {
		return nil
	}

	output := strings.TrimSpace(string(out))
	if output == "" {
		return nil
	}

	var entries []whoSessionEntry
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		user := fields[0]
		tty := fields[1]
		loginTime := strings.Join(fields[2:], " ")
		host := ""

		if idx := strings.Index(loginTime, "("); idx != -1 {
			endIdx := strings.Index(loginTime, ")")
			if endIdx > idx {
				host = loginTime[idx+1 : endIdx]
				loginTime = strings.TrimSpace(loginTime[:idx])
			}
		}

		from := host
		if from == "" {
			from = "-"
		}

		entries = append(entries, whoSessionEntry{
			User:      user,
			TTY:       tty,
			LoginTime: loginTime,
			From:      from,
			Status:    "active",
		})
	}

	return entries
}
