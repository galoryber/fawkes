package commands

import "strings"

type launchdEntry struct {
	PID    string
	Status string
	Label  string
}

// parseLaunchdListOutput parses the output of `launchctl list` into structured entries.
// The output format is: PID<tab>Status<tab>Label (one per line), with a header line.
func parseLaunchdListOutput(output string) []launchdEntry {
	var results []launchdEntry
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[2] == "Label" {
			continue
		}
		results = append(results, launchdEntry{fields[0], fields[1], fields[2]})
	}
	return results
}
