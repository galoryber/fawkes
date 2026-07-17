//go:build linux

package commands

import (
	"fmt"
	"os"
	"strings"
)

func enumerateKWallet(showSecrets bool) ([]linuxCredEntry, string) {
	kwBin := ""
	for _, bin := range []string{"kwalletcli", "kwallet-query"} {
		if p, err := os.Stat("/usr/bin/" + bin); err == nil && !p.IsDir() {
			kwBin = bin
			break
		}
	}
	if kwBin == "" {
		return nil, "kwalletcli/kwallet-query not found (KWallet enumeration unavailable)"
	}

	var entries []linuxCredEntry

	if kwBin == "kwallet-query" {
		out, err := execCmdTimeout("kwallet-query", "-l", "kdewallet")
		if err != nil {
			return nil, fmt.Sprintf("kwallet-query failed: %v", err)
		}
		for _, folder := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			folder = strings.TrimSpace(folder)
			if folder == "" {
				continue
			}
			entryOut, err := execCmdTimeout("kwallet-query", "-l", "kdewallet", "-f", folder)
			if err != nil {
				continue
			}
			for _, entry := range strings.Split(strings.TrimSpace(string(entryOut)), "\n") {
				entry = strings.TrimSpace(entry)
				if entry == "" {
					continue
				}
				e := linuxCredEntry{
					Source: "KWallet",
					Label:  entry,
					Attrs:  map[string]string{"folder": folder},
				}
				if showSecrets {
					secretOut, err := execCmdTimeout("kwallet-query", "-r", entry, "kdewallet", "-f", folder)
					if err == nil {
						e.Secret = strings.TrimSpace(string(secretOut))
					}
				}
				entries = append(entries, e)
			}
		}
	} else {
		out, err := execCmdTimeout("kwalletcli", "-l")
		if err != nil {
			return nil, fmt.Sprintf("kwalletcli list failed: %v", err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			entries = append(entries, linuxCredEntry{
				Source: "KWallet",
				Label:  line,
				Attrs:  map[string]string{},
			})
		}
	}

	return entries, ""
}
