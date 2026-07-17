//go:build linux

package commands

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

var secretToolAttrRe = regexp.MustCompile(`^attribute\.(\S+)\s*=\s*(.+)$`)

func enumerateSecretService(showSecrets bool) ([]linuxCredEntry, string) {
	if _, err := os.Stat("/usr/bin/secret-tool"); err != nil {
		return nil, "secret-tool not found (install libsecret-tools for keyring enumeration)"
	}

	out, err := execCmdTimeout("secret-tool", "search", "--all", "xdg:schema", "org.freedesktop.Secret.Generic")
	if err != nil {
		out, err = execCmdTimeout("secret-tool", "search", "--all", "")
		if err != nil {
			return enumerateSecretServiceTargeted(showSecrets)
		}
	}

	entries := parseSecretToolOutput(string(out), "Secret Service")

	if showSecrets {
		for i := range entries {
			secret := lookupSecretByAttrs(entries[i].Attrs)
			if secret != "" {
				entries[i].Secret = secret
			}
		}
	}

	return entries, ""
}

func enumerateSecretServiceTargeted(showSecrets bool) ([]linuxCredEntry, string) {
	schemas := []string{
		"org.freedesktop.Secret.Generic",
		"org.gnome.keyring.Note",
		"org.gnome.keyring.NetworkPassword",
		"chrome_libsecret_os_crypt_password_v2",
	}

	var allEntries []linuxCredEntry
	anySuccess := false

	for _, schema := range schemas {
		out, err := execCmdTimeout("secret-tool", "search", "--all", "xdg:schema", schema)
		if err != nil {
			continue
		}
		anySuccess = true
		entries := parseSecretToolOutput(string(out), "Secret Service")
		if showSecrets {
			for i := range entries {
				secret := lookupSecretByAttrs(entries[i].Attrs)
				if secret != "" {
					entries[i].Secret = secret
				}
			}
		}
		allEntries = append(allEntries, entries...)
	}

	if !anySuccess {
		return nil, "No keyring daemon running or no items stored"
	}
	return allEntries, ""
}

func parseSecretToolOutput(output, source string) []linuxCredEntry {
	var entries []linuxCredEntry
	var current *linuxCredEntry

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			if current != nil {
				entries = append(entries, *current)
			}
			current = &linuxCredEntry{
				Source: source,
				Attrs:  make(map[string]string),
			}
			continue
		}

		if current == nil {
			continue
		}

		if strings.HasPrefix(line, "label = ") {
			current.Label = strings.TrimPrefix(line, "label = ")
		} else if strings.HasPrefix(line, "secret = ") {
			current.Secret = strings.TrimPrefix(line, "secret = ")
		} else if m := secretToolAttrRe.FindStringSubmatch(line); m != nil {
			key, val := m[1], m[2]
			current.Attrs[key] = val
			if key == "username" || key == "user" || key == "account" {
				current.Account = val
			}
		}
	}
	if current != nil {
		entries = append(entries, *current)
	}
	return entries
}

func lookupSecretByAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	var lookupArgs []string
	for _, key := range []string{"application", "xdg:schema", "server", "user", "username", "service"} {
		if v, ok := attrs[key]; ok {
			lookupArgs = append(lookupArgs, key, v)
		}
		if len(lookupArgs) >= 4 {
			break
		}
	}
	if len(lookupArgs) < 2 {
		for k, v := range attrs {
			lookupArgs = append(lookupArgs, k, v)
			if len(lookupArgs) >= 4 {
				break
			}
		}
	}
	if len(lookupArgs) < 2 {
		return ""
	}
	out, err := execCmdTimeoutOutput("secret-tool", append([]string{"lookup"}, lookupArgs...)...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
