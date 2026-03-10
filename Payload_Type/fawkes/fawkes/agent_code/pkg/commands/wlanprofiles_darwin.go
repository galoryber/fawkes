package commands

import (
	"strings"
)

func getWlanProfiles() ([]wlanProfile, error) {
	var profiles []wlanProfile

	// List known networks using networksetup
	out, err := execCmdTimeoutOutput("/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en0")
	if err != nil {
		// Try en1 as fallback
		out, err = execCmdTimeoutOutput("/usr/sbin/networksetup", "-listpreferredwirelessnetworks", "en1")
		if err != nil {
			return nil, nil
		}
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Preferred networks") {
			continue
		}

		ssid := line

		// Try to get the password from keychain
		key := ""
		keyOut, err := execCmdTimeoutOutput("/usr/bin/security",
			"find-generic-password",
			"-D", "AirPort network password",
			"-a", ssid,
			"-w",
		)
		if err == nil {
			key = strings.TrimSpace(string(keyOut))
		}

		profiles = append(profiles, wlanProfile{
			SSID:     ssid,
			AuthType: "WPA/WPA2",
			Key:      key,
			Source:   "keychain",
		})
	}

	return profiles, nil
}
