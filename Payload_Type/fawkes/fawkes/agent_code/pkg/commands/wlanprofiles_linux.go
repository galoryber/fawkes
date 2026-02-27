package commands

import (
	"os"
	"path/filepath"
	"strings"
)

func getWlanProfiles() ([]wlanProfile, error) {
	var profiles []wlanProfile

	// NetworkManager stores profiles in /etc/NetworkManager/system-connections/
	nmDir := "/etc/NetworkManager/system-connections"
	entries, err := os.ReadDir(nmDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			path := filepath.Join(nmDir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			content := string(data)
			profile := parseNMProfile(content, path)
			if profile.SSID != "" {
				profiles = append(profiles, profile)
			}
		}
	}

	// Also check wpa_supplicant config
	wpaConfs := []string{
		"/etc/wpa_supplicant/wpa_supplicant.conf",
		"/etc/wpa_supplicant.conf",
	}
	for _, conf := range wpaConfs {
		data, err := os.ReadFile(conf)
		if err != nil {
			continue
		}
		wpaProfiles := parseWPASupplicant(string(data), conf)
		profiles = append(profiles, wpaProfiles...)
	}

	// iwd stores profiles in /var/lib/iwd/
	iwdDir := "/var/lib/iwd"
	iwdEntries, err := os.ReadDir(iwdDir)
	if err == nil {
		for _, entry := range iwdEntries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".psk") {
				continue
			}
			path := filepath.Join(iwdDir, entry.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			ssid := strings.TrimSuffix(entry.Name(), ".psk")
			psk := ""
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Passphrase=") {
					psk = strings.TrimPrefix(line, "Passphrase=")
				} else if strings.HasPrefix(line, "PreSharedKey=") {
					psk = strings.TrimPrefix(line, "PreSharedKey=")
				}
			}
			profiles = append(profiles, wlanProfile{
				SSID:     ssid,
				AuthType: "WPA-PSK",
				Key:      psk,
				Source:   path,
			})
		}
	}

	if len(profiles) == 0 {
		return nil, nil
	}
	return profiles, nil
}

func parseNMProfile(content, path string) wlanProfile {
	var profile wlanProfile
	profile.Source = path

	lines := strings.Split(content, "\n")
	inWifi := false
	inSecurity := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "[wifi]" {
			inWifi = true
			inSecurity = false
			continue
		}
		if line == "[wifi-security]" {
			inSecurity = true
			inWifi = false
			continue
		}
		if strings.HasPrefix(line, "[") {
			inWifi = false
			inSecurity = false
			continue
		}

		if inWifi {
			if strings.HasPrefix(line, "ssid=") {
				profile.SSID = strings.TrimPrefix(line, "ssid=")
			}
		}
		if inSecurity {
			if strings.HasPrefix(line, "key-mgmt=") {
				profile.AuthType = strings.ToUpper(strings.TrimPrefix(line, "key-mgmt="))
			}
			if strings.HasPrefix(line, "psk=") {
				profile.Key = strings.TrimPrefix(line, "psk=")
			}
		}
	}
	return profile
}

func parseWPASupplicant(content, path string) []wlanProfile {
	var profiles []wlanProfile
	blocks := strings.Split(content, "network={")

	for _, block := range blocks[1:] { // skip preamble before first network=
		end := strings.Index(block, "}")
		if end < 0 {
			continue
		}
		block = block[:end]

		var ssid, psk, keyMgmt string
		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ssid=") {
				ssid = strings.Trim(strings.TrimPrefix(line, "ssid="), "\"")
			}
			if strings.HasPrefix(line, "psk=") {
				psk = strings.Trim(strings.TrimPrefix(line, "psk="), "\"")
			}
			if strings.HasPrefix(line, "key_mgmt=") {
				keyMgmt = strings.ToUpper(strings.TrimPrefix(line, "key_mgmt="))
			}
		}

		if ssid != "" {
			if keyMgmt == "" {
				keyMgmt = "WPA-PSK"
			}
			profiles = append(profiles, wlanProfile{
				SSID:     ssid,
				AuthType: keyMgmt,
				Key:      psk,
				Source:   path,
			})
		}
	}
	return profiles
}
