//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"
	"fmt"
)

func enumerateNetworkManager() ([]linuxCredEntry, string) {
	nmDir := "/etc/NetworkManager/system-connections"
	dirEntries, err := os.ReadDir(nmDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "NetworkManager not installed or no saved connections"
		}
		if os.IsPermission(err) {
			return nil, "Access denied to /etc/NetworkManager/system-connections/ (requires root)"
		}
		return nil, fmt.Sprintf("Error reading NM connections: %v", err)
	}

	var entries []linuxCredEntry
	for _, de := range dirEntries {
		if de.IsDir() {
			continue
		}
		path := filepath.Join(nmDir, de.Name())
		conn, err := parseNMConnectionFile(path)
		if err != nil || conn.Label == "" {
			continue
		}
		conn.Source = "NetworkManager"
		entries = append(entries, conn)
	}
	return entries, ""
}

func parseNMConnectionFile(path string) (linuxCredEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return linuxCredEntry{}, err
	}

	entry := linuxCredEntry{
		Attrs: make(map[string]string),
	}

	var section string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])

		switch section {
		case "connection":
			switch key {
			case "id":
				entry.Label = val
			case "type":
				entry.Attrs["type"] = val
			}
		case "wifi":
			if key == "ssid" {
				entry.Label = val
				entry.Attrs["ssid"] = val
			}
		case "wifi-security":
			switch key {
			case "psk":
				entry.Secret = val
			case "key-mgmt":
				entry.Attrs["security"] = val
			}
		case "802-1x":
			switch key {
			case "identity":
				entry.Account = val
			case "password":
				entry.Secret = val
			}
		case "vpn":
			if key == "password" || strings.HasSuffix(key, "-password") {
				entry.Secret = val
			} else if key == "user" || key == "username" {
				entry.Account = val
			}
		}
	}

	return entry, nil
}

func enumerateGNOMEOnlineAccounts() []linuxCredEntry {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	goaPath := filepath.Join(home, ".config", "goa-1.0", "accounts.conf")
	data, err := os.ReadFile(goaPath)
	if err != nil {
		return nil
	}

	var entries []linuxCredEntry
	var current *linuxCredEntry

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[Account ") {
			if current != nil && current.Label != "" {
				entries = append(entries, *current)
			}
			current = &linuxCredEntry{
				Source: "GNOME Online Accounts",
				Attrs:  make(map[string]string),
			}
			continue
		}
		if current == nil {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, val := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		switch key {
		case "Provider":
			current.Attrs["provider"] = val
		case "Identity":
			current.Account = val
		case "PresentationIdentity":
			if current.Label == "" {
				current.Label = val
			}
		case "IsTemporary":
			if val == "true" {
				current = nil
			}
		}
	}
	if current != nil && current.Label != "" {
		entries = append(entries, *current)
	}
	return entries
}
