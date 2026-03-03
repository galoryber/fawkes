package commands

import (
	"database/sql"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// tccDBPaths returns the user-level and system-level TCC database paths.
func tccDBPaths() (string, string) {
	homeDir := "/var/root" // fallback
	if u, err := user.Current(); err == nil {
		homeDir = u.HomeDir
	}

	userDB := filepath.Join(homeDir, "Library", "Application Support", "com.apple.TCC", "TCC.db")
	systemDB := "/Library/Application Support/com.apple.TCC/TCC.db"

	return userDB, systemDB
}

// tccServiceNames maps TCC service identifiers to human-readable names.
var tccServiceNames = map[string]string{
	"kTCCServiceAccessibility":                 "Accessibility",
	"kTCCServiceAddressBook":                   "Contacts",
	"kTCCServiceAppleEvents":                   "Apple Events / Automation",
	"kTCCServiceBluetoothAlways":               "Bluetooth",
	"kTCCServiceCalendar":                      "Calendar",
	"kTCCServiceCamera":                        "Camera",
	"kTCCServiceContactsFull":                  "Full Contacts Access",
	"kTCCServiceContactsLimited":               "Limited Contacts Access",
	"kTCCServiceDeveloperTool":                 "Developer Tools",
	"kTCCServiceEndpointSecurityClient":        "Endpoint Security",
	"kTCCServiceFocusStatus":                   "Focus Status",
	"kTCCServiceFileProviderDomain":            "File Provider",
	"kTCCServiceFileProviderPresence":          "File Provider Presence",
	"kTCCServiceListenEvent":                   "Input Monitoring",
	"kTCCServiceLiverpool":                     "Location Simulation",
	"kTCCServiceLocation":                      "Location Services",
	"kTCCServiceMediaLibrary":                  "Media Library",
	"kTCCServiceMicrophone":                    "Microphone",
	"kTCCServiceMotion":                        "Motion & Fitness",
	"kTCCServicePhotos":                        "Photos",
	"kTCCServicePhotosAdd":                     "Photos (Add Only)",
	"kTCCServicePostEvent":                     "Post Events",
	"kTCCServicePrototype3Rights":              "Prototype3",
	"kTCCServicePrototype4Rights":              "Prototype4",
	"kTCCServiceReminders":                     "Reminders",
	"kTCCServiceScreenCapture":                 "Screen Recording",
	"kTCCServiceSiri":                          "Siri",
	"kTCCServiceSpeechRecognition":             "Speech Recognition",
	"kTCCServiceSystemPolicyAllFiles":          "Full Disk Access",
	"kTCCServiceSystemPolicyAppBundles":        "App Management",
	"kTCCServiceSystemPolicyDesktopFolder":     "Desktop Folder",
	"kTCCServiceSystemPolicyDeveloperFiles":    "Developer Files",
	"kTCCServiceSystemPolicyDocumentsFolder":   "Documents Folder",
	"kTCCServiceSystemPolicyDownloadsFolder":   "Downloads Folder",
	"kTCCServiceSystemPolicyNetworkVolumes":    "Network Volumes",
	"kTCCServiceSystemPolicyRemovableVolumes":  "Removable Volumes",
	"kTCCServiceSystemPolicySysAdminFiles":     "Admin Files",
	"kTCCServiceUbiquity":                      "iCloud",
	"kTCCServiceWillow":                        "Home Data",
}

// tccEntry represents a single TCC permission record.
type tccEntry struct {
	Service     string `json:"service"`
	ServiceName string `json:"service_name"`
	Client      string `json:"client"`
	ClientType  int    `json:"client_type"`
	AuthValue   int    `json:"auth_value"`
	AuthReason  int    `json:"auth_reason"`
	Source      string `json:"source"`
}

// tccAuthValueStr returns a human-readable string for the TCC auth_value.
func tccAuthValueStr(v int) string {
	switch v {
	case 0:
		return "Denied"
	case 1:
		return "Unknown"
	case 2:
		return "Allowed"
	case 3:
		return "Limited"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// tccAuthReasonStr returns a human-readable string for the TCC auth_reason.
func tccAuthReasonStr(v int) string {
	switch v {
	case 0:
		return "Error"
	case 1:
		return "User Consent"
	case 2:
		return "User Set"
	case 3:
		return "System Set"
	case 4:
		return "Service Policy"
	case 5:
		return "MDM Policy"
	case 6:
		return "Override Policy"
	case 7:
		return "Missing Usage String"
	case 8:
		return "Prompt Timeout"
	case 9:
		return "Preflight Unknown"
	case 10:
		return "Entitled"
	case 11:
		return "App Type Policy"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// tccClientTypeStr returns a human-readable string for the TCC client_type.
func tccClientTypeStr(v int) string {
	switch v {
	case 0:
		return "Bundle ID"
	case 1:
		return "Absolute Path"
	default:
		return fmt.Sprintf("Unknown(%d)", v)
	}
}

// readTCCDatabase reads TCC records from a SQLite database.
func readTCCDatabase(dbPath, serviceFilter, source string) ([]tccEntry, error) {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("database not found: %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}
	defer db.Close()

	query := "SELECT service, client, client_type, auth_value, auth_reason FROM access"
	var queryArgs []interface{}

	if serviceFilter != "" {
		query += " WHERE service LIKE ?"
		queryArgs = append(queryArgs, "%"+serviceFilter+"%")
	}

	query += " ORDER BY service, client"

	rows, err := db.Query(query, queryArgs...)
	if err != nil {
		return nil, fmt.Errorf("query failed: %v", err)
	}
	defer rows.Close()

	var entries []tccEntry
	for rows.Next() {
		var e tccEntry
		if err := rows.Scan(&e.Service, &e.Client, &e.ClientType, &e.AuthValue, &e.AuthReason); err != nil {
			continue
		}
		e.Source = source
		if name, ok := tccServiceNames[e.Service]; ok {
			e.ServiceName = name
		} else {
			e.ServiceName = e.Service
		}
		entries = append(entries, e)
	}

	return entries, nil
}

// formatTCCOutput formats TCC entries into readable output.
func formatTCCOutput(entries []tccEntry, serviceFilter, userDB, systemDB string) string {
	var sb strings.Builder

	sb.WriteString("=== macOS TCC Permissions ===\n\n")
	sb.WriteString(fmt.Sprintf("User DB:   %s\n", userDB))
	sb.WriteString(fmt.Sprintf("System DB: %s\n", systemDB))
	if serviceFilter != "" {
		sb.WriteString(fmt.Sprintf("Filter:    %s\n", serviceFilter))
	}
	sb.WriteString(fmt.Sprintf("Records:   %d\n\n", len(entries)))

	// Group by service for readability
	grouped := make(map[string][]tccEntry)
	var order []string
	for _, e := range entries {
		if _, exists := grouped[e.ServiceName]; !exists {
			order = append(order, e.ServiceName)
		}
		grouped[e.ServiceName] = append(grouped[e.ServiceName], e)
	}

	for _, svcName := range order {
		svcEntries := grouped[svcName]
		sb.WriteString(fmt.Sprintf("--- %s ---\n", svcName))
		for _, e := range svcEntries {
			status := tccAuthValueStr(e.AuthValue)
			reason := tccAuthReasonStr(e.AuthReason)
			clientType := tccClientTypeStr(e.ClientType)
			sb.WriteString(fmt.Sprintf("  [%s] %s  (%s, %s, %s)\n",
				status, e.Client, clientType, reason, e.Source))
		}
		sb.WriteString("\n")
	}

	// Summary: highlight interesting permissions
	sb.WriteString("=== Allowed Permissions Summary ===\n")
	allowed := 0
	for _, e := range entries {
		if e.AuthValue == 2 {
			allowed++
			sb.WriteString(fmt.Sprintf("  %s: %s (%s)\n", e.ServiceName, e.Client, e.Source))
		}
	}
	if allowed == 0 {
		sb.WriteString("  (no allowed permissions found)\n")
	}

	return sb.String()
}
