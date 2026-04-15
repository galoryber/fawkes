package commands

// command_helpers.go contains pure helper functions extracted from
// platform-specific command files for cross-platform testing.

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// --- DPAPI helpers (from dpapi.go) ---

// dpapiIsPrintable checks if a byte slice contains printable ASCII/UTF-8
func dpapiIsPrintable(data []byte) bool {
	for _, b := range data {
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

// isGUID checks if a string looks like a GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// --- ETW helpers (from etw.go) ---

// classifySessionSecurity classifies an ETW session name by security relevance
func classifySessionSecurity(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "defender") || strings.Contains(lower, "antimalware"):
		return "!! DEFENDER/AV"
	case strings.Contains(lower, "sysmon"):
		return "!! SYSMON"
	case strings.Contains(lower, "edr") || strings.Contains(lower, "sentinel") ||
		strings.Contains(lower, "crowdstrike") || strings.Contains(lower, "carbon"):
		return "!! EDR"
	case strings.Contains(lower, "security"):
		return "! Security"
	case strings.Contains(lower, "audit"):
		return "! Audit"
	case strings.Contains(lower, "etw") || strings.Contains(lower, "eventlog"):
		return "Telemetry"
	case strings.Contains(lower, "kernel"):
		return "Kernel"
	case strings.Contains(lower, "diagtrack") || strings.Contains(lower, "autologger"):
		return "Diagnostics"
	default:
		return ""
	}
}

// Well-known ETW provider GUIDs for security tools
var knownSecurityProviders = map[string]string{
	"54849625-5478-4994-A5BA-3E3B0328C30D": "Microsoft-Windows-Security-Auditing",
	"EDD08927-9CC4-4E65-B970-C2560FB5C289": "Microsoft-Windows-Kernel-Process",
	"22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716": "Microsoft-Windows-Kernel-File",
	"A68CA8B7-004F-D7B6-A698-04740076C4E7": "Microsoft-Windows-Kernel-Network",
	"0BD3506A-9030-4F76-B16D-2803530B31F1": "Microsoft-Windows-Kernel-Registry",
	"DCBE5AAA-16E2-457C-9337-366950045F0A": "Microsoft-Windows-WMI-Activity",
	"7DD42A49-5329-4832-8DFD-43D979153A88": "Microsoft-Windows-Kernel-Audit-API-Calls",
	"B675EC37-BDB6-4648-BC92-F3FDC74D3CA2": "Microsoft-Windows-LDAP-Client",
	"F4E1897A-BB65-5399-F245-102D38640FFE": "Microsoft-Antimalware-Scan-Interface",
	"A0C1853B-5C40-4B15-8766-3CF1C58F985A": "Microsoft-Windows-PowerShell",
	"11C5D8AD-756A-42C2-8087-EB1B4A72A846": "Microsoft-Windows-WinRM",
	"F4190177-63B0-4CB5-8B2C-3A5C3D319B6D": "Microsoft-Windows-CAPI2",
	"DBE9B383-7CF3-4331-91CC-A3CB16A3B538": "Microsoft-Windows-Winlogon",
	"0CCE985E-0000-0000-0000-000000000000": "Microsoft-Windows-Security-Auditing-Process",
	"E8109B99-3A2C-4961-AA83-D1A7A148ADA8": "Microsoft-Windows-TaskScheduler",
	"B3A7698A-0C45-44DA-B73D-E181C9B5C8E6": "Microsoft-Windows-Sysmon",
	"555908D1-A6D7-4695-8E1E-26931D2012F4": "Microsoft-Windows-DNS-Client",
	"A83D4C09-79AF-4A78-A129-A15ECCAE1BF9": "Microsoft-Windows-RPC",
	"04C2CAB3-2A99-4097-AB1C-1291F8EB6E95": "Microsoft-Windows-DotNETRuntime",
}

// Shorthand provider names for operator convenience
var providerShorthands = map[string]string{
	"security-auditing": "54849625-5478-4994-A5BA-3E3B0328C30D",
	"kernel-process":    "EDD08927-9CC4-4E65-B970-C2560FB5C289",
	"kernel-file":       "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716",
	"kernel-network":    "A68CA8B7-004F-D7B6-A698-04740076C4E7",
	"kernel-registry":   "0BD3506A-9030-4F76-B16D-2803530B31F1",
	"sysmon":            "B3A7698A-0C45-44DA-B73D-E181C9B5C8E6",
	"amsi":              "F4E1897A-BB65-5399-F245-102D38640FFE",
	"powershell":        "A0C1853B-5C40-4B15-8766-3CF1C58F985A",
	"winrm":             "11C5D8AD-756A-42C2-8087-EB1B4A72A846",
	"dotnet":            "04C2CAB3-2A99-4097-AB1C-1291F8EB6E95",
	"wmi":               "DCBE5AAA-16E2-457C-9337-366950045F0A",
	"api-calls":         "7DD42A49-5329-4832-8DFD-43D979153A88",
	"task-scheduler":    "E8109B99-3A2C-4961-AA83-D1A7A148ADA8",
	"dns-client":        "555908D1-A6D7-4695-8E1E-26931D2012F4",
}

// resolveProviderGUID resolves a provider name/shorthand/GUID to a GUID string and display name
func resolveProviderGUID(provider string) (string, string) {
	if provider == "" {
		return "", ""
	}

	// Check shorthand names first
	lower := strings.ToLower(provider)
	if guid, ok := providerShorthands[lower]; ok {
		name := knownSecurityProviders[guid]
		return guid, name
	}

	// Check exact match first (case-insensitive) — prevents ambiguous substring matches
	for guid, name := range knownSecurityProviders {
		if strings.EqualFold(name, provider) {
			return guid, name
		}
	}

	// Substring match: "Sysmon" matches "Microsoft-Windows-Sysmon"
	for guid, name := range knownSecurityProviders {
		if strings.Contains(strings.ToLower(name), lower) {
			return guid, name
		}
	}

	// Check if it looks like a GUID already
	cleaned := strings.Trim(provider, "{}")
	if len(cleaned) == 36 && strings.Count(cleaned, "-") == 4 {
		name := knownSecurityProviders[strings.ToUpper(cleaned)]
		return strings.ToUpper(cleaned), name
	}

	return "", ""
}

// --- Credential Manager helpers (from credman.go) ---

// Credential type constants
const (
	credTypeGeneric           = 1
	credTypeDomainPassword    = 2
	credTypeDomainCertificate = 3
	credTypeDomainVisible     = 4
)

// isPrintable checks if a string contains only printable characters
func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) > 0
}

// credTypeName maps Windows credential type codes to display names
func credTypeName(t uint32) string {
	switch t {
	case credTypeGeneric:
		return "Generic"
	case credTypeDomainPassword:
		return "Domain Password"
	case credTypeDomainCertificate:
		return "Domain Certificate"
	case credTypeDomainVisible:
		return "Domain Visible Password"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

// credPersistName maps credential persistence scope codes to names
func credPersistName(p uint32) string {
	switch p {
	case 1:
		return "Session"
	case 2:
		return "Local Machine"
	case 3:
		return "Enterprise"
	default:
		return fmt.Sprintf("Unknown (%d)", p)
	}
}

// --- Amcache/Shimcache helpers (from amcache.go) ---

// decodeUTF16LEShim decodes a UTF-16LE byte slice to a Go string
func decodeUTF16LEShim(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2 : i*2+2])
	}
	// Remove trailing null
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// --- Firewall helpers (from firewall.go) ---

// Firewall protocol, direction, and action constants
const (
	fwIPProtocolTCP = 6
	fwIPProtocolUDP = 17
	fwIPProtocolAny = 256

	fwRuleDirectionIn  = 1
	fwRuleDirectionOut = 2

	fwActionBlock = 0
	fwActionAllow = 1
)

// fwDirectionToString converts a firewall rule direction to display string
func fwDirectionToString(dir int) string {
	switch dir {
	case fwRuleDirectionIn:
		return "In"
	case fwRuleDirectionOut:
		return "Out"
	default:
		return fmt.Sprintf("%d", dir)
	}
}

// fwActionIntToString converts a firewall action code to display string
func fwActionIntToString(action int) string {
	switch action {
	case fwActionBlock:
		return "Block"
	case fwActionAllow:
		return "Allow"
	default:
		return fmt.Sprintf("%d", action)
	}
}

// fwProtocolToString converts a protocol number to display string
func fwProtocolToString(proto int) string {
	switch proto {
	case fwIPProtocolTCP:
		return "TCP"
	case fwIPProtocolUDP:
		return "UDP"
	case fwIPProtocolAny:
		return "Any"
	case 1:
		return "ICMPv4"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("%d", proto)
	}
}

// --- Thread Scan helpers (from ts.go) ---

// tsWaitReasonString converts a KWAIT_REASON enum value to human-readable string
func tsWaitReasonString(reason uint32) string {
	switch reason {
	case 0:
		return "Executive"
	case 1:
		return "FreePage"
	case 2:
		return "PageIn"
	case 3:
		return "PoolAllocation"
	case 4:
		return "DelayExecution"
	case 5:
		return "Suspended"
	case 6:
		return "UserRequest"
	case 7:
		return "WrExecutive"
	case 8:
		return "WrFreePage"
	case 9:
		return "WrPageIn"
	case 10:
		return "WrPoolAllocation"
	case 11:
		return "WrDelayExecution"
	case 12:
		return "WrSuspended"
	case 13:
		return "WrUserRequest"
	case 14:
		return "WrEventPair"
	case 15:
		return "WrQueue"
	case 16:
		return "WrLpcReceive"
	case 17:
		return "WrLpcReply"
	case 18:
		return "WrVirtualMemory"
	case 19:
		return "WrPageOut"
	case 20:
		return "WrRendezvous"
	case 21:
		return "WrKeyedEvent"
	case 22:
		return "WrTerminated"
	case 23:
		return "WrProcessInSwap"
	case 24:
		return "WrCpuRateControl"
	case 25:
		return "WrCalloutStack"
	case 26:
		return "WrKernel"
	case 27:
		return "WrResource"
	case 28:
		return "WrPushLock"
	case 29:
		return "WrMutex"
	case 30:
		return "WrQuantumEnd"
	case 31:
		return "WrDispatchInt"
	case 32:
		return "WrPreempted"
	case 33:
		return "WrYieldExecution"
	case 34:
		return "WrFastMutex"
	case 35:
		return "WrGuardedMutex"
	case 36:
		return "WrRundown"
	case 37:
		return "WrAlertByThreadId"
	case 38:
		return "WrDeferredPreempt"
	default:
		return fmt.Sprintf("Unknown(%d)", reason)
	}
}

// tsTruncateOwner consolidated into truncStr in format_helpers.go
