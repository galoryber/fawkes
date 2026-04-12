package commands

import (
	"encoding/json"
	"fmt"
	"strings"
)

// edrServiceEntry defines a known EDR/AV service.
type edrServiceEntry struct {
	ServiceName string `json:"service_name"`
	DisplayName string `json:"display_name"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Platform    string `json:"platform"` // windows, linux, darwin, all
}

// edrEnumResult represents a detected EDR/AV service.
type edrEnumResult struct {
	ServiceName string `json:"service_name"`
	Vendor      string `json:"vendor"`
	Product     string `json:"product"`
	Status      string `json:"status"` // running, stopped, disabled, unknown
}

// edrKnownServices is a comprehensive database of EDR/AV service names.
var edrKnownServices = []edrServiceEntry{
	// CrowdStrike
	{"CSFalconService", "CrowdStrike Falcon Sensor", "CrowdStrike", "Falcon", "windows"},
	{"CSAgent", "CrowdStrike Agent", "CrowdStrike", "Falcon", "windows"},
	{"falcon-sensor", "CrowdStrike Falcon Sensor", "CrowdStrike", "Falcon", "linux"},
	{"com.crowdstrike.falcon.Agent", "CrowdStrike Falcon", "CrowdStrike", "Falcon", "darwin"},

	// SentinelOne
	{"SentinelAgent", "SentinelOne Agent", "SentinelOne", "Singularity", "windows"},
	{"SentinelStaticEngine", "SentinelOne Static Engine", "SentinelOne", "Singularity", "windows"},
	{"SentinelHelperService", "SentinelOne Helper", "SentinelOne", "Singularity", "windows"},
	{"sentinelone", "SentinelOne Agent", "SentinelOne", "Singularity", "linux"},

	// Microsoft Defender
	{"WinDefend", "Windows Defender Antivirus Service", "Microsoft", "Defender", "windows"},
	{"WdNisSvc", "Windows Defender NIS", "Microsoft", "Defender", "windows"},
	{"SecurityHealthService", "Windows Security Service", "Microsoft", "Defender", "windows"},
	{"MsSense", "Windows Defender ATP", "Microsoft", "Defender ATP", "windows"},
	{"mdatp", "Microsoft Defender for Endpoint", "Microsoft", "Defender ATP", "linux"},

	// Carbon Black
	{"CbDefense", "Carbon Black Defense", "VMware", "Carbon Black", "windows"},
	{"CbDefenseSensor", "Carbon Black Defense Sensor", "VMware", "Carbon Black", "windows"},
	{"CarbonBlack", "Carbon Black", "VMware", "Carbon Black", "windows"},
	{"cb-psc-sensor", "Carbon Black Cloud Sensor", "VMware", "Carbon Black", "linux"},

	// Symantec / Broadcom
	{"ccSvcHst", "Symantec Service Framework", "Broadcom", "Symantec EP", "windows"},
	{"SepMasterService", "Symantec EP Master Service", "Broadcom", "Symantec EP", "windows"},
	{"SmcService", "Symantec Management Client", "Broadcom", "Symantec EP", "windows"},

	// Sophos
	{"SAVService", "Sophos Anti-Virus", "Sophos", "Intercept X", "windows"},
	{"SophosCleanM", "Sophos Clean Service", "Sophos", "Intercept X", "windows"},
	{"SophosHealth", "Sophos Health Service", "Sophos", "Intercept X", "windows"},
	{"SophosMcsAgent", "Sophos MCS Agent", "Sophos", "Intercept X", "windows"},
	{"sophos-spl", "Sophos Protection", "Sophos", "Intercept X", "linux"},

	// ESET
	{"ekrn", "ESET Service", "ESET", "Endpoint Security", "windows"},
	{"EsetService", "ESET Service", "ESET", "Endpoint Security", "windows"},

	// Kaspersky
	{"AVP", "Kaspersky Anti-Virus", "Kaspersky", "Endpoint Security", "windows"},
	{"kavfs", "Kaspersky File Server", "Kaspersky", "Endpoint Security", "windows"},
	{"klnagent", "Kaspersky Network Agent", "Kaspersky", "Endpoint Security", "windows"},

	// Trend Micro
	{"OfficeScan", "Trend Micro OfficeScan", "Trend Micro", "Apex One", "windows"},
	{"TmCCSF", "Trend Micro Common Client", "Trend Micro", "Apex One", "windows"},
	{"ds_agent", "Trend Micro Deep Security", "Trend Micro", "Deep Security", "linux"},

	// Palo Alto
	{"CortexXDR", "Cortex XDR", "Palo Alto", "Cortex XDR", "windows"},
	{"TrapsSvc", "Traps Endpoint Security", "Palo Alto", "Traps", "windows"},
	{"traps_pmd", "Cortex XDR", "Palo Alto", "Cortex XDR", "linux"},

	// Cylance
	{"CylanceSvc", "Cylance Service", "BlackBerry", "CylancePROTECT", "windows"},
	{"CylanceUI", "Cylance UI", "BlackBerry", "CylancePROTECT", "windows"},

	// McAfee / Trellix
	{"McShield", "McAfee McShield", "Trellix", "ENS", "windows"},
	{"mfemms", "McAfee Management Service", "Trellix", "ENS", "windows"},
	{"mfefire", "McAfee Firewall", "Trellix", "ENS", "windows"},

	// Elastic
	{"elastic-agent", "Elastic Agent", "Elastic", "Elastic Security", "all"},
	{"elastic-endpoint", "Elastic Endpoint", "Elastic", "Elastic Security", "all"},

	// Wazuh
	{"wazuh-agent", "Wazuh Agent", "Wazuh", "Wazuh", "all"},
	{"ossec", "OSSEC HIDS", "OSSEC", "OSSEC", "all"},

	// ClamAV
	{"clamd", "ClamAV Daemon", "ClamAV", "ClamAV", "linux"},
	{"freshclam", "ClamAV Update", "ClamAV", "ClamAV", "linux"},

	// Malwarebytes
	{"MBAMService", "Malwarebytes Service", "Malwarebytes", "Malwarebytes", "windows"},

	// Webroot
	{"WRSVC", "Webroot SecureAnywhere", "Webroot", "SecureAnywhere", "windows"},

	// Bitdefender
	{"EPSecurityService", "Bitdefender Endpoint Security", "Bitdefender", "GravityZone", "windows"},
	{"EPIntegrationService", "Bitdefender Integration", "Bitdefender", "GravityZone", "windows"},

	// Fortinet
	{"FortiESNAC", "FortiClient NAC", "Fortinet", "FortiClient", "windows"},
	{"FortiClientMonitor", "FortiClient Monitor", "Fortinet", "FortiClient", "windows"},

	// Qualys
	{"QualysAgent", "Qualys Cloud Agent", "Qualys", "Cloud Agent", "all"},

	// Rapid7
	{"ir_agent", "Rapid7 InsightAgent", "Rapid7", "InsightIDR", "all"},
}

// edrMatchesForPlatform returns the EDR entries that match the given platform.
func edrMatchesForPlatform(platform string) []edrServiceEntry {
	var matches []edrServiceEntry
	for _, entry := range edrKnownServices {
		if entry.Platform == platform || entry.Platform == "all" {
			matches = append(matches, entry)
		}
	}
	return matches
}

// formatEdrEnumResults formats the EDR enumeration results.
func formatEdrEnumResults(results []edrEnumResult) string {
	if len(results) == 0 {
		return "[*] No EDR/AV services detected"
	}

	jsonBytes, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Sprintf("Error formatting results: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] Found %d EDR/AV services:\n\n", len(results)))
	sb.Write(jsonBytes)
	return sb.String()
}
