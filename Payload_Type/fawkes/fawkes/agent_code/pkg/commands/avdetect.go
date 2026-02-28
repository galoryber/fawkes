package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/shirou/gopsutil/v3/process"
)

// AvDetectCommand detects AV/EDR/security products by process name
type AvDetectCommand struct{}

func (c *AvDetectCommand) Name() string {
	return "av-detect"
}

func (c *AvDetectCommand) Description() string {
	return "Detect installed AV/EDR/security products by scanning running processes"
}

// securityProduct maps a process name to its product info
type securityProduct struct {
	Product  string
	Vendor   string
	Category string // "AV", "EDR", "Firewall", "HIPS", "DLP", "Logging"
}

// knownSecurityProcesses maps lowercase process names to product info.
// Maintained as a comprehensive list of common security products.
var knownSecurityProcesses = map[string]securityProduct{
	// Microsoft Defender
	"msmpeng.exe":               {"Windows Defender", "Microsoft", "AV"},
	"mpcmdrun.exe":              {"Windows Defender", "Microsoft", "AV"},
	"msascuil.exe":              {"Windows Defender", "Microsoft", "AV"},
	"securityhealthservice.exe": {"Windows Security Health", "Microsoft", "AV"},
	"securityhealthsystray.exe": {"Windows Security Health", "Microsoft", "AV"},
	"mssense.exe":               {"Defender for Endpoint", "Microsoft", "EDR"},
	"sensecncproxy.exe":         {"Defender for Endpoint", "Microsoft", "EDR"},
	"senseir.exe":               {"Defender for Endpoint", "Microsoft", "EDR"},

	// CrowdStrike Falcon
	"csfalconservice.exe":   {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"csfalconcontainer.exe": {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"csagent.exe":           {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcond":               {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcon-sensor":         {"CrowdStrike Falcon", "CrowdStrike", "EDR"},

	// SentinelOne
	"sentinelagent.exe":        {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelctl.exe":          {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelservicehost.exe":  {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelstaticengine.exe": {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelagent":            {"SentinelOne", "SentinelOne", "EDR"},

	// Carbon Black
	"cb.exe":       {"Carbon Black", "VMware", "EDR"},
	"cbcomms.exe":  {"Carbon Black", "VMware", "EDR"},
	"cbstream.exe": {"Carbon Black", "VMware", "EDR"},
	"repmgr.exe":   {"Carbon Black", "VMware", "EDR"},
	"cbdefense":    {"Carbon Black", "VMware", "EDR"},

	// Cortex XDR (Palo Alto)
	"traps.exe":         {"Cortex XDR", "Palo Alto", "EDR"},
	"trapsd.exe":        {"Cortex XDR", "Palo Alto", "EDR"},
	"cyserver.exe":      {"Cortex XDR", "Palo Alto", "EDR"},
	"cytray.exe":        {"Cortex XDR", "Palo Alto", "EDR"},
	"cyveraservice.exe": {"Cortex XDR", "Palo Alto", "EDR"},

	// Symantec / Broadcom
	"sepmaster.exe":        {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"smc.exe":              {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"smcgui.exe":           {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"ccsvchst.exe":         {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"rtvscan.exe":          {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"sepmasterservice.exe": {"Symantec Endpoint Protection", "Broadcom", "AV"},

	// McAfee / Trellix
	"mfemms.exe":   {"McAfee/Trellix", "Trellix", "AV"},
	"mfetp.exe":    {"McAfee/Trellix", "Trellix", "AV"},
	"mfemactl.exe": {"McAfee/Trellix", "Trellix", "AV"},
	"mcshield.exe": {"McAfee/Trellix", "Trellix", "AV"},
	"masvc.exe":    {"McAfee Agent", "Trellix", "AV"},
	"macmnsvc.exe": {"McAfee Agent", "Trellix", "AV"},
	"firetray.exe": {"Trellix Endpoint", "Trellix", "EDR"},
	"firesvc.exe":  {"Trellix Endpoint", "Trellix", "EDR"},
	"xagt.exe":     {"Trellix XDR", "Trellix", "EDR"},

	// Kaspersky
	"avp.exe":      {"Kaspersky", "Kaspersky", "AV"},
	"avpui.exe":    {"Kaspersky", "Kaspersky", "AV"},
	"klnagent.exe": {"Kaspersky Network Agent", "Kaspersky", "AV"},
	"kavfswp.exe":  {"Kaspersky", "Kaspersky", "AV"},

	// ESET
	"ekrn.exe":     {"ESET Endpoint Security", "ESET", "AV"},
	"egui.exe":     {"ESET Endpoint Security", "ESET", "AV"},
	"esets_daemon": {"ESET Endpoint Security", "ESET", "AV"},

	// Sophos
	"sophossps.exe":         {"Sophos Endpoint", "Sophos", "AV"},
	"savservice.exe":        {"Sophos Endpoint", "Sophos", "AV"},
	"hmpalert.exe":          {"Sophos Intercept X", "Sophos", "EDR"},
	"sophosfs.exe":          {"Sophos Endpoint", "Sophos", "AV"},
	"sophosfilescanner.exe": {"Sophos Endpoint", "Sophos", "AV"},
	"sophoshealth.exe":      {"Sophos Endpoint", "Sophos", "AV"},

	// Trend Micro
	"tmbmsrv.exe":          {"Trend Micro", "Trend Micro", "AV"},
	"ntrtscan.exe":         {"Trend Micro OfficeScan", "Trend Micro", "AV"},
	"tmccsf.exe":           {"Trend Micro", "Trend Micro", "AV"},
	"coreserviceshell.exe": {"Trend Micro Apex One", "Trend Micro", "EDR"},
	"ds_agent.exe":         {"Trend Micro Deep Security", "Trend Micro", "EDR"},

	// Bitdefender
	"bdagent.exe":       {"Bitdefender", "Bitdefender", "AV"},
	"bdservicehost.exe": {"Bitdefender", "Bitdefender", "AV"},
	"seccenter.exe":     {"Bitdefender", "Bitdefender", "AV"},
	"epag.exe":          {"Bitdefender GravityZone", "Bitdefender", "EDR"},

	// Cylance (BlackBerry)
	"cylancesvc.exe":    {"Cylance", "BlackBerry", "AV"},
	"cylanceui.exe":     {"Cylance", "BlackBerry", "AV"},
	"cylanceoptics.exe": {"Cylance Optics", "BlackBerry", "EDR"},

	// Elastic
	"elastic-agent.exe":    {"Elastic Agent", "Elastic", "EDR"},
	"elastic-agent":        {"Elastic Agent", "Elastic", "EDR"},
	"elastic-endpoint.exe": {"Elastic Endpoint", "Elastic", "EDR"},
	"elastic-endpoint":     {"Elastic Endpoint", "Elastic", "EDR"},

	// Cisco Secure Endpoint (AMP)
	"sfc.exe":     {"Cisco Secure Endpoint", "Cisco", "EDR"},
	"iptray.exe":  {"Cisco Secure Endpoint", "Cisco", "EDR"},
	"orbital.exe": {"Cisco Orbital", "Cisco", "EDR"},

	// Cybereason
	"activeconsole.exe": {"Cybereason", "Cybereason", "EDR"},
	"crssvc.exe":        {"Cybereason", "Cybereason", "EDR"},
	"minionhost.exe":    {"Cybereason", "Cybereason", "EDR"},

	// Fortinet
	"forticlient.exe": {"FortiClient", "Fortinet", "AV"},
	"fortitray.exe":   {"FortiClient", "Fortinet", "AV"},
	"fcappdb.exe":     {"FortiClient", "Fortinet", "AV"},

	// WatchGuard
	"epdr.exe": {"WatchGuard EPDR", "WatchGuard", "EDR"},

	// Sysmon / Windows Logging
	"sysmon.exe":   {"Sysmon", "Microsoft", "Logging"},
	"sysmon64.exe": {"Sysmon", "Microsoft", "Logging"},
	"sysmon":       {"Sysmon", "Microsoft", "Logging"},

	// Windows Firewall
	"mpssvc.exe": {"Windows Firewall", "Microsoft", "Firewall"},

	// Splunk
	"splunkd.exe": {"Splunk Forwarder", "Splunk", "Logging"},
	"splunkd":     {"Splunk Forwarder", "Splunk", "Logging"},

	// Wazuh
	"wazuh-agent.exe": {"Wazuh Agent", "Wazuh", "Logging"},
	"wazuh-agentd":    {"Wazuh Agent", "Wazuh", "Logging"},
	"ossec-agentd":    {"OSSEC/Wazuh", "Wazuh", "Logging"},

	// Qualys
	"qualysagent.exe": {"Qualys Agent", "Qualys", "Logging"},

	// Tanium
	"taniumclient.exe": {"Tanium", "Tanium", "EDR"},
	"taniumclient":     {"Tanium", "Tanium", "EDR"},

	// Rapid7
	"ir_agent.exe": {"Rapid7 InsightIDR", "Rapid7", "EDR"},

	// macOS-specific
	"xprotectservice":   {"XProtect", "Apple", "AV"},
	"endpointsecurityd": {"Endpoint Security", "Apple", "EDR"},

	// Linux-specific
	"clamd":     {"ClamAV", "Open Source", "AV"},
	"freshclam": {"ClamAV", "Open Source", "AV"},
	"auditd":    {"Linux Audit", "Open Source", "Logging"},
}

// detectedProduct holds info about a found security product
type detectedProduct struct {
	Product     string `json:"product"`
	Vendor      string `json:"vendor"`
	Category    string `json:"category"`
	ProcessName string `json:"process"`
	PID         int32  `json:"pid"`
}

func (c *AvDetectCommand) Execute(task structs.Task) structs.CommandResult {
	procs, err := process.Processes()
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error enumerating processes: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var detected []detectedProduct

	for _, p := range procs {
		name, err := p.Name()
		if err != nil {
			continue
		}

		nameLower := strings.ToLower(name)
		if product, ok := knownSecurityProcesses[nameLower]; ok {
			detected = append(detected, detectedProduct{
				Product:     product.Product,
				Vendor:      product.Vendor,
				Category:    product.Category,
				ProcessName: name,
				PID:         p.Pid,
			})
		}
	}

	if len(detected) == 0 {
		return structs.CommandResult{
			Output:    "[]",
			Status:    "success",
			Completed: true,
		}
	}

	data, err := json.Marshal(detected)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error marshaling results: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output:    string(data),
		Status:    "success",
		Completed: true,
	}
}
