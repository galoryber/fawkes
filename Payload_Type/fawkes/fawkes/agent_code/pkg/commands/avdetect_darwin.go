//go:build darwin

package commands

import (
	"os"
	"path/filepath"
	"strings"
)

// knownSecurityKexts maps kernel extension bundle names to security products.
var knownSecurityKexts = map[string]securityProduct{
	"com.crowdstrike.sensor":       {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"crowdstrike":                  {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"sentinelmonitor":              {"SentinelOne", "SentinelOne", "EDR"},
	"sentinel":                     {"SentinelOne", "SentinelOne", "EDR"},
	"cbdefensesensor":              {"Carbon Black", "VMware", "EDR"},
	"carbonblack":                  {"Carbon Black", "VMware", "EDR"},
	"sophos":                       {"Sophos Endpoint", "Sophos", "AV"},
	"eset":                         {"ESET Endpoint Security", "ESET", "AV"},
	"symantec":                     {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"trendmicro":                   {"Trend Micro", "Trend Micro", "AV"},
	"kaspersky":                    {"Kaspersky", "Kaspersky", "AV"},
	"bitdefender":                  {"Bitdefender", "Bitdefender", "AV"},
	"littlesnitch":                 {"Little Snitch", "Objective Development", "Firewall"},
	"lulu":                         {"LuLu", "Objective-See", "Firewall"},
}

// knownSecuritySystemExtensions maps system extension identifiers to security products.
var knownSecuritySystemExtensions = map[string]securityProduct{
	"com.crowdstrike.falcon":  {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"com.sentinelone":         {"SentinelOne", "SentinelOne", "EDR"},
	"com.vmware.carbonblack":  {"Carbon Black", "VMware", "EDR"},
	"com.microsoft.wdav":      {"Defender for Endpoint", "Microsoft", "EDR"},
	"com.sophos":              {"Sophos Endpoint", "Sophos", "AV"},
	"com.eset":                {"ESET Endpoint Security", "ESET", "AV"},
	"com.elastic":             {"Elastic Agent", "Elastic", "EDR"},
	"com.paloaltonetworks":    {"Cortex XDR", "Palo Alto", "EDR"},
	"com.trendmicro":          {"Trend Micro", "Trend Micro", "AV"},
	"com.bitdefender":         {"Bitdefender", "Bitdefender", "AV"},
	"com.malwarebytes":        {"Malwarebytes", "Malwarebytes", "AV"},
	"com.objective-see.lulu":  {"LuLu", "Objective-See", "Firewall"},
	"at.obdev.littlesnitch":   {"Little Snitch", "Objective Development", "Firewall"},
}

// knownSecurityLaunchDaemons maps LaunchDaemon plist filenames to security products.
var knownSecurityLaunchDaemons = map[string]securityProduct{
	"com.crowdstrike.falcond.plist":                    {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"com.crowdstrike.falcon.Agent.plist":               {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"com.sentinelone.sentinelagent.plist":               {"SentinelOne", "SentinelOne", "EDR"},
	"com.sentinelone.sentinelagent-helper.plist":        {"SentinelOne", "SentinelOne", "EDR"},
	"com.vmware.carbonblack.daemon.plist":               {"Carbon Black", "VMware", "EDR"},
	"com.carbonblack.defense.daemon.plist":              {"Carbon Black", "VMware", "EDR"},
	"com.microsoft.wdav.daemon.plist":                   {"Defender for Endpoint", "Microsoft", "EDR"},
	"com.microsoft.dlp.daemon.plist":                    {"Microsoft DLP", "Microsoft", "DLP"},
	"com.sophos.endpoint.scanengine.plist":              {"Sophos Endpoint", "Sophos", "AV"},
	"com.sophos.endpoint.uiserver.plist":                {"Sophos Endpoint", "Sophos", "AV"},
	"com.sophos.autoupdate.plist":                       {"Sophos Endpoint", "Sophos", "AV"},
	"com.eset.remoteadministrator.agent.plist":          {"ESET Endpoint Security", "ESET", "AV"},
	"com.eset.esets_daemon.plist":                       {"ESET Endpoint Security", "ESET", "AV"},
	"com.elastic.agent.plist":                           {"Elastic Agent", "Elastic", "EDR"},
	"com.elastic.endpoint.plist":                        {"Elastic Endpoint", "Elastic", "EDR"},
	"com.paloaltonetworks.traps.pmd.plist":              {"Cortex XDR", "Palo Alto", "EDR"},
	"com.trendmicro.icore.daemon.plist":                 {"Trend Micro", "Trend Micro", "AV"},
	"com.kaspersky.kav.plist":                           {"Kaspersky", "Kaspersky", "AV"},
	"com.bitdefender.EndpointSecurityforMac.plist":      {"Bitdefender", "Bitdefender", "AV"},
	"com.malwarebytes.mbam.rtprotection.daemon.plist":   {"Malwarebytes", "Malwarebytes", "AV"},
	"com.jamf.protect.daemon.plist":                     {"Jamf Protect", "Jamf", "EDR"},
	"com.kandji.agent.plist":                            {"Kandji Agent", "Kandji", "Logging"},
	"at.obdev.littlesnitchd.plist":                      {"Little Snitch", "Objective Development", "Firewall"},
	"com.objective-see.lulu.plist":                      {"LuLu", "Objective-See", "Firewall"},
	"com.cisco.amp.daemon.plist":                        {"Cisco Secure Endpoint", "Cisco", "EDR"},
	"com.tanium.taniumclient.plist":                     {"Tanium", "Tanium", "EDR"},
	"com.rapid7.ir_agent.plist":                         {"Rapid7 InsightIDR", "Rapid7", "EDR"},
	"com.cylance.agent.plist":                           {"Cylance", "BlackBerry", "AV"},
	"com.wazuh.agent.plist":                             {"Wazuh Agent", "Wazuh", "Logging"},
	"com.splunk.forwarder.plist":                        {"Splunk Forwarder", "Splunk", "Logging"},
	"com.osquery.osqueryd.plist":                        {"osquery", "Open Source", "Logging"},
}

// knownSecurityApps maps application bundle names (in /Applications/) to security products.
var knownSecurityApps = map[string]securityProduct{
	"CrowdStrike Falcon.app":                {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"Falcon.app":                            {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"SentinelOne.app":                       {"SentinelOne", "SentinelOne", "EDR"},
	"SentinelOne Extensions.app":            {"SentinelOne", "SentinelOne", "EDR"},
	"Carbon Black Cloud.app":                {"Carbon Black", "VMware", "EDR"},
	"Microsoft Defender.app":                {"Defender for Endpoint", "Microsoft", "EDR"},
	"Sophos Endpoint.app":                   {"Sophos Endpoint", "Sophos", "AV"},
	"Sophos Anti-Virus.app":                 {"Sophos Endpoint", "Sophos", "AV"},
	"ESET Endpoint Security.app":            {"ESET Endpoint Security", "ESET", "AV"},
	"ESET Endpoint Antivirus.app":           {"ESET Endpoint Security", "ESET", "AV"},
	"Cortex XDR.app":                        {"Cortex XDR", "Palo Alto", "EDR"},
	"Trend Micro Antivirus.app":             {"Trend Micro", "Trend Micro", "AV"},
	"Kaspersky Internet Security.app":       {"Kaspersky", "Kaspersky", "AV"},
	"Bitdefender Antivirus for Mac.app":     {"Bitdefender", "Bitdefender", "AV"},
	"Malwarebytes.app":                      {"Malwarebytes", "Malwarebytes", "AV"},
	"Norton Security.app":                   {"Norton", "Gen Digital", "AV"},
	"Norton 360.app":                        {"Norton", "Gen Digital", "AV"},
	"Jamf Protect.app":                      {"Jamf Protect", "Jamf", "EDR"},
	"Little Snitch.app":                     {"Little Snitch", "Objective Development", "Firewall"},
	"LuLu.app":                              {"LuLu", "Objective-See", "Firewall"},
	"BlockBlock.app":                        {"BlockBlock", "Objective-See", "HIPS"},
	"KnockKnock.app":                        {"KnockKnock", "Objective-See", "Logging"},
	"OverSight.app":                         {"OverSight", "Objective-See", "Logging"},
	"Cisco Secure Client.app":               {"Cisco Secure Endpoint", "Cisco", "EDR"},
	"Symantec Endpoint Protection.app":      {"Symantec Endpoint Protection", "Broadcom", "AV"},
	"Avast Security.app":                    {"Avast", "Gen Digital", "AV"},
	"AVG Antivirus.app":                     {"AVG", "Gen Digital", "AV"},
	"ClamXAV.app":                           {"ClamXAV", "ClamXAV", "AV"},
	"Intego VirusBarrier.app":               {"VirusBarrier", "Intego", "AV"},
}

// knownSecurityConfigDirs maps macOS config directory paths to security products.
var knownSecurityConfigDirs = map[string]securityProduct{
	"/Library/Application Support/CrowdStrike":             {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"/Library/CS":                                          {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"/Library/Application Support/com.sentinelone":         {"SentinelOne", "SentinelOne", "EDR"},
	"/Library/Sentinel":                                    {"SentinelOne", "SentinelOne", "EDR"},
	"/Library/Application Support/com.vmware.carbonblack":  {"Carbon Black", "VMware", "EDR"},
	"/Library/Application Support/CarbonBlack":             {"Carbon Black", "VMware", "EDR"},
	"/Library/Application Support/Microsoft/Defender":      {"Defender for Endpoint", "Microsoft", "EDR"},
	"/Library/Application Support/Sophos":                  {"Sophos Endpoint", "Sophos", "AV"},
	"/Library/Application Support/com.eset":                {"ESET Endpoint Security", "ESET", "AV"},
	"/Library/Application Support/ESET":                    {"ESET Endpoint Security", "ESET", "AV"},
	"/Library/Application Support/Elastic":                 {"Elastic Agent", "Elastic", "EDR"},
	"/Library/Application Support/PaloAltoNetworks":        {"Cortex XDR", "Palo Alto", "EDR"},
	"/Library/Application Support/TrendMicro":              {"Trend Micro", "Trend Micro", "AV"},
	"/Library/Application Support/Kaspersky Lab":           {"Kaspersky", "Kaspersky", "AV"},
	"/Library/Application Support/Bitdefender":             {"Bitdefender", "Bitdefender", "AV"},
	"/Library/Application Support/Malwarebytes":            {"Malwarebytes", "Malwarebytes", "AV"},
	"/Library/Application Support/Jamf/Protect":            {"Jamf Protect", "Jamf", "EDR"},
	"/Library/Application Support/Kandji":                  {"Kandji Agent", "Kandji", "Logging"},
	"/usr/local/McAfee":                                    {"McAfee/Trellix", "Trellix", "AV"},
	"/Library/McAfee":                                      {"McAfee/Trellix", "Trellix", "AV"},
	"/Library/Tanium":                                      {"Tanium", "Tanium", "EDR"},
	"/Library/Cisco/AMP":                                   {"Cisco Secure Endpoint", "Cisco", "EDR"},
	"/Library/Application Support/Cylance":                 {"Cylance", "BlackBerry", "AV"},
	"/var/ossec":                                           {"OSSEC/Wazuh", "Wazuh", "Logging"},
	"/Library/Ossec":                                       {"OSSEC/Wazuh", "Wazuh", "Logging"},
	"/opt/SplunkForwarder":                                 {"Splunk Forwarder", "Splunk", "Logging"},
	"/opt/splunkforwarder":                                 {"Splunk Forwarder", "Splunk", "Logging"},
	"/Library/Rapid7":                                      {"Rapid7 InsightIDR", "Rapid7", "EDR"},
	"/var/db/osquery":                                      {"osquery", "Open Source", "Logging"},
}

// avDeepScan checks kernel extensions, system extensions, LaunchDaemons,
// LaunchAgents, application bundles, and config directories on macOS.
func avDeepScan() []detectedProduct {
	var results []detectedProduct
	seen := make(map[string]bool)

	addResult := func(product securityProduct, source string) {
		key := product.Vendor + ":" + product.Product
		if !seen[key] {
			seen[key] = true
			results = append(results, detectedProduct{
				Product:     product.Product,
				Vendor:      product.Vendor,
				Category:    product.Category,
				ProcessName: source,
				PID:         0,
			})
		}
	}

	// 1. Check kernel extensions
	for _, kextDir := range []string{"/Library/Extensions", "/System/Library/Extensions"} {
		entries, err := os.ReadDir(kextDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			nameLower := strings.ToLower(entry.Name())
			for keyword, product := range knownSecurityKexts {
				if strings.Contains(nameLower, keyword) {
					addResult(product, "kext:"+entry.Name())
					break
				}
			}
		}
	}

	// 2. Check system extensions
	sysExtDir := "/Library/SystemExtensions"
	if entries, err := os.ReadDir(sysExtDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			// System extensions are directories containing .systemextension bundles
			subEntries, err := os.ReadDir(filepath.Join(sysExtDir, entry.Name()))
			if err != nil {
				continue
			}
			for _, sub := range subEntries {
				nameLower := strings.ToLower(sub.Name())
				for prefix, product := range knownSecuritySystemExtensions {
					if strings.HasPrefix(nameLower, prefix) {
						addResult(product, "sysext:"+sub.Name())
						break
					}
				}
			}
		}
	}

	// 3. Check LaunchDaemons
	for _, daemonDir := range []string{"/Library/LaunchDaemons"} {
		entries, err := os.ReadDir(daemonDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if product, ok := knownSecurityLaunchDaemons[entry.Name()]; ok {
				addResult(product, "launchdaemon:"+entry.Name())
			}
		}
	}

	// 4. Check LaunchAgents (system-level only, not per-user)
	for _, agentDir := range []string{"/Library/LaunchAgents"} {
		entries, err := os.ReadDir(agentDir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			nameLower := strings.ToLower(entry.Name())
			// Match known security vendor prefixes in LaunchAgent plists
			for prefix, product := range knownSecuritySystemExtensions {
				if strings.HasPrefix(nameLower, prefix) {
					addResult(product, "launchagent:"+entry.Name())
					break
				}
			}
		}
	}

	// 5. Check application bundles
	if entries, err := os.ReadDir("/Applications"); err == nil {
		for _, entry := range entries {
			if product, ok := knownSecurityApps[entry.Name()]; ok {
				addResult(product, "app:"+entry.Name())
			}
		}
	}

	// 6. Check config directories
	for path, product := range knownSecurityConfigDirs {
		if _, err := os.Stat(path); err == nil {
			addResult(product, "config:"+path)
		}
	}

	return results
}
