//go:build linux

package commands

import (
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

// knownSecurityKernelModules maps kernel module names to security products.
var knownSecurityKernelModules = map[string]securityProduct{
	"falcon_lsm_serviceable":   {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcon_lsm_pinned_16206":  {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcon_lsm_pinned_16306":  {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcon_lsm_pinned_16506":  {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"falcon_nf":                {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"sentinelone":              {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelagent":            {"SentinelOne", "SentinelOne", "EDR"},
	"s1_agent":                 {"SentinelOne", "SentinelOne", "EDR"},
	"cbsensor":                 {"Carbon Black", "VMware", "EDR"},
	"event_monitor":            {"Carbon Black", "VMware", "EDR"},
	"sophos_lsm":               {"Sophos Endpoint", "Sophos", "AV"},
	"cylance":                  {"Cylance", "BlackBerry", "AV"},
	"trendmicro_filter":        {"Trend Micro", "Trend Micro", "AV"},
}

// knownSecuritySystemdUnits maps systemd unit names to security products.
var knownSecuritySystemdUnits = map[string]securityProduct{
	"falcon-sensor.service":          {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"sentinelagent.service":          {"SentinelOne", "SentinelOne", "EDR"},
	"sentinelone.service":            {"SentinelOne", "SentinelOne", "EDR"},
	"cbagentd.service":               {"Carbon Black", "VMware", "EDR"},
	"cbdaemon.service":               {"Carbon Black", "VMware", "EDR"},
	"elastic-agent.service":          {"Elastic Agent", "Elastic", "EDR"},
	"elastic-endpoint.service":       {"Elastic Endpoint", "Elastic", "EDR"},
	"clamav-daemon.service":          {"ClamAV", "Open Source", "AV"},
	"clamav-freshclam.service":       {"ClamAV", "Open Source", "AV"},
	"auditd.service":                 {"Linux Audit", "Open Source", "Logging"},
	"wazuh-agent.service":            {"Wazuh Agent", "Wazuh", "Logging"},
	"ossec-hids.service":             {"OSSEC/Wazuh", "Wazuh", "Logging"},
	"splunkd.service":                {"Splunk Forwarder", "Splunk", "Logging"},
	"SplunkForwarder.service":        {"Splunk Forwarder", "Splunk", "Logging"},
	"taniumclient.service":           {"Tanium", "Tanium", "EDR"},
	"cortex-xdr.service":             {"Cortex XDR", "Palo Alto", "EDR"},
	"traps_pmd.service":              {"Cortex XDR", "Palo Alto", "EDR"},
	"sophos-spl.service":             {"Sophos Endpoint", "Sophos", "AV"},
	"savd.service":                   {"Sophos Endpoint", "Sophos", "AV"},
	"esets.service":                  {"ESET Endpoint Security", "ESET", "AV"},
	"qualys-cloud-agent.service":     {"Qualys Agent", "Qualys", "Logging"},
	"ds_agent.service":               {"Trend Micro Deep Security", "Trend Micro", "EDR"},
	"MFEcma.service":                 {"McAfee/Trellix", "Trellix", "AV"},
	"bdsec.service":                  {"Bitdefender", "Bitdefender", "AV"},
	"sysmonforlinux.service":         {"Sysmon for Linux", "Microsoft", "Logging"},
	"mdatp.service":                  {"Defender for Endpoint", "Microsoft", "EDR"},
	"osqueryd.service":               {"osquery", "Open Source", "Logging"},
	"filebeat.service":               {"Filebeat", "Elastic", "Logging"},
	"rapid7-ir-agent.service":        {"Rapid7 InsightIDR", "Rapid7", "EDR"},
}

// knownSecurityConfigPaths maps config directory/file paths to security products.
var knownSecurityConfigPaths = map[string]securityProduct{
	"/opt/CrowdStrike":                {"CrowdStrike Falcon", "CrowdStrike", "EDR"},
	"/opt/sentinelone":                {"SentinelOne", "SentinelOne", "EDR"},
	"/opt/carbonblack":                {"Carbon Black", "VMware", "EDR"},
	"/opt/sophos-av":                  {"Sophos Endpoint", "Sophos", "AV"},
	"/etc/sophos-av":                  {"Sophos Endpoint", "Sophos", "AV"},
	"/opt/eset":                       {"ESET Endpoint Security", "ESET", "AV"},
	"/etc/eset":                       {"ESET Endpoint Security", "ESET", "AV"},
	"/opt/McAfee":                     {"McAfee/Trellix", "Trellix", "AV"},
	"/opt/isec":                       {"McAfee/Trellix", "Trellix", "AV"},
	"/etc/opt/BESClient":              {"BigFix", "HCL", "Logging"},
	"/opt/Tanium":                     {"Tanium", "Tanium", "EDR"},
	"/opt/traps":                      {"Cortex XDR", "Palo Alto", "EDR"},
	"/etc/panw":                       {"Cortex XDR", "Palo Alto", "EDR"},
	"/var/ossec":                      {"OSSEC/Wazuh", "Wazuh", "Logging"},
	"/opt/SplunkForwarder":            {"Splunk Forwarder", "Splunk", "Logging"},
	"/opt/splunkforwarder":            {"Splunk Forwarder", "Splunk", "Logging"},
	"/opt/qualys":                     {"Qualys Agent", "Qualys", "Logging"},
	"/opt/ds_agent":                   {"Trend Micro Deep Security", "Trend Micro", "EDR"},
	"/opt/rapid7":                     {"Rapid7 InsightIDR", "Rapid7", "EDR"},
	"/opt/microsoft/mdatp":            {"Defender for Endpoint", "Microsoft", "EDR"},
	"/etc/opt/microsoft/mdatp":        {"Defender for Endpoint", "Microsoft", "EDR"},
	"/opt/microsoft/sysmonforlinux":   {"Sysmon for Linux", "Microsoft", "Logging"},
	"/opt/elastic-agent":              {"Elastic Agent", "Elastic", "EDR"},
	"/opt/Elastic/Agent":              {"Elastic Agent", "Elastic", "EDR"},
	"/opt/Elastic/Endpoint":           {"Elastic Endpoint", "Elastic", "EDR"},
	"/opt/bitdefender-security-tools": {"Bitdefender", "Bitdefender", "AV"},
}

// avDeepScan checks kernel modules, systemd units, and config directories.
func avDeepScan() []detectedProduct {
	var results []detectedProduct

	// Deduplicate: track products already found
	seen := make(map[string]bool)

	// 1. Check loaded kernel modules
	if data, err := os.ReadFile("/proc/modules"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			modName := strings.ToLower(fields[0])
			if product, ok := knownSecurityKernelModules[modName]; ok {
				key := product.Vendor + ":" + product.Product
				if !seen[key] {
					seen[key] = true
					results = append(results, detectedProduct{
						Product:     product.Product,
						Vendor:      product.Vendor,
						Category:    product.Category,
						ProcessName: "kmod:" + fields[0],
						PID:         0,
					})
				}
			}
		}
		structs.ZeroBytes(data)
	}

	// 2. Check systemd unit files
	unitDirs := []string{
		"/etc/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}
	for _, dir := range unitDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			name := entry.Name()
			if product, ok := knownSecuritySystemdUnits[name]; ok {
				key := product.Vendor + ":" + product.Product
				if !seen[key] {
					seen[key] = true
					results = append(results, detectedProduct{
						Product:     product.Product,
						Vendor:      product.Vendor,
						Category:    product.Category,
						ProcessName: "systemd:" + name,
						PID:         0,
					})
				}
			}
			// Also check for symlinks to known units
			if entry.Type()&os.ModeSymlink != 0 {
				target, err := os.Readlink(filepath.Join(dir, name))
				if err == nil {
					base := filepath.Base(target)
					if product, ok := knownSecuritySystemdUnits[base]; ok {
						key := product.Vendor + ":" + product.Product
						if !seen[key] {
							seen[key] = true
							results = append(results, detectedProduct{
								Product:     product.Product,
								Vendor:      product.Vendor,
								Category:    product.Category,
								ProcessName: "systemd:" + base,
								PID:         0,
							})
						}
					}
				}
			}
		}
	}

	// 3. Check known config directories
	for path, product := range knownSecurityConfigPaths {
		if _, err := os.Stat(path); err == nil {
			key := product.Vendor + ":" + product.Product
			if !seen[key] {
				seen[key] = true
				results = append(results, detectedProduct{
					Product:     product.Product,
					Vendor:      product.Vendor,
					Category:    product.Category,
					ProcessName: "config:" + path,
					PID:         0,
				})
			}
		}
	}

	return results
}
