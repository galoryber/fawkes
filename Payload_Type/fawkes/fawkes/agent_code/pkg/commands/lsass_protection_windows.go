//go:build windows
// +build windows

package commands

// Windows-only registry reader for LsassProtectionState.
//
// `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` is readable by any local
// member of the Users group; the agent does not need elevation to inspect
// the protection-state values. The reader is best-effort — missing keys
// surface as `*Detected = false` rather than errors so the JSON output is
// always populated.

import "golang.org/x/sys/windows/registry"

const lsaProtectionRegPath = `SYSTEM\CurrentControlSet\Control\Lsa`

func detectLsassProtection() LsassProtectionState {
	var state LsassProtectionState

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, lsaProtectionRegPath, registry.QUERY_VALUE)
	if err != nil {
		state.Error = err.Error()
		return state
	}
	defer key.Close()

	if v, _, err := key.GetIntegerValue("RunAsPPL"); err == nil {
		state.RunAsPPL = uint32(v)
		state.RunAsPPLDetected = true
	}
	if v, _, err := key.GetIntegerValue("LsaCfgFlags"); err == nil {
		state.LsaCfgFlags = uint32(v)
		state.LsaCfgFlagsDetected = true
	}
	return state
}
