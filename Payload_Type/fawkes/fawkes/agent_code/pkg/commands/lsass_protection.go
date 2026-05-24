package commands

// LSASS Protection-State Reporter (cross-platform data model).
//
// Phase 2A's lsassOpenForRead returns ACCESS_DENIED when LSASS is running as a
// Protected Process Light (PPL) — the default posture on Win11 22H2+ and on any
// host with `RunAsPPL=1|2` set under HKLM\SYSTEM\CurrentControlSet\Control\Lsa.
// The same registry hive also describes Credential Guard via `LsaCfgFlags`.
//
// This file defines the cross-platform LsassProtectionState struct and the
// formatting helpers that translate the raw registry DWORDs into operator-
// readable strings. The Windows-only registry reader lives in
// `lsass_protection_windows.go`. Splitting them lets the formatters be unit
// tested on Linux against synthetic state values without needing a Windows
// registry.

import "fmt"

// LsassProtectionState captures the relevant LSA-protection registry values
// from `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. Each Detected flag is
// independently set so callers can distinguish "key is absent / unreadable"
// from "key present and explicitly set to 0".
type LsassProtectionState struct {
	RunAsPPL         uint32 // 0=off, 1=PPL, 2=PPL with UEFI variable lock
	RunAsPPLDetected bool

	LsaCfgFlags         uint32 // 1=CG+UEFI lock, 2=CG no UEFI lock, 0=off
	LsaCfgFlagsDetected bool

	// Error captures the first non-trivial error encountered while reading
	// the registry (e.g. permission denied on the Lsa key). Empty on a
	// healthy non-elevated read.
	Error string
}

// PPLActive returns true if RunAsPPL is detected and non-zero.
func (s LsassProtectionState) PPLActive() bool {
	return s.RunAsPPLDetected && s.RunAsPPL != 0
}

// CredentialGuardActive returns true if LsaCfgFlags is detected and non-zero.
func (s LsassProtectionState) CredentialGuardActive() bool {
	return s.LsaCfgFlagsDetected && s.LsaCfgFlags != 0
}

// RunAsPPLLabel returns a human-readable label for the RunAsPPL value
// matching the values documented in the Microsoft "Configure additional LSA
// protection" article: 0=off, 1=PPL, 2=PPL with UEFI variable lock. Unknown
// values are reported as the raw integer for layout-drift triage.
func (s LsassProtectionState) RunAsPPLLabel() string {
	if !s.RunAsPPLDetected {
		return "unset"
	}
	switch s.RunAsPPL {
	case 0:
		return "off"
	case 1:
		return "PPL"
	case 2:
		return "PPL+UEFI-lock"
	default:
		return fmt.Sprintf("unknown(%d)", s.RunAsPPL)
	}
}

// LsaCfgFlagsLabel returns a human-readable label for the Credential Guard
// configuration value. 0=off, 1=CG with UEFI lock, 2=CG without UEFI lock.
func (s LsassProtectionState) LsaCfgFlagsLabel() string {
	if !s.LsaCfgFlagsDetected {
		return "unset"
	}
	switch s.LsaCfgFlags {
	case 0:
		return "off"
	case 1:
		return "CredGuard+UEFI-lock"
	case 2:
		return "CredGuard"
	default:
		return fmt.Sprintf("unknown(%d)", s.LsaCfgFlags)
	}
}

// Summary returns a one-line operator-facing description, suitable for both
// JSON output and the error-message tail when OpenProcess fails.
func (s LsassProtectionState) Summary() string {
	if s.Error != "" && !s.RunAsPPLDetected && !s.LsaCfgFlagsDetected {
		return fmt.Sprintf("protection state unavailable: %s", s.Error)
	}
	return fmt.Sprintf("RunAsPPL=%s; LsaCfgFlags=%s",
		s.RunAsPPLLabel(), s.LsaCfgFlagsLabel())
}

// AccessDeniedHint returns a tactical sentence appended to the Phase 2B
// "OpenProcess failed: Access is denied" error path. The hint maps the
// detected protection state to the most likely real-world cause.
func (s LsassProtectionState) AccessDeniedHint() string {
	switch {
	case s.PPLActive() && s.CredentialGuardActive():
		return fmt.Sprintf("LSASS is PPL-protected (%s) AND Credential Guard is active (%s) — "+
			"PROCESS_VM_READ on lsass.exe is blocked at the kernel level. Even SYSTEM + SeDebugPrivilege "+
			"cannot open this LSASS for memory read; a kernel-level PPL bypass would be required to proceed.",
			s.RunAsPPLLabel(), s.LsaCfgFlagsLabel())
	case s.PPLActive():
		return fmt.Sprintf("LSASS is PPL-protected (%s) — PROCESS_VM_READ is blocked by the protected-process "+
			"check in PsTestProtectedProcessIncompatibility. SYSTEM + SeDebugPrivilege are insufficient; a "+
			"kernel-level PPL bypass is required to read LSASS memory on this host.",
			s.RunAsPPLLabel())
	case s.CredentialGuardActive():
		return fmt.Sprintf("Credential Guard is active (%s) — secrets are isolated in a VTL1 process. The "+
			"agent may still open LSASS but LogonSessionList walks will return empty primary credentials "+
			"because the cleartext/hash material lives outside the LSASS address space.",
			s.LsaCfgFlagsLabel())
	default:
		return "Neither RunAsPPL nor LsaCfgFlags is set in the Lsa registry hive — Access Denied likely " +
			"reflects insufficient privileges. The agent needs SYSTEM (integrity 4) plus SeDebugPrivilege " +
			"to open lsass.exe with PROCESS_VM_READ. Re-run after `getsystem` if currently elevated to admin only."
	}
}
