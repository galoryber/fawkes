package commands

import (
	"strings"
	"testing"
)

func TestLsassProtectionState_PPLActive(t *testing.T) {
	cases := []struct {
		name string
		s    LsassProtectionState
		want bool
	}{
		{"undetected returns false", LsassProtectionState{}, false},
		{"detected zero returns false", LsassProtectionState{RunAsPPL: 0, RunAsPPLDetected: true}, false},
		{"detected one returns true", LsassProtectionState{RunAsPPL: 1, RunAsPPLDetected: true}, true},
		{"detected two returns true", LsassProtectionState{RunAsPPL: 2, RunAsPPLDetected: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.PPLActive(); got != tc.want {
				t.Errorf("PPLActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLsassProtectionState_CredentialGuardActive(t *testing.T) {
	cases := []struct {
		name string
		s    LsassProtectionState
		want bool
	}{
		{"undetected returns false", LsassProtectionState{}, false},
		{"detected zero returns false", LsassProtectionState{LsaCfgFlags: 0, LsaCfgFlagsDetected: true}, false},
		{"detected one returns true", LsassProtectionState{LsaCfgFlags: 1, LsaCfgFlagsDetected: true}, true},
		{"detected two returns true", LsassProtectionState{LsaCfgFlags: 2, LsaCfgFlagsDetected: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.CredentialGuardActive(); got != tc.want {
				t.Errorf("CredentialGuardActive() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestLsassProtectionState_RunAsPPLLabel(t *testing.T) {
	cases := []struct {
		name string
		s    LsassProtectionState
		want string
	}{
		{"unset", LsassProtectionState{}, "unset"},
		{"off", LsassProtectionState{RunAsPPL: 0, RunAsPPLDetected: true}, "off"},
		{"PPL", LsassProtectionState{RunAsPPL: 1, RunAsPPLDetected: true}, "PPL"},
		{"PPL+UEFI-lock", LsassProtectionState{RunAsPPL: 2, RunAsPPLDetected: true}, "PPL+UEFI-lock"},
		{"unknown(7)", LsassProtectionState{RunAsPPL: 7, RunAsPPLDetected: true}, "unknown(7)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.RunAsPPLLabel(); got != tc.want {
				t.Errorf("RunAsPPLLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLsassProtectionState_LsaCfgFlagsLabel(t *testing.T) {
	cases := []struct {
		name string
		s    LsassProtectionState
		want string
	}{
		{"unset", LsassProtectionState{}, "unset"},
		{"off", LsassProtectionState{LsaCfgFlags: 0, LsaCfgFlagsDetected: true}, "off"},
		{"CredGuard+UEFI-lock", LsassProtectionState{LsaCfgFlags: 1, LsaCfgFlagsDetected: true}, "CredGuard+UEFI-lock"},
		{"CredGuard", LsassProtectionState{LsaCfgFlags: 2, LsaCfgFlagsDetected: true}, "CredGuard"},
		{"unknown(99)", LsassProtectionState{LsaCfgFlags: 99, LsaCfgFlagsDetected: true}, "unknown(99)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.LsaCfgFlagsLabel(); got != tc.want {
				t.Errorf("LsaCfgFlagsLabel() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLsassProtectionState_Summary(t *testing.T) {
	cases := []struct {
		name    string
		s       LsassProtectionState
		want    string
	}{
		{
			name: "everything unset",
			s:    LsassProtectionState{},
			want: "RunAsPPL=unset; LsaCfgFlags=unset",
		},
		{
			name: "PPL+UEFI-lock + CredGuard",
			s: LsassProtectionState{
				RunAsPPL: 2, RunAsPPLDetected: true,
				LsaCfgFlags: 2, LsaCfgFlagsDetected: true,
			},
			want: "RunAsPPL=PPL+UEFI-lock; LsaCfgFlags=CredGuard",
		},
		{
			name: "registry error with no detections",
			s:    LsassProtectionState{Error: "open: access denied"},
			want: "protection state unavailable: open: access denied",
		},
		{
			name: "error but partial detection still summarises labels",
			s: LsassProtectionState{
				RunAsPPL: 1, RunAsPPLDetected: true,
				Error: "LsaCfgFlags: not found",
			},
			want: "RunAsPPL=PPL; LsaCfgFlags=unset",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.Summary(); got != tc.want {
				t.Errorf("Summary() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLsassProtectionState_AccessDeniedHint(t *testing.T) {
	cases := []struct {
		name        string
		s           LsassProtectionState
		mustContain []string
	}{
		{
			name:        "no protection => privilege guidance",
			s:           LsassProtectionState{},
			mustContain: []string{"Neither RunAsPPL", "SYSTEM", "SeDebugPrivilege"},
		},
		{
			name: "PPL only",
			s:    LsassProtectionState{RunAsPPL: 2, RunAsPPLDetected: true},
			mustContain: []string{
				"PPL-protected", "PPL+UEFI-lock", "kernel-level PPL bypass",
			},
		},
		{
			name: "CG only",
			s:    LsassProtectionState{LsaCfgFlags: 2, LsaCfgFlagsDetected: true},
			mustContain: []string{
				"Credential Guard is active", "VTL1", "outside the LSASS address space",
			},
		},
		{
			name: "PPL + CG combined",
			s: LsassProtectionState{
				RunAsPPL: 2, RunAsPPLDetected: true,
				LsaCfgFlags: 2, LsaCfgFlagsDetected: true,
			},
			mustContain: []string{
				"PPL-protected", "Credential Guard is active",
				"kernel level", // appears as "kernel level" in the combined branch
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.s.AccessDeniedHint()
			if got == "" {
				t.Fatalf("AccessDeniedHint() returned empty string")
			}
			for _, frag := range tc.mustContain {
				if !strings.Contains(got, frag) {
					t.Errorf("AccessDeniedHint() = %q\n  missing fragment %q", got, frag)
				}
			}
		})
	}
}
