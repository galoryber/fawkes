//go:build windows
// +build windows

package commands

import (
	"testing"
	"unsafe"
)

func TestInsituLogonSessionDataLayout(t *testing.T) {
	var d insituLogonSessionData

	// Total size must be 136 bytes (0x88) to match SECURITY_LOGON_SESSION_DATA on amd64
	if got := unsafe.Sizeof(d); got != 136 {
		t.Errorf("insituLogonSessionData size = %d, want 136", got)
	}

	// Key field offsets match Windows SDK layout verified against SECURITY_LOGON_SESSION_DATA
	cases := []struct {
		field  string
		offset uintptr
	}{
		{"Size", unsafe.Offsetof(d.Size)},             // +0x00
		{"LogonIdLow", unsafe.Offsetof(d.LogonIdLow)}, // +0x04
		{"LogonIdHigh", unsafe.Offsetof(d.LogonIdHigh)}, // +0x08
		{"UserName", unsafe.Offsetof(d.UserName)},     // +0x10
		{"LogonDomain", unsafe.Offsetof(d.LogonDomain)}, // +0x20
		{"AuthPkg", unsafe.Offsetof(d.AuthPkg)},       // +0x30
		{"LogonType", unsafe.Offsetof(d.LogonType)},   // +0x40
		{"Session", unsafe.Offsetof(d.Session)},       // +0x44
		{"Sid", unsafe.Offsetof(d.Sid)},               // +0x48
		{"LogonTime", unsafe.Offsetof(d.LogonTime)},   // +0x50
		{"LogonServer", unsafe.Offsetof(d.LogonServer)}, // +0x58
		{"DnsDomainName", unsafe.Offsetof(d.DnsDomainName)}, // +0x68
		{"Upn", unsafe.Offsetof(d.Upn)},               // +0x78
	}
	want := []uintptr{0x00, 0x04, 0x08, 0x10, 0x20, 0x30, 0x40, 0x44, 0x48, 0x50, 0x58, 0x68, 0x78}

	for i, tc := range cases {
		if tc.offset != want[i] {
			t.Errorf("insituLogonSessionData.%s offset = 0x%x, want 0x%x", tc.field, tc.offset, want[i])
		}
	}
}

func TestInsituReadStr_Empty(t *testing.T) {
	// Zero Length → empty string
	s := unicodeStringKL{Length: 0, Buffer: 0}
	if got := insituReadStr(s); got != "" {
		t.Errorf("insituReadStr(zero) = %q, want empty", got)
	}
}

func TestInsituReadStr_ZeroBuffer(t *testing.T) {
	// Non-zero length but null Buffer pointer → empty string (avoids nil dereference)
	s := unicodeStringKL{Length: 10, Buffer: 0}
	if got := insituReadStr(s); got != "" {
		t.Errorf("insituReadStr(null buffer) = %q, want empty", got)
	}
}

func TestInsituLogonTypeName(t *testing.T) {
	cases := []struct {
		typ  uint32
		want string
	}{
		{2, "Interactive"},
		{3, "Network"},
		{4, "Batch"},
		{5, "Service"},
		{7, "Unlock"},
		{8, "NetworkCleartext"},
		{9, "NewCredentials"},
		{10, "RemoteInteractive"},
		{11, "CachedInteractive"},
		{12, "CachedRemoteInteractive"},
		{13, "CachedUnlock"},
		{99, "Unknown(99)"},
	}
	for _, tc := range cases {
		if got := insituLogonTypeName(tc.typ); got != tc.want {
			t.Errorf("insituLogonTypeName(%d) = %q, want %q", tc.typ, got, tc.want)
		}
	}
}

func TestInsituFiletimeStr_Zero(t *testing.T) {
	if got := insituFiletimeStr(0); got != "" {
		t.Errorf("insituFiletimeStr(0) = %q, want empty", got)
	}
}

func TestInsituFiletimeStr_Known(t *testing.T) {
	// 2024-01-01 00:00:00 UTC as Windows FILETIME:
	// Unix: 1704067200 → FILETIME = (1704067200 + 11644473600) * 10000000 = 133483296000000000
	const ft = int64(133483296000000000)
	got := insituFiletimeStr(ft)
	if got != "2024-01-01 00:00:00 UTC" {
		t.Errorf("insituFiletimeStr(%d) = %q, want 2024-01-01 00:00:00 UTC", ft, got)
	}
}

func TestInsituFiletimeStr_Negative(t *testing.T) {
	if got := insituFiletimeStr(-1); got != "" {
		t.Errorf("insituFiletimeStr(-1) = %q, want empty", got)
	}
}

func TestInsituEnableDebugPriv_NoError(t *testing.T) {
	// May fail if not running as admin — that's acceptable. Must not panic.
	_ = insituEnableDebugPriv()
}
