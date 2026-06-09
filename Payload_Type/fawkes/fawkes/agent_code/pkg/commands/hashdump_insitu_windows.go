//go:build windows
// +build windows

package commands

// LSASS In-Situ Credential Analysis — Phase 1
//
// Enumerates active logon sessions by calling LsaEnumerateLogonSessions and
// LsaGetLogonSessionData in-process, then reporting session metadata (user,
// domain, logon type, auth package, logon time). This avoids disk-based LSASS
// dump artifacts.
//
// Phase 2 (future session): walk msv1_0 credential cache via direct LSASS VM_READ
// to extract NT hashes and WDigest cleartext without disk artifacts.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// insituLogonSessionData mirrors SECURITY_LOGON_SESSION_DATA on Windows x64.
//
// Layout (verified against Windows SDK, amd64):
//
//	+0x00 Size                 uint32
//	+0x04 LogonIdLow           uint32
//	+0x08 LogonIdHigh          int32
//	+0x0C _padding             uint32        (aligns next unicodeStringKL to 8-byte boundary)
//	+0x10 UserName             unicodeStringKL (16 bytes)
//	+0x20 LogonDomain          unicodeStringKL
//	+0x30 AuthenticationPackage unicodeStringKL
//	+0x40 LogonType            uint32
//	+0x44 Session              uint32
//	+0x48 Sid                  uintptr
//	+0x50 LogonTime            int64         (LARGE_INTEGER / FILETIME)
//	+0x58 LogonServer          unicodeStringKL
//	+0x68 DnsDomainName        unicodeStringKL
//	+0x78 Upn                  unicodeStringKL
//	+0x88 total size: 136 bytes
//
// unicodeStringKL is defined in klist_windows.go (Length, MaximumLength, _pad, Buffer).
type insituLogonSessionData struct {
	Size                  uint32
	LogonIdLow            uint32
	LogonIdHigh           int32
	_                     uint32          // padding
	UserName              unicodeStringKL // uses type from klist_windows.go
	LogonDomain           unicodeStringKL
	AuthPkg               unicodeStringKL
	LogonType             uint32
	Session               uint32
	Sid                   uintptr
	LogonTime             int64
	LogonServer           unicodeStringKL
	DnsDomainName         unicodeStringKL
	Upn                   unicodeStringKL
}

// insituSession is the JSON output format for a single active logon session.
type insituSession struct {
	LogonID   string `json:"logon_id"`
	Username  string `json:"username"`
	Domain    string `json:"domain"`
	UPN       string `json:"upn,omitempty"`
	LogonType string `json:"logon_type"`
	AuthPkg   string `json:"auth_package"`
	Session   uint32 `json:"session"`
	LogonTime string `json:"logon_time,omitempty"`
	DnsDomain string `json:"dns_domain,omitempty"`
}

// executeInsitu enumerates active logon sessions via LSA APIs and returns
// structured session metadata. Does not write to disk. Requires administrative
// privileges for complete session enumeration across all users.
func executeInsitu() structs.CommandResult {
	sessions, err := enumerateInsituSessions()
	if err != nil {
		return errorf("%v", err)
	}
	if len(sessions) == 0 {
		return successResult("[]\n[*] No user logon sessions found (non-user sessions skipped)")
	}

	jsonBytes, err := json.MarshalIndent(sessions, "", "  ")
	if err != nil {
		return errorf("marshal: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] %d active logon session(s) found\n\n", len(sessions)))
	sb.WriteString(string(jsonBytes))
	return successResult(sb.String())
}

// enumerateInsituSessions returns the Phase 1 LSA-API session list. Used by
// both executeInsitu (text output) and executeInsituFull (cross-reference
// for Phase 2B walk validation). Sorted by logon type then username.
func enumerateInsituSessions() ([]insituSession, error) {
	// SeDebugPrivilege is not strictly required for LsaEnumerateLogonSessions
	// but improves completeness of results when running as admin.
	_ = insituEnableDebugPriv()

	var count uint32
	var luidPtr uintptr

	ret, _, _ := procLsaEnumerateLogonSessions.Call(
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&luidPtr)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("session enumeration failed: status=0x%x (%v)", ret, lsaNtStatusToError(ret))
	}
	if luidPtr != 0 {
		defer procLsaFreeReturnBuffer.Call(luidPtr)
	}
	if count == 0 || luidPtr == 0 {
		return nil, nil
	}

	// Copy LUIDs out of the LSA buffer before iterating (LsaGetLogonSessionData
	// call with each LUID must not overlap with the enumerated buffer).
	luids := make([]luidKD, count)
	for i := uint32(0); i < count; i++ {
		p := (*luidKD)(unsafe.Pointer(luidPtr + uintptr(i)*8))
		luids[i] = *p
	}

	var sessions []insituSession
	for _, luid := range luids {
		luidCopy := luid // avoid pointer-to-loop-variable

		var dataPtr uintptr
		ret2, _, _ := procLsaGetLogonSessionData.Call(
			uintptr(unsafe.Pointer(&luidCopy)),
			uintptr(unsafe.Pointer(&dataPtr)),
		)
		if ret2 != 0 || dataPtr == 0 {
			continue
		}

		data := (*insituLogonSessionData)(unsafe.Pointer(dataPtr))
		username := insituReadStr(data.UserName)

		// Skip sessions without a username (system/idle/service sessions)
		if username == "" {
			procLsaFreeReturnBuffer.Call(dataPtr)
			continue
		}

		s := insituSession{
			LogonID:   fmt.Sprintf("%d:%d", data.LogonIdHigh, data.LogonIdLow),
			Username:  username,
			Domain:    insituReadStr(data.LogonDomain),
			UPN:       insituReadStr(data.Upn),
			LogonType: insituLogonTypeName(data.LogonType),
			AuthPkg:   insituReadStr(data.AuthPkg),
			Session:   data.Session,
			LogonTime: insituFiletimeStr(data.LogonTime),
			DnsDomain: insituReadStr(data.DnsDomainName),
		}
		procLsaFreeReturnBuffer.Call(dataPtr)
		sessions = append(sessions, s)
	}

	// Sort: interactive first, then by logon type name, then username
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].LogonType != sessions[j].LogonType {
			return sessions[i].LogonType < sessions[j].LogonType
		}
		return strings.ToLower(sessions[i].Username) < strings.ToLower(sessions[j].Username)
	})
	return sessions, nil
}

// insituLUIDValue returns an insituSession's LogonID as a 64-bit value matching
// the in-memory LUID layout (LowPart in low 32 bits, HighPart in high 32 bits).
// LogonID was formatted as "%d:%d" → "<HighPart>:<LowPart>"; reconstructing the
// raw 8-byte LUID lets executeInsituFull search walked node buffers for it.
func insituLUIDValue(s insituSession) (uint64, bool) {
	var hi int32
	var lo uint32
	if _, err := fmt.Sscanf(s.LogonID, "%d:%d", &hi, &lo); err != nil {
		return 0, false
	}
	return (uint64(uint32(hi)) << 32) | uint64(lo), true
}

// insituReadStr reads a unicodeStringKL (LSA_UNICODE_STRING) whose Buffer
// pointer is valid in the current process address space (returned by LsaGetLogonSessionData).
func insituReadStr(s unicodeStringKL) string {
	if s.Length == 0 || s.Buffer == 0 {
		return ""
	}
	n := int(s.Length) / 2 // Length is in bytes; divide by 2 for uint16 count
	if n <= 0 {
		return ""
	}
	chars := unsafe.Slice((*uint16)(unsafe.Pointer(s.Buffer)), n)
	return windows.UTF16ToString(chars)
}

// insituLogonTypeName maps a SECURITY_LOGON_TYPE value to a readable string.
func insituLogonTypeName(t uint32) string {
	switch t {
	case 2:
		return "Interactive"
	case 3:
		return "Network"
	case 4:
		return "Batch"
	case 5:
		return "Service"
	case 7:
		return "Unlock"
	case 8:
		return "NetworkCleartext"
	case 9:
		return "NewCredentials"
	case 10:
		return "RemoteInteractive"
	case 11:
		return "CachedInteractive"
	case 12:
		return "CachedRemoteInteractive"
	case 13:
		return "CachedUnlock"
	default:
		return fmt.Sprintf("Unknown(%d)", t)
	}
}

// insituFiletimeStr converts a Windows FILETIME (100-ns intervals since 1601-01-01)
// stored as int64 to a UTC string. Returns "" for zero or out-of-range values.
func insituFiletimeStr(ft int64) string {
	if ft <= 0 {
		return ""
	}
	// Windows epoch: Jan 1, 1601; Unix epoch: Jan 1, 1970 (11644473600 seconds apart)
	const epochDelta = int64(11644473600)
	secs := ft/10000000 - epochDelta
	if secs < 0 || secs > 32503680000 { // reject values outside 1970-3000
		return ""
	}
	return time.Unix(secs, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// insituEnableDebugPriv enables SeDebugPrivilege on the current process token.
// Failure is non-fatal — most LSA session enumeration works without it.
func insituEnableDebugPriv() error {
	var token windows.Token
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}
	if err = windows.OpenProcessToken(proc, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()

	var luid windows.LUID
	if err = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeDebugPrivilege"), &luid); err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED},
		},
	}
	return windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
}
