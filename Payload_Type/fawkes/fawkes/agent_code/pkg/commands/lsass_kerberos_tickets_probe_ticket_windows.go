//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"fmt"
	"time"
)

// probeKerbTicketLayout reads raw ticket bytes and scans for known patterns
// to auto-detect the correct field offsets within KIWI_KERBEROS_INTERNAL_TICKET.
// Server 2019+ may add extra fields before ServiceName, shifting all offsets.
//
// Strategy: find consecutive LSA_UNICODE_STRING fields (DomainName, TargetDomainName,
// Description, AltTargetDomainName) by scanning for valid patterns. The offset of
// the first one gives us DomainNameOff; from there we compute the shift.
func probeKerbTicketLayout(r lsassReader, ticketBase uintptr, base kerbTicketLayout) (kerbTicketLayout, string) {
	probeSize := uint32(0x200)
	raw, err := r.Read(ticketBase, probeSize)
	if err != nil || len(raw) < 0x100 {
		return base, ""
	}

	return probeKerbTicketLayoutFromBytes(r, raw, base)
}

// probeKerbTicketLayoutFromBytes is the core probe logic, separated for testability.
func probeKerbTicketLayoutFromBytes(r lsassReader, raw []byte, base kerbTicketLayout) (kerbTicketLayout, string) {
	type uniCandidate struct {
		off    int
		length uint16
		bufPtr uintptr
	}

	// Pass 1: find all plausible LSA_UNICODE_STRING patterns in the buffer.
	var candidates []uniCandidate
	for off := 0x18; off+16 <= len(raw); off += 8 {
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

	// Pass 2: find a run of 3+ consecutive LSA_UNICODE_STRING at 16-byte spacing.
	// This corresponds to DomainName, TargetDomainName, Description, AltTargetDomainName.
	for i := 0; i+2 < len(candidates); i++ {
		a, b, c := candidates[i], candidates[i+1], candidates[i+2]
		if b.off-a.off != 16 || c.off-b.off != 16 {
			continue
		}

		// Validate at least one of them resolves to a readable string (the realm).
		if r != nil {
			str, sErr := readRemoteLSAUnicodeString(r, raw[a.off:a.off+16])
			if sErr != nil || str == "" {
				str, sErr = readRemoteLSAUnicodeString(r, raw[b.off:b.off+16])
				if sErr != nil || str == "" {
					continue
				}
			}
		}

		// a.off is the probed DomainNameOff
		shift := a.off - base.DomainNameOff
		if shift == 0 {
			return base, fmt.Sprintf("ticket probe: no shift needed (DomainName at 0x%02X)", a.off)
		}

		adjusted := adjustTicketLayout(base, shift)
		return adjusted, fmt.Sprintf("ticket probe: shift=%+d (DomainName at 0x%02X)", shift, a.off)
	}

	// Pass 3: fallback — look for FILETIME patterns (valid 2020-2030 range)
	// to anchor the StartTime/EndTime fields.
	const (
		ft2020 = uint64(132224352000000000) // 2020-01-01
		ft2030 = uint64(133799616000000000) // 2030-01-01
	)
	for off := 0x80; off+24 <= len(raw); off += 8 {
		v1 := binary.LittleEndian.Uint64(raw[off : off+8])
		v2 := binary.LittleEndian.Uint64(raw[off+8 : off+16])
		if v1 >= ft2020 && v1 <= ft2030 && v2 >= ft2020 && v2 <= ft2030 {
			// Consecutive FILETIMEs found — this is StartTime/EndTime
			t1 := kerbFiletimeToTime(v1)
			t2 := kerbFiletimeToTime(v2)
			if t2.After(t1) && t2.Sub(t1) < 365*24*time.Hour {
				shift := off - base.StartTimeOff
				if shift == 0 {
					return base, fmt.Sprintf("ticket probe via FILETIME: no shift (StartTime at 0x%02X)", off)
				}
				adjusted := adjustTicketLayout(base, shift)
				return adjusted, fmt.Sprintf("ticket probe via FILETIME: shift=%+d (StartTime at 0x%02X → %s)", shift, off, t1.Format("2006-01-02"))
			}
		}
	}

	return base, ""
}

func adjustTicketLayout(base kerbTicketLayout, shift int) kerbTicketLayout {
	adjusted := base
	adjusted.Name = fmt.Sprintf("%s_probed_%+d", base.Name, shift)
	adjusted.ServiceNameOff += shift
	adjusted.TargetNameOff += shift
	adjusted.DomainNameOff += shift
	adjusted.TargetDomainOff += shift
	adjusted.AltTargetDomOff += shift
	adjusted.ClientNameOff += shift
	adjusted.TicketFlagsOff += shift
	adjusted.KeyTypeOff += shift
	adjusted.KeyOff += shift
	adjusted.StartTimeOff += shift
	adjusted.EndTimeOff += shift
	adjusted.RenewUntilOff += shift
	adjusted.TicketEncTypeOff += shift
	adjusted.TicketKvnoOff += shift
	adjusted.TicketOff += shift
	adjusted.NodeReadSize += shift
	return adjusted
}

// ticketDiagHexDump returns a diagnostic hex dump of the first N bytes
// of a ticket entry, for debugging struct layout mismatches.
func ticketDiagHexDump(raw []byte, ticketBase uintptr, layout kerbTicketLayout) string {
	var out string
	out += fmt.Sprintf("[TICKET DIAG] Ticket at 0x%X (%d bytes)\n", ticketBase, len(raw))
	out += fmt.Sprintf("[TICKET DIAG] Layout: %s (ServiceName=%#x, Domain=%#x, Flags=%#x, Start=%#x, Ticket=%#x)\n",
		layout.Name, layout.ServiceNameOff, layout.DomainNameOff, layout.TicketFlagsOff, layout.StartTimeOff, layout.TicketOff)

	maxDump := 0x180
	if maxDump > len(raw) {
		maxDump = len(raw)
	}
	for off := 0; off < maxDump; off += 16 {
		end := off + 16
		if end > maxDump {
			end = maxDump
		}
		hex := ""
		ascii := ""
		for j := off; j < end; j++ {
			hex += fmt.Sprintf("%02X ", raw[j])
			if raw[j] >= 0x20 && raw[j] <= 0x7E {
				ascii += string(raw[j])
			} else {
				ascii += "."
			}
		}
		out += fmt.Sprintf("[TICKET DIAG] +%04X: %-48s %s\n", off, hex, ascii)
	}
	return out
}
