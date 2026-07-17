package commands

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// stampMov48_8B_0D writes a 7-byte `48 8B 0D ?? ?? ?? ??` mov instruction at
// buf[at:at+7], encoding the supplied disp32. Used by the cross-platform
// sigscan tests to plant synthetic IV / h3DesKey / hAesKey loads inside a
// fake lsasrv.dll image without depending on a real Windows binary.
func stampMov48_8B_0D(buf []byte, at int, disp int32) {
	buf[at+0] = 0x48
	buf[at+1] = 0x8B
	buf[at+2] = 0x0D
	binary.LittleEndian.PutUint32(buf[at+3:at+7], uint32(disp))
}

// stampLsaInitProtectedMemoryPattern writes the 12-byte sigscan pattern at
// buf[at:at+12]. The last 3 bytes (`48 8B 0D`) are also the START of the IV
// mov instruction; callers should NOT additionally stamp an IV mov at the
// pattern boundary — instead, write the disp32 four bytes after the pattern
// (`stampMov48_8B_0D(buf, at+9, ivDisp)` works because `48 8B 0D` is already
// in place).
func stampLsaInitProtectedMemoryPattern(buf []byte, at int) {
	pattern := []byte{0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8B, 0x4D, 0xD8, 0x48, 0x8B, 0x0D}
	copy(buf[at:at+12], pattern)
}

// makeFakeLsasrvImage builds a synthetic lsasrv.dll buffer with the
// LsaInitializeProtectedMemory pattern at `patternOff`, plus the three
// RIP-relative MOV instructions positioned at the layout offsets. Each disp32
// targets a distinct, in-buffer destination so the test can verify the
// resolved global addresses.
//
// The buffer is sized large enough to hold the negative-offset h3DesKey/hAesKey
// movs (which sit BEFORE the pattern by ~75 bytes) plus all three RIP-relative
// targets (which we choose to land later in the buffer).
func makeFakeLsasrvImage(t *testing.T, layout lsaCryptoLayout, patternOff int, ivTargetOff, desTargetOff, aesTargetOff int) []byte {
	t.Helper()
	bufSize := 0x1000
	buf := make([]byte, bufSize)

	// Pattern (which embeds the IV mov's first 3 bytes at +9).
	stampLsaInitProtectedMemoryPattern(buf, patternOff)

	// IV mov: the first 3 bytes (`48 8B 0D`) are already laid down by the
	// pattern. We just need to write the disp32 at +12.
	ivInstrStart := patternOff + layout.IVMovStart
	ivInstrEnd := ivInstrStart + layout.MovInstrLen
	disp := int32(ivTargetOff - ivInstrEnd)
	binary.LittleEndian.PutUint32(buf[ivInstrStart+layout.MovDispOffset:ivInstrStart+layout.MovDispOffset+4], uint32(disp))

	// h3DesKey mov: stamp the full 7-byte instruction at the negative offset.
	desInstrStart := patternOff + layout.H3DesKeyMovStart
	desInstrEnd := desInstrStart + layout.MovInstrLen
	desDisp := int32(desTargetOff - desInstrEnd)
	stampMov48_8B_0D(buf, desInstrStart, desDisp)

	// hAesKey mov: same pattern, different negative offset.
	aesInstrStart := patternOff + layout.HAesKeyMovStart
	aesInstrEnd := aesInstrStart + layout.MovInstrLen
	aesDisp := int32(aesTargetOff - aesInstrEnd)
	stampMov48_8B_0D(buf, aesInstrStart, aesDisp)

	return buf
}

func TestFindLsaCryptoGlobals_HitWithCalibratedOffsets(t *testing.T) {
	const (
		patternOff   = 0x400
		ivTargetOff  = 0x800
		desTargetOff = 0x900
		aesTargetOff = 0xA00
		base         = uintptr(0x180000000)
	)
	buf := makeFakeLsasrvImage(t, LsaCryptoWin10W8, patternOff, ivTargetOff, desTargetOff, aesTargetOff)

	g, err := findLsaCryptoGlobals(buf, base, LsaCryptoWin10W8)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g.IVAddr != base+uintptr(ivTargetOff) {
		t.Errorf("IVAddr = 0x%X, want 0x%X", g.IVAddr, base+uintptr(ivTargetOff))
	}
	if g.H3DesKeyAddr != base+uintptr(desTargetOff) {
		t.Errorf("H3DesKeyAddr = 0x%X, want 0x%X", g.H3DesKeyAddr, base+uintptr(desTargetOff))
	}
	if g.HAesKeyAddr != base+uintptr(aesTargetOff) {
		t.Errorf("HAesKeyAddr = 0x%X, want 0x%X", g.HAesKeyAddr, base+uintptr(aesTargetOff))
	}
}

func TestFindLsaCryptoGlobals_SignatureNotFound(t *testing.T) {
	buf := make([]byte, 0x1000) // all zeros; no pattern
	_, err := findLsaCryptoGlobals(buf, 0x10000000, LsaCryptoWin10W8)
	if err == nil || !strings.Contains(err.Error(), "signature") || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected signature-not-found error, got %v", err)
	}
}

func TestFindLsaCryptoGlobals_NoKeysInSmallBuffer(t *testing.T) {
	// Pattern found but no valid key globals in a tiny buffer.
	const (
		patternOff = 0x40
		bufSize    = 0x80
	)
	buf := make([]byte, bufSize)
	stampLsaInitProtectedMemoryPattern(buf, patternOff)

	_, err := findLsaCryptoGlobals(buf, 0, LsaCryptoWin10W8)
	if err == nil {
		t.Errorf("expected error when no key globals found, got nil")
	}
}

func TestFindLsaCryptoGlobals_BadPattern(t *testing.T) {
	bogus := lsaCryptoLayout{
		Name:             "bogus",
		Sign:             "ZZ ZZ", // invalid hex token
		IVMovStart:       0,
		H3DesKeyMovStart: 0,
		HAesKeyMovStart:  0,
		MovInstrLen:      7,
		MovDispOffset:    3,
	}
	_, err := findLsaCryptoGlobals(make([]byte, 0x100), 0, bogus)
	if err == nil || !strings.Contains(err.Error(), "internal: bad crypto init signature") {
		t.Errorf("expected bad-pattern error, got %v", err)
	}
}

// stampBcryptHandleKey lays down a 32-byte KIWI_BCRYPT_HANDLE_KEY at buf[0:].
func stampBcryptHandleKey(buf []byte, size, tag uint32, hAlgo, key, unk0 uintptr) {
	binary.LittleEndian.PutUint32(buf[0:4], size)
	binary.LittleEndian.PutUint32(buf[4:8], tag)
	binary.LittleEndian.PutUint64(buf[8:16], uint64(hAlgo))
	binary.LittleEndian.PutUint64(buf[16:24], uint64(key))
	binary.LittleEndian.PutUint64(buf[24:32], uint64(unk0))
}

// stampBcryptKey81 lays down the 0x40-byte KIWI_BCRYPT_KEY81 header followed
// by `cbSecret` as a 4-byte little-endian DWORD. The trailing key bytes are
// returned separately for the caller to register at addr+0x44.
func stampBcryptKey81(size, tag, type_, bits, cbSecret uint32) []byte {
	hdr := make([]byte, bcryptHardKeyDataOff)
	binary.LittleEndian.PutUint32(hdr[0:4], size)
	binary.LittleEndian.PutUint32(hdr[4:8], tag)
	binary.LittleEndian.PutUint32(hdr[8:12], type_)
	binary.LittleEndian.PutUint32(hdr[0x18:0x1C], bits)
	binary.LittleEndian.PutUint32(hdr[bcryptHardKeyCbSecretOff:bcryptHardKeyCbSecretOff+4], cbSecret)
	return hdr
}

func TestReadBcryptHandleKey_TagValid(t *testing.T) {
	const handleAddr = uintptr(0x10000)
	r := newBufferReader()
	hdr := make([]byte, bcryptHandleKeySize)
	stampBcryptHandleKey(hdr, 0x80, bcryptHandleKeyTagWant, 0xA1A1A1A1, 0x20000, 0xB2B2B2B2)
	r.put(handleAddr, hdr)

	hk, err := readBcryptHandleKey(r, handleAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hk.TagValid {
		t.Errorf("TagValid = false, want true (tag=0x%X)", hk.Tag)
	}
	if hk.KeyAddr != 0x20000 {
		t.Errorf("KeyAddr = 0x%X, want 0x20000", hk.KeyAddr)
	}
	if hk.Size != 0x80 {
		t.Errorf("Size = %d, want 0x80", hk.Size)
	}
}

func TestReadBcryptHandleKey_TagInvalid_StillReturnsFields(t *testing.T) {
	const handleAddr = uintptr(0x10000)
	r := newBufferReader()
	hdr := make([]byte, bcryptHandleKeySize)
	stampBcryptHandleKey(hdr, 0x80, 0xDEADBEEF, 0, 0x20000, 0)
	r.put(handleAddr, hdr)

	hk, err := readBcryptHandleKey(r, handleAddr)
	if err != nil {
		t.Fatalf("unexpected error (tag mismatch should not be fatal): %v", err)
	}
	if hk.TagValid {
		t.Errorf("TagValid = true, want false (tag=0x%X)", hk.Tag)
	}
	if hk.KeyAddr != 0x20000 {
		t.Errorf("KeyAddr should still be parsed even on tag mismatch, got 0x%X", hk.KeyAddr)
	}
}

func TestReadBcryptHandleKey_ZeroAddr(t *testing.T) {
	_, err := readBcryptHandleKey(newBufferReader(), 0)
	if err == nil || !strings.Contains(err.Error(), "zero KIWI_BCRYPT_HANDLE_KEY address") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadBcryptHandleKey_NilReader(t *testing.T) {
	_, err := readBcryptHandleKey(nil, 0x100)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestReadBcryptHandleKey_ReadFailure(t *testing.T) {
	_, err := readBcryptHandleKey(newBufferReader(), 0xDEAD)
	if err == nil || !strings.Contains(err.Error(), "read KIWI_BCRYPT_HANDLE_KEY") {
		t.Errorf("expected read-failure error, got %v", err)
	}
}

func TestReadBcryptKey81_AesKey32Bytes(t *testing.T) {
	const keyAddr = uintptr(0x20000)
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(0x10 + i)
	}
	r := newBufferReader()
	r.put(keyAddr, stampBcryptKey81(0xC0, bcryptKey81TagWant, 0x00 /*type*/, 256 /*bits*/, 32 /*cbSecret*/))
	r.put(keyAddr+uintptr(bcryptHardKeyDataOff), keyBytes)

	k, err := readBcryptKey81(r, keyAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !k.TagValid {
		t.Errorf("TagValid = false, want true (tag=0x%X)", k.Tag)
	}
	if k.CbSecret != 32 {
		t.Errorf("CbSecret = %d, want 32", k.CbSecret)
	}
	if k.Bits != 256 {
		t.Errorf("Bits = %d, want 256", k.Bits)
	}
	if !bytes.Equal(k.Key, keyBytes) {
		t.Errorf("Key = %X, want %X", k.Key, keyBytes)
	}
}

func TestReadBcryptKey81_3DesKey24Bytes(t *testing.T) {
	const keyAddr = uintptr(0x30000)
	keyBytes := make([]byte, 24)
	for i := range keyBytes {
		keyBytes[i] = byte(0xAA - i)
	}
	r := newBufferReader()
	r.put(keyAddr, stampBcryptKey81(0xB0, bcryptKey81TagWant, 0, 192, 24))
	r.put(keyAddr+uintptr(bcryptHardKeyDataOff), keyBytes)

	k, err := readBcryptKey81(r, keyAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.CbSecret != 24 || !bytes.Equal(k.Key, keyBytes) {
		t.Errorf("CbSecret=%d Key=%X; want 24 / %X", k.CbSecret, k.Key, keyBytes)
	}
}

func TestReadBcryptKey81_TagInvalid_StillReturnsFields(t *testing.T) {
	const keyAddr = uintptr(0x40000)
	keyBytes := []byte{1, 2, 3, 4}
	r := newBufferReader()
	r.put(keyAddr, stampBcryptKey81(0x60, 0xCAFEBABE, 0, 32, 4))
	r.put(keyAddr+uintptr(bcryptHardKeyDataOff), keyBytes)

	k, err := readBcryptKey81(r, keyAddr)
	if err != nil {
		t.Fatalf("unexpected error (tag mismatch should not be fatal): %v", err)
	}
	if k.TagValid {
		t.Errorf("TagValid = true, want false (tag=0x%X)", k.Tag)
	}
	if !bytes.Equal(k.Key, keyBytes) {
		t.Errorf("Key bytes should still be returned on tag mismatch, got %X", k.Key)
	}
}

func TestReadBcryptKey81_CbSecretZero_NoTrailingRead(t *testing.T) {
	const keyAddr = uintptr(0x50000)
	r := newBufferReader()
	// Only register the header — no trailing data page. The function must
	// short-circuit when CbSecret==0 instead of attempting a zero-length read.
	r.put(keyAddr, stampBcryptKey81(0x40, bcryptKey81TagWant, 0, 0, 0))

	k, err := readBcryptKey81(r, keyAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if k.CbSecret != 0 {
		t.Errorf("CbSecret = %d, want 0", k.CbSecret)
	}
	if k.Key != nil {
		t.Errorf("Key should be nil for cbSecret=0, got %X", k.Key)
	}
}

func TestReadBcryptKey81_CbSecretExceedsSanityCap(t *testing.T) {
	const keyAddr = uintptr(0x60000)
	r := newBufferReader()
	r.put(keyAddr, stampBcryptKey81(0x40, bcryptKey81TagWant, 0, 0, 99999))

	k, err := readBcryptKey81(r, keyAddr)
	if err == nil || !strings.Contains(err.Error(), "sanity cap") {
		t.Errorf("expected sanity-cap error, got %v", err)
	}
	// Header fields should still be returned for diagnostics.
	if k.CbSecret != 99999 {
		t.Errorf("CbSecret should be reported even on sanity-cap rejection, got %d", k.CbSecret)
	}
}

func TestReadBcryptKey81_KeyDataReadFails(t *testing.T) {
	const keyAddr = uintptr(0x70000)
	r := newBufferReader()
	r.put(keyAddr, stampBcryptKey81(0x60, bcryptKey81TagWant, 0, 256, 32))
	// trailing key page intentionally NOT registered → second read fails

	_, err := readBcryptKey81(r, keyAddr)
	if err == nil || !strings.Contains(err.Error(), "read KIWI_HARD_KEY.data") {
		t.Errorf("expected key-data read failure, got %v", err)
	}
}

func TestReadBcryptKey81_HeaderShortRead(t *testing.T) {
	_, err := readBcryptKey81(newBufferReader(), 0xDEAD)
	if err == nil || !strings.Contains(err.Error(), "read KIWI_BCRYPT_KEY81 header") {
		t.Errorf("expected header read-failure error, got %v", err)
	}
}

func TestReadBcryptKey81_ZeroAddr(t *testing.T) {
	_, err := readBcryptKey81(newBufferReader(), 0)
	if err == nil || !strings.Contains(err.Error(), "zero KIWI_BCRYPT_KEY81 address") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadBcryptKey81_NilReader(t *testing.T) {
	_, err := readBcryptKey81(nil, 0x100)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestReadBcryptKeyMaterial_FullChain(t *testing.T) {
	const (
		globalAddr = uintptr(0x10000)
		handleAddr = uintptr(0x20000)
		keyAddr    = uintptr(0x30000)
	)
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	r := newBufferReader()
	// Step 1: global → handle pointer.
	ptrPage := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptrPage, uint64(handleAddr))
	r.put(globalAddr, ptrPage)
	// Step 2: handle struct.
	hdr := make([]byte, bcryptHandleKeySize)
	stampBcryptHandleKey(hdr, 0x80, bcryptHandleKeyTagWant, 0, keyAddr, 0)
	r.put(handleAddr, hdr)
	// Step 3: KIWI_BCRYPT_KEY81 + key bytes.
	r.put(keyAddr, stampBcryptKey81(0xC0, bcryptKey81TagWant, 0, 256, 32))
	r.put(keyAddr+uintptr(bcryptHardKeyDataOff), keyBytes)

	hk, k, err := readBcryptKeyMaterial(r, globalAddr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hk.Address != handleAddr {
		t.Errorf("hk.Address = 0x%X, want 0x%X", hk.Address, handleAddr)
	}
	if k.Address != keyAddr {
		t.Errorf("k.Address = 0x%X, want 0x%X", k.Address, keyAddr)
	}
	if !bytes.Equal(k.Key, keyBytes) {
		t.Errorf("Key bytes mismatch: got %X, want %X", k.Key, keyBytes)
	}
}

func TestReadBcryptKeyMaterial_GlobalHoldsNull(t *testing.T) {
	const globalAddr = uintptr(0x10000)
	r := newBufferReader()
	r.put(globalAddr, make([]byte, 8)) // 8 zero bytes → NULL handle pointer

	_, _, err := readBcryptKeyMaterial(r, globalAddr)
	if err == nil || !strings.Contains(err.Error(), "holds NULL") {
		t.Errorf("expected NULL-pointer error, got %v", err)
	}
}

func TestReadBcryptKeyMaterial_HandleHasNullKey(t *testing.T) {
	const (
		globalAddr = uintptr(0x10000)
		handleAddr = uintptr(0x20000)
	)
	r := newBufferReader()
	ptrPage := make([]byte, 8)
	binary.LittleEndian.PutUint64(ptrPage, uint64(handleAddr))
	r.put(globalAddr, ptrPage)
	hdr := make([]byte, bcryptHandleKeySize)
	stampBcryptHandleKey(hdr, 0x80, bcryptHandleKeyTagWant, 0, 0, 0) // KeyAddr=0
	r.put(handleAddr, hdr)

	_, _, err := readBcryptKeyMaterial(r, globalAddr)
	if err == nil || !strings.Contains(err.Error(), "NULL key pointer") {
		t.Errorf("expected null-key-pointer error, got %v", err)
	}
}

func TestReadBcryptKeyMaterial_GlobalReadFails(t *testing.T) {
	_, _, err := readBcryptKeyMaterial(newBufferReader(), 0xDEAD)
	if err == nil || !strings.Contains(err.Error(), "read crypto key global") {
		t.Errorf("expected global read-failure error, got %v", err)
	}
}

func TestReadBcryptKeyMaterial_ZeroAddr(t *testing.T) {
	_, _, err := readBcryptKeyMaterial(newBufferReader(), 0)
	if err == nil || !strings.Contains(err.Error(), "zero global address") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadBcryptKeyMaterial_NilReader(t *testing.T) {
	_, _, err := readBcryptKeyMaterial(nil, 0x100)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestReadIVBytes_RoundTrip(t *testing.T) {
	const ivAddr = uintptr(0x50000)
	want := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}
	r := newBufferReader()
	r.put(ivAddr, want)

	got, err := readIVBytes(r, ivAddr, 16)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("IV = %X, want %X", got, want)
	}
}

func TestReadIVBytes_ZeroAddr(t *testing.T) {
	_, err := readIVBytes(newBufferReader(), 0, 16)
	if err == nil || !strings.Contains(err.Error(), "zero IV address") {
		t.Errorf("expected zero-addr error, got %v", err)
	}
}

func TestReadIVBytes_NilReader(t *testing.T) {
	_, err := readIVBytes(nil, 0x100, 16)
	if err == nil || !strings.Contains(err.Error(), "nil lsassReader") {
		t.Errorf("expected nil-reader error, got %v", err)
	}
}

func TestReadIVBytes_ImplausibleSize(t *testing.T) {
	for _, size := range []uint32{0, 65, 1024} {
		_, err := readIVBytes(newBufferReader(), 0x100, size)
		if err == nil || !strings.Contains(err.Error(), "implausible IV size") {
			t.Errorf("size=%d: expected implausible-size error, got %v", size, err)
		}
	}
}

func TestReadIVBytes_ReadFailure(t *testing.T) {
	_, err := readIVBytes(newBufferReader(), 0xDEAD, 16)
	if err == nil || !strings.Contains(err.Error(), "read IV") {
		t.Errorf("expected read-failure error, got %v", err)
	}
}
