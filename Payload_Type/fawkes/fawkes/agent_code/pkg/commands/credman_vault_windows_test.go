//go:build windows

package commands

import (
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestGuidToString_Format(t *testing.T) {
	g := windows.GUID{
		Data1: 0x4BF4C442,
		Data2: 0x9B8A,
		Data3: 0x41A0,
		Data4: [8]byte{0xB3, 0x80, 0xDD, 0x4A, 0x70, 0x4D, 0xDB, 0x28},
	}
	got := guidToString(&g)
	want := "{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}"
	if got != want {
		t.Errorf("guidToString = %q, want %q", got, want)
	}
}

func TestGuidToString_Nil(t *testing.T) {
	if got := guidToString(nil); got != "" {
		t.Errorf("guidToString(nil) = %q, want empty", got)
	}
}

func TestKnownVaultGUIDs_LookupHits(t *testing.T) {
	cases := map[string]string{
		"{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}": "Web Credentials",
		"{77BC582B-F0A6-4E15-4E80-61736B6F3B29}": "Windows Credentials",
		"{154E23E0-6F30-49CB-AB42-9B33D3E2B1CB}": "Passport",
	}
	for guid, want := range cases {
		if got := knownVaultGUIDs[guid]; got != want {
			t.Errorf("knownVaultGUIDs[%s] = %q, want %q", guid, got, want)
		}
	}
}

func TestKnownVaultGUIDs_NoLowercaseKeys(t *testing.T) {
	for k := range knownVaultGUIDs {
		if k != strings.ToUpper(k) {
			t.Errorf("knownVaultGUIDs key %q must be uppercase to match guidToString output", k)
		}
	}
}

func TestKnownVaultSchemas_NoLowercaseKeys(t *testing.T) {
	for k := range knownVaultSchemas {
		if k != strings.ToUpper(k) {
			t.Errorf("knownVaultSchemas key %q must be uppercase to match guidToString output", k)
		}
	}
}

func TestFiletimeString_Zero(t *testing.T) {
	if got := filetimeString(windows.Filetime{}); got != "" {
		t.Errorf("filetimeString(zero) = %q, want empty", got)
	}
}

func TestFiletimeString_OutOfRange(t *testing.T) {
	// FILETIME from year 1601 — secs would be negative.
	ft := windows.Filetime{LowDateTime: 1, HighDateTime: 0}
	if got := filetimeString(ft); got != "" {
		t.Errorf("filetimeString(very-small) = %q, want empty (out of range)", got)
	}
}

func TestFiletimeString_ValidEpoch(t *testing.T) {
	// 1970-01-01 00:00:00 UTC = 116444736000000000 in FILETIME (100-ns since 1601).
	const unixEpochAsFiletime = uint64(116444736000000000)
	ft := windows.Filetime{
		LowDateTime:  uint32(unixEpochAsFiletime & 0xFFFFFFFF),
		HighDateTime: uint32(unixEpochAsFiletime >> 32),
	}
	got := filetimeString(ft)
	if got != "1970-01-01 00:00:00 UTC" {
		t.Errorf("filetimeString(unix epoch) = %q, want 1970-01-01 00:00:00 UTC", got)
	}
}

func TestElementToString_Nil(t *testing.T) {
	val, present := elementToString(nil)
	if val != "" || present {
		t.Errorf("elementToString(nil) = (%q, %v), want (empty, false)", val, present)
	}
}

func TestElementToString_Boolean(t *testing.T) {
	cases := []struct {
		name string
		low  uint64
		want string
	}{
		{"true", 1, "true"},
		{"false", 0, "false"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			elem := &vaultItemElement{Type: vaultElemBoolean, UnionLow: c.low}
			got, present := elementToString(elem)
			if !present {
				t.Errorf("present = false, want true")
			}
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestElementToString_Integer(t *testing.T) {
	elem := &vaultItemElement{Type: vaultElemInteger, UnionLow: 42}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "42" {
		t.Errorf("got %q, want 42", got)
	}
}

func TestElementToString_String(t *testing.T) {
	utf16, err := windows.UTF16PtrFromString("hello")
	if err != nil {
		t.Fatalf("UTF16PtrFromString: %v", err)
	}
	elem := &vaultItemElement{
		Type:     vaultElemString,
		UnionLow: uint64(uintptr(unsafe.Pointer(utf16))),
	}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "hello" {
		t.Errorf("got %q, want hello", got)
	}
}

func TestElementToString_StringNullPointer(t *testing.T) {
	elem := &vaultItemElement{Type: vaultElemString, UnionLow: 0}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestElementToString_ByteArrayUTF16(t *testing.T) {
	// Encode "secret" as UTF-16LE.
	u16, err := windows.UTF16FromString("secret")
	if err != nil {
		t.Fatalf("UTF16FromString: %v", err)
	}
	// Strip trailing null for byte length math.
	bytesLen := uint32(len(u16) * 2)
	elem := &vaultItemElement{
		Type:      vaultElemByteArray,
		UnionLow:  uint64(bytesLen), // VAULT_BYTE_BUFFER.Length in low 32 bits
		UnionHigh: uint64(uintptr(unsafe.Pointer(&u16[0]))),
	}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "secret" {
		t.Errorf("got %q, want secret", got)
	}
}

func TestElementToString_ByteArrayEmpty(t *testing.T) {
	elem := &vaultItemElement{Type: vaultElemByteArray, UnionLow: 0, UnionHigh: 0}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestElementToString_ProtectedArrayBinary(t *testing.T) {
	// Non-printable bytes — should yield empty but present.
	binary := []byte{0x00, 0x01, 0xFE, 0xFF}
	elem := &vaultItemElement{
		Type:      vaultElemProtectedArray,
		UnionLow:  uint64(len(binary)),
		UnionHigh: uint64(uintptr(unsafe.Pointer(&binary[0]))),
	}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "" {
		t.Errorf("got %q, want empty for binary", got)
	}
}

func TestElementToString_Undefined(t *testing.T) {
	elem := &vaultItemElement{Type: vaultElemUndefined}
	got, present := elementToString(elem)
	if !present {
		t.Errorf("present = false, want true")
	}
	if got != "" {
		t.Errorf("got %q, want empty for undefined type", got)
	}
}

func TestParseVaultItem_Nil(t *testing.T) {
	got := parseVaultItem(nil)
	if got != (vaultParsedItem{}) {
		t.Errorf("parseVaultItem(nil) = %+v, want zero value", got)
	}
}

func TestParseVaultItem_KnownSchema(t *testing.T) {
	// Schema GUID = {3CCD5499-87A8-4B10-A215-608888DD3B55} (Web Password Credential)
	resourceUTF16, _ := windows.UTF16PtrFromString("https://example.com")
	identityUTF16, _ := windows.UTF16PtrFromString("alice@example.com")
	authUTF16, _ := windows.UTF16PtrFromString("hunter2")
	friendlyUTF16, _ := windows.UTF16PtrFromString("example login")

	resourceElem := &vaultItemElement{
		Type:     vaultElemString,
		UnionLow: uint64(uintptr(unsafe.Pointer(resourceUTF16))),
	}
	identityElem := &vaultItemElement{
		Type:     vaultElemString,
		UnionLow: uint64(uintptr(unsafe.Pointer(identityUTF16))),
	}
	authElem := &vaultItemElement{
		Type:     vaultElemString,
		UnionLow: uint64(uintptr(unsafe.Pointer(authUTF16))),
	}

	item := &vaultItemW8{
		SchemaID: windows.GUID{
			Data1: 0x3CCD5499,
			Data2: 0x87A8,
			Data3: 0x4B10,
			Data4: [8]byte{0xA2, 0x15, 0x60, 0x88, 0x88, 0xDD, 0x3B, 0x55},
		},
		FriendlyName:  friendlyUTF16,
		Resource:      resourceElem,
		Identity:      identityElem,
		Authenticator: authElem,
	}

	got := parseVaultItem(item)
	if got.SchemaName != "Web Password Credential" {
		t.Errorf("SchemaName = %q, want Web Password Credential", got.SchemaName)
	}
	if got.FriendlyName != "example login" {
		t.Errorf("FriendlyName = %q", got.FriendlyName)
	}
	if got.Resource != "https://example.com" {
		t.Errorf("Resource = %q", got.Resource)
	}
	if got.Identity != "alice@example.com" {
		t.Errorf("Identity = %q", got.Identity)
	}
	if got.Authenticator != "hunter2" {
		t.Errorf("Authenticator = %q", got.Authenticator)
	}
	if got.AuthenticatorRaw {
		t.Errorf("AuthenticatorRaw = true, want false (string was decoded)")
	}
}

func TestParseVaultItem_UnknownSchemaFallsBackToGUID(t *testing.T) {
	item := &vaultItemW8{
		SchemaID: windows.GUID{
			Data1: 0xDEADBEEF,
			Data2: 0x1234,
			Data3: 0x5678,
			Data4: [8]byte{0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44},
		},
	}
	got := parseVaultItem(item)
	want := "{DEADBEEF-1234-5678-9ABC-DEF011223344}"
	if got.SchemaName != want {
		t.Errorf("SchemaName = %q, want %q (raw GUID fallback)", got.SchemaName, want)
	}
}

func TestParseVaultItem_AuthenticatorRawWhenEmpty(t *testing.T) {
	// Authenticator element exists but Type=ProtectedArray with no data — should
	// surface AuthenticatorRaw=true so the caller can render the
	// "[protected, decryption requires interactive user context]" hint.
	emptyAuth := &vaultItemElement{Type: vaultElemProtectedArray, UnionLow: 0, UnionHigh: 0}
	item := &vaultItemW8{
		Authenticator: emptyAuth,
	}
	got := parseVaultItem(item)
	if got.Authenticator != "" {
		t.Errorf("Authenticator = %q, want empty", got.Authenticator)
	}
	if !got.AuthenticatorRaw {
		t.Errorf("AuthenticatorRaw = false, want true (element present but no cleartext)")
	}
}

func TestVaultItemW8_StructSize(t *testing.T) {
	// Lock in the on-wire struct size at 80 bytes (Windows 8+ x64).
	// If this fails, we got the field offsets wrong and ALL pointer arithmetic
	// over the API-allocated array will read garbage.
	if got := unsafe.Sizeof(vaultItemW8{}); got != sizeofVaultItemW8 {
		t.Errorf("sizeof(vaultItemW8) = %d, want %d", got, sizeofVaultItemW8)
	}
}

func TestVaultItemElement_StructSize(t *testing.T) {
	// VAULT_ITEM_ELEMENT is 24 bytes on x64.
	if got := unsafe.Sizeof(vaultItemElement{}); got != 24 {
		t.Errorf("sizeof(vaultItemElement) = %d, want 24", got)
	}
}

func TestVaultByteBuffer_StructSize(t *testing.T) {
	// VAULT_BYTE_BUFFER is 16 bytes on x64.
	if got := unsafe.Sizeof(vaultByteBuffer{}); got != 16 {
		t.Errorf("sizeof(vaultByteBuffer) = %d, want 16", got)
	}
}
