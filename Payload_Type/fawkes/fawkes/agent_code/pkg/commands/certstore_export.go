//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

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
