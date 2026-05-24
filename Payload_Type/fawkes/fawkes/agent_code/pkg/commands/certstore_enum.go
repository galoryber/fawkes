//go:build windows
// +build windows

package commands

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
		return nil, fmt.Errorf("CertOpenStore failed: %w", sysErr)
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
