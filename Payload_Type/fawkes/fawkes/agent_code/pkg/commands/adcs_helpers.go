package commands

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// adcsResolveEKU converts an OID to a human-readable name
func adcsResolveEKU(oid string) string {
	names := map[string]string{
		oidClientAuth:              "Client Authentication",
		oidServerAuth:              "Server Authentication",
		oidPKINITClient:            "PKINIT Client Auth",
		oidSmartCardLogon:          "Smart Card Logon",
		oidAnyPurpose:              "Any Purpose",
		oidCertRequestAgent:        "Certificate Request Agent",
		"1.3.6.1.5.5.7.3.4":        "Secure Email",
		"1.3.6.1.5.5.7.3.8":        "Time Stamping",
		"1.3.6.1.4.1.311.10.3.4":   "EFS Recovery Agent",
		"1.3.6.1.4.1.311.10.3.12":  "Document Signing",
		"1.3.6.1.4.1.311.54.1.2":   "Remote Desktop Auth",
		"1.3.6.1.4.1.311.10.3.4.1": "EFS Data Recovery",
		"1.3.6.1.4.1.311.21.5":     "CA Encryption Certificate",
		"1.3.6.1.4.1.311.10.3.1":   "CTL Signing",
		"1.3.6.1.5.5.7.3.9":        "OCSP Signing",
	}
	if name, ok := names[oid]; ok {
		return name
	}
	return oid
}

func adcsHasAuthEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true // no EKU = any purpose
	}
	for _, eku := range ekus {
		switch eku {
		case oidClientAuth, oidPKINITClient, oidSmartCardLogon, oidAnyPurpose:
			return true
		}
	}
	return false
}

func adcsHasAnyPurposeEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == oidAnyPurpose {
			return true
		}
	}
	return false
}

func adcsHasCertRequestAgentEKU(ekus []string) bool {
	for _, eku := range ekus {
		if eku == oidCertRequestAgent {
			return true
		}
	}
	return false
}

// --- Security Descriptor Parsing ---

type sdACE struct {
	sid        string
	mask       uint32
	objectGUID []byte
}

// adcsParseEnrollmentPerms extracts SIDs with Certificate-Enrollment or GenericAll rights
func adcsParseEnrollmentPerms(sd []byte) []string {
	aces := adcsParseSD(sd)
	sids := make(map[string]bool)

	for _, ace := range aces {
		if ace.mask&adsGenericAll != 0 {
			sids[ace.sid] = true
			continue
		}
		if ace.mask&adsRightDSControlAccess != 0 {
			if len(ace.objectGUID) == 0 {
				sids[ace.sid] = true // all extended rights
			} else if adcsMatchGUID(ace.objectGUID, enrollmentGUID) {
				sids[ace.sid] = true
			}
		}
	}

	result := make([]string, 0, len(sids))
	for sid := range sids {
		result = append(result, sid)
	}
	return result
}

// adcsParseWritePerms extracts SIDs with write access to the template
func adcsParseWritePerms(sd []byte) []string {
	aces := adcsParseSD(sd)
	sids := make(map[string]bool)

	for _, ace := range aces {
		if ace.mask&adsGenericAll != 0 || ace.mask&adsWriteDACL != 0 || ace.mask&adsWriteOwner != 0 {
			sids[ace.sid] = true
		}
	}

	result := make([]string, 0, len(sids))
	for sid := range sids {
		result = append(result, sid)
	}
	return result
}

// adcsParseSD parses a binary SECURITY_DESCRIPTOR_RELATIVE to extract DACL ACEs
func adcsParseSD(sd []byte) []sdACE {
	if len(sd) < 20 {
		return nil
	}

	// SECURITY_DESCRIPTOR_RELATIVE header (20 bytes):
	// [0]  Revision (1), [1] Sbz1 (1), [2:4] Control (2 LE)
	// [4:8] OffsetOwner, [8:12] OffsetGroup, [12:16] OffsetSacl, [16:20] OffsetDacl

	daclOffset := int(binary.LittleEndian.Uint32(sd[16:20]))
	if daclOffset == 0 || daclOffset >= len(sd) {
		return nil
	}

	return adcsParseACL(sd, daclOffset)
}

// adcsParseACL parses an ACL at the given offset within the SD buffer
func adcsParseACL(sd []byte, offset int) []sdACE {
	if offset+8 > len(sd) {
		return nil
	}

	// ACL header (8 bytes):
	// [0] Revision, [1] Sbz1, [2:4] AclSize, [4:6] AceCount, [6:8] Sbz2

	aceCount := int(binary.LittleEndian.Uint16(sd[offset+4 : offset+6]))
	aces := make([]sdACE, 0, aceCount)
	pos := offset + 8

	for i := 0; i < aceCount && pos+4 <= len(sd); i++ {
		aceType := sd[pos]
		aceSize := int(binary.LittleEndian.Uint16(sd[pos+2 : pos+4]))

		if aceSize < 4 || pos+aceSize > len(sd) {
			break
		}

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE_TYPE
			if pos+8 <= len(sd) {
				mask := binary.LittleEndian.Uint32(sd[pos+4 : pos+8])
				sid := adcsParseSID(sd[pos+8 : pos+aceSize])
				if sid != "" {
					aces = append(aces, sdACE{sid: sid, mask: mask})
				}
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE_TYPE
			if pos+12 <= len(sd) {
				mask := binary.LittleEndian.Uint32(sd[pos+4 : pos+8])
				flags := binary.LittleEndian.Uint32(sd[pos+8 : pos+12])

				sidStart := pos + 12
				var objectGUID []byte

				if flags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
					if sidStart+16 <= len(sd) {
						objectGUID = make([]byte, 16)
						copy(objectGUID, sd[sidStart:sidStart+16])
						sidStart += 16
					}
				}
				if flags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
					sidStart += 16
				}

				if sidStart < pos+aceSize {
					sid := adcsParseSID(sd[sidStart : pos+aceSize])
					if sid != "" {
						aces = append(aces, sdACE{sid: sid, mask: mask, objectGUID: objectGUID})
					}
				}
			}
		}

		pos += aceSize
	}

	return aces
}

// adcsParseSID converts binary SID to string format S-R-I-S-S-S...
func adcsParseSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subCount := int(b[1])

	if len(b) < 8+subCount*4 {
		return ""
	}

	// Identifier authority (6 bytes, big-endian)
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	parts := make([]string, 0, 2+subCount)
	parts = append(parts, fmt.Sprintf("S-%d-%d", revision, authority))

	for i := 0; i < subCount; i++ {
		off := 8 + i*4
		sub := binary.LittleEndian.Uint32(b[off : off+4])
		parts = append(parts, strconv.FormatUint(uint64(sub), 10))
	}

	return strings.Join(parts, "-")
}

// guidToBytes converts "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to 16-byte mixed-endian binary
func guidToBytes(s string) []byte {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return nil
	}

	b := make([]byte, 16)

	// Data1 (4 bytes LE)
	d1, _ := strconv.ParseUint(parts[0], 16, 32)
	binary.LittleEndian.PutUint32(b[0:4], uint32(d1))

	// Data2 (2 bytes LE)
	d2, _ := strconv.ParseUint(parts[1], 16, 16)
	binary.LittleEndian.PutUint16(b[4:6], uint16(d2))

	// Data3 (2 bytes LE)
	d3, _ := strconv.ParseUint(parts[2], 16, 16)
	binary.LittleEndian.PutUint16(b[6:8], uint16(d3))

	// Data4 (8 bytes BE) — parts[3] + parts[4] concatenated
	d4str := parts[3] + parts[4]
	for i := 0; i < 8 && i*2+1 < len(d4str); i++ {
		val, _ := strconv.ParseUint(d4str[i*2:i*2+2], 16, 8)
		b[8+i] = byte(val)
	}

	return b
}

// adcsMatchGUID compares two 16-byte GUID buffers
func adcsMatchGUID(a, b []byte) bool {
	if len(a) != 16 || len(b) != 16 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// adcsFilterLowPriv filters SID strings to only return low-privilege identities
func adcsFilterLowPriv(sids []string) []string {
	var result []string
	for _, sid := range sids {
		if name, ok := lowPrivSIDMap[sid]; ok {
			result = append(result, name)
			continue
		}
		// Check domain-relative RIDs (S-1-5-21-x-x-x-RID)
		parts := strings.Split(sid, "-")
		if len(parts) >= 5 && parts[0] == "S" && parts[1] == "1" && parts[2] == "5" && parts[3] == "21" {
			rid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
			if err == nil {
				if name, ok := lowPrivRIDMap[uint32(rid)]; ok {
					result = append(result, name)
				}
			}
		}
	}
	return result
}
