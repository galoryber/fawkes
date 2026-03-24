package commands

// acl_edit_helpers.go contains pure helper functions extracted from acl_edit.go
// for cross-platform testing. No build tags — these are testable on any platform.

import (
	"encoding/binary"
	"strings"
)

// hexByte converts a 2-character hex string to a byte.
func hexByte(s string) byte {
	var b byte
	for _, c := range s {
		b <<= 4
		switch {
		case c >= '0' && c <= '9':
			b |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			b |= byte(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			b |= byte(c - 'A' + 10)
		}
	}
	return b
}

// aclGUIDBytes converts a GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" to
// mixed-endian binary format used by Active Directory.
func aclGUIDBytes(guidStr string) []byte {
	// Remove hyphens
	clean := strings.ReplaceAll(guidStr, "-", "")
	if len(clean) != 32 {
		return nil
	}

	guid := make([]byte, 16)
	// Data1 (4 bytes, little-endian)
	for i := 0; i < 4; i++ {
		b := hexByte(clean[(3-i)*2 : (3-i)*2+2])
		guid[i] = b
	}
	// Data2 (2 bytes, little-endian)
	for i := 0; i < 2; i++ {
		b := hexByte(clean[8+(1-i)*2 : 8+(1-i)*2+2])
		guid[4+i] = b
	}
	// Data3 (2 bytes, little-endian)
	for i := 0; i < 2; i++ {
		b := hexByte(clean[12+(1-i)*2 : 12+(1-i)*2+2])
		guid[6+i] = b
	}
	// Data4 (8 bytes, big-endian)
	for i := 0; i < 8; i++ {
		guid[8+i] = hexByte(clean[16+i*2 : 16+i*2+2])
	}

	return guid
}

// rightToMaskAndGUID maps friendly right names to access mask and optional object GUID.
// Returns (mask, objectGUID, aceType). Returns (0, nil, 0) for unknown rights.
func rightToMaskAndGUID(right string) (uint32, []byte, byte) {
	right = strings.ToLower(right)
	switch right {
	case "genericall", "full-control":
		return 0x10000000, nil, 0x00 // GenericAll
	case "genericwrite":
		return 0x40000000, nil, 0x00 // GenericWrite
	case "writedacl":
		return 0x00040000, nil, 0x00 // WriteDACL
	case "writeowner":
		return 0x00080000, nil, 0x00 // WriteOwner
	case "allextendedrights":
		return 0x00000100, nil, 0x00 // All Extended Rights
	case "writeproperty":
		return 0x00000020, nil, 0x00 // Write all properties
	case "forcechangepassword":
		// ExtendedRight with User-Force-Change-Password GUID
		return 0x00000100, aclGUIDBytes("00299570-246d-11d0-a768-00aa006e0529"), 0x05
	case "dcsync", "ds-replication-get-changes":
		return 0x00000100, aclGUIDBytes("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), 0x05
	case "ds-replication-get-changes-all":
		return 0x00000100, aclGUIDBytes("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), 0x05
	case "write-member":
		// WriteProperty on 'member' attribute
		return 0x00000020, aclGUIDBytes("bf9679c0-0de6-11d0-a285-00aa003049e2"), 0x05
	case "write-spn":
		return 0x00000020, aclGUIDBytes("bf967a86-0de6-11d0-a285-00aa003049e2"), 0x05
	case "write-keycredentiallink":
		return 0x00000020, aclGUIDBytes("5b47d60f-6090-40b2-9f37-2a4de88f3063"), 0x05
	default:
		return 0, nil, 0x00
	}
}

// buildACE constructs a binary ACE (Access Control Entry) structure.
func buildACE(aceType byte, mask uint32, sid []byte, objectGUID []byte) []byte {
	if aceType == 0x05 && len(objectGUID) == 16 {
		// ACCESS_ALLOWED_OBJECT_ACE_TYPE
		// Header(4) + Mask(4) + Flags(4) + ObjectType(16) + SID
		aceSize := 4 + 4 + 4 + 16 + len(sid)
		ace := make([]byte, aceSize)
		ace[0] = 0x05                                            // AceType
		ace[1] = 0x00                                            // AceFlags (no inheritance)
		binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize)) // AceSize
		binary.LittleEndian.PutUint32(ace[4:8], mask)            // AccessMask
		binary.LittleEndian.PutUint32(ace[8:12], 0x01)           // Flags: ACE_OBJECT_TYPE_PRESENT
		copy(ace[12:28], objectGUID)                             // ObjectType GUID
		copy(ace[28:], sid)                                      // SID
		return ace
	}

	// ACCESS_ALLOWED_ACE_TYPE (standard)
	aceSize := 4 + 4 + len(sid) // Header(4) + Mask(4) + SID
	ace := make([]byte, aceSize)
	ace[0] = 0x00                                            // AceType
	ace[1] = 0x00                                            // AceFlags
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize)) // AceSize
	binary.LittleEndian.PutUint32(ace[4:8], mask)            // AccessMask
	copy(ace[8:], sid)                                       // SID
	return ace
}

// removeMatchingACEs removes ACEs that match the given SID, mask, and objectGUID.
// Uses a two-pass approach: first tries exact mask match, then falls back to SID-based
// matching. AD often decomposes generic rights (e.g., GenericAll 0x10000000) into
// specific component rights, so exact mask matching may fail after a write.
func removeMatchingACEs(aceData []byte, aceCount int, targetSID string, targetMask uint32, targetGUID []byte, targetType byte) ([]byte, int) {
	// Pass 1: Try exact match (mask + SID + GUID)
	result, remaining := removeMatchingACEsPass(aceData, aceCount, targetSID, targetMask, targetGUID, targetType, true)
	if remaining < aceCount {
		return result, remaining
	}

	// Pass 2: Relaxed match — SID only for standard ACEs, SID + GUID for object ACEs.
	// This handles cases where AD decomposed GenericAll/GenericWrite into specific rights.
	return removeMatchingACEsPass(aceData, aceCount, targetSID, targetMask, targetGUID, targetType, false)
}

func removeMatchingACEsPass(aceData []byte, aceCount int, targetSID string, targetMask uint32, targetGUID []byte, targetType byte, exactMask bool) ([]byte, int) {
	var result []byte
	remaining := aceCount
	pos := 0

	for i := 0; i < aceCount && pos+4 <= len(aceData); i++ {
		aceType := aceData[pos]
		aceSize := int(binary.LittleEndian.Uint16(aceData[pos+2 : pos+4]))

		if aceSize < 4 || pos+aceSize > len(aceData) {
			break
		}

		shouldRemove := false

		switch aceType {
		case 0x00: // ACCESS_ALLOWED_ACE_TYPE
			if pos+8 <= len(aceData) && targetType == 0x00 && len(targetGUID) == 0 {
				sid := adcsParseSID(aceData[pos+8 : pos+aceSize])
				if sid == targetSID {
					if exactMask {
						mask := binary.LittleEndian.Uint32(aceData[pos+4 : pos+8])
						shouldRemove = (mask == targetMask)
					} else {
						// Relaxed: match by SID only — handles decomposed generic rights
						shouldRemove = true
					}
				}
			}
		case 0x05: // ACCESS_ALLOWED_OBJECT_ACE_TYPE
			if pos+12 <= len(aceData) && targetType == 0x05 {
				flags := binary.LittleEndian.Uint32(aceData[pos+8 : pos+12])

				sidStart := pos + 12
				var objGUID []byte
				if flags&0x01 != 0 && sidStart+16 <= len(aceData) {
					objGUID = aceData[sidStart : sidStart+16]
					sidStart += 16
				}
				if flags&0x02 != 0 {
					sidStart += 16
				}

				if sidStart < pos+aceSize {
					sid := adcsParseSID(aceData[sidStart : pos+aceSize])
					guidsMatch := len(targetGUID) == 16 && len(objGUID) == 16
					if guidsMatch {
						for j := 0; j < 16; j++ {
							if targetGUID[j] != objGUID[j] {
								guidsMatch = false
								break
							}
						}
					}
					if sid == targetSID && guidsMatch {
						if exactMask {
							mask := binary.LittleEndian.Uint32(aceData[pos+4 : pos+8])
							shouldRemove = (mask == targetMask)
						} else {
							shouldRemove = true
						}
					}
				}
			}
		}

		if !shouldRemove {
			result = append(result, aceData[pos:pos+aceSize]...)
		} else {
			remaining--
		}

		pos += aceSize
	}

	return result, remaining
}
