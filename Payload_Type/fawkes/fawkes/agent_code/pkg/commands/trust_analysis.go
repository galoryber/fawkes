// trust_analysis.go contains trust security risk analysis, formatting helpers,
// and binary SID parsing. Core enumeration is in trust.go.

package commands

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// trustCategory determines the trust category based on attributes and type.
func trustCategory(t trustEntry) string {
	if t.attributes&trustAttrWithinForest != 0 {
		return "Intra-Forest"
	}
	if t.attributes&trustAttrForestTransitive != 0 {
		return "Forest"
	}
	if t.attributes&trustAttrTreatAsExternal != 0 {
		return "External (forced)"
	}
	if t.trustType == trustTypeUplevel {
		return "External"
	}
	if t.trustType == trustTypeMIT {
		return "MIT Kerberos"
	}
	if t.trustType == trustTypeDownlevel {
		return "Downlevel"
	}
	return "Other"
}

// trustTransitivity returns whether the trust is transitive and why.
func trustTransitivity(t trustEntry) string {
	if t.attributes&trustAttrNonTransitive != 0 {
		return "Non-transitive"
	}
	if t.attributes&trustAttrWithinForest != 0 {
		return "Transitive (intra-forest)"
	}
	if t.attributes&trustAttrForestTransitive != 0 {
		return "Transitive (forest)"
	}
	// External trusts are non-transitive by default
	if t.trustType == trustTypeUplevel && t.attributes&trustAttrWithinForest == 0 && t.attributes&trustAttrForestTransitive == 0 {
		return "Non-transitive (external)"
	}
	return "Transitive"
}

// trustComputeRisks analyzes a trust entry for security risks.
func trustComputeRisks(t trustEntry) []string {
	var risks []string

	if t.direction == trustDirectionOutbound || t.direction == trustDirectionBidir {
		if t.attributes&trustAttrFilterSIDs == 0 {
			risks = append(risks, "No SID filtering — SID history attacks possible")
		}
		if t.attributes&trustAttrWithinForest != 0 {
			risks = append(risks, "Intra-forest — implicit full trust")
		}
		if t.attributes&trustAttrForestTransitive != 0 && t.attributes&trustAttrFilterSIDs == 0 {
			risks = append(risks, "Forest trust without SID filtering — cross-forest attack possible")
		}
	}

	// RC4-only encryption is weak — AES should be preferred
	if t.attributes&trustAttrUsesRC4Encryption != 0 && t.attributes&trustAttrUsesAESKeys == 0 {
		risks = append(risks, "RC4 encryption only — vulnerable to offline cracking")
	}

	// Selective authentication means the trust requires explicit permissions
	if t.attributes&trustAttrCrossOrganization != 0 {
		// This is actually defensive, so note it rather than flag as risk
		risks = append(risks, "Selective authentication enabled — restricted access")
	}

	// TGT delegation across organizations
	if t.attributes&trustAttrCrossOrgEnableTGTDe != 0 {
		risks = append(risks, "TGT delegation enabled across organizations")
	}

	return risks
}

// trustDirectionStr provides a detailed direction string including domain context.
func trustDirectionStr(dir int, currentDomain, partner string) string {
	switch dir {
	case trustDirectionInbound:
		return fmt.Sprintf("Inbound (%s trusts %s)", partner, currentDomain)
	case trustDirectionOutbound:
		return fmt.Sprintf("Outbound (%s trusts %s)", currentDomain, partner)
	case trustDirectionBidir:
		return "Bidirectional"
	default:
		return fmt.Sprintf("Unknown (%d)", dir)
	}
}

// trustFormatTimestamp formats AD generalized time (20060102150405.0Z) to readable form.
func trustFormatTimestamp(raw string) string {
	if raw == "" {
		return ""
	}
	// AD timestamps use format: 20060102150405.0Z
	raw = strings.TrimSuffix(raw, ".0Z")
	if len(raw) >= 14 {
		return raw[:4] + "-" + raw[4:6] + "-" + raw[6:8] + " " + raw[8:10] + ":" + raw[10:12] + ":" + raw[12:14] + " UTC"
	}
	return raw
}

func trustTypeStr(t int) string {
	switch t {
	case trustTypeDownlevel:
		return "Downlevel (Windows NT 4.0)"
	case trustTypeUplevel:
		return "Uplevel (Active Directory)"
	case trustTypeMIT:
		return "MIT (Kerberos realm)"
	default:
		return fmt.Sprintf("Unknown (%d)", t)
	}
}

func trustAttributesStr(attrs int) string {
	if attrs == 0 {
		return "None"
	}

	var flags []string
	if attrs&trustAttrNonTransitive != 0 {
		flags = append(flags, "NON_TRANSITIVE")
	}
	if attrs&trustAttrUplevelOnly != 0 {
		flags = append(flags, "UPLEVEL_ONLY")
	}
	if attrs&trustAttrFilterSIDs != 0 {
		flags = append(flags, "SID_FILTERING")
	}
	if attrs&trustAttrForestTransitive != 0 {
		flags = append(flags, "FOREST_TRANSITIVE")
	}
	if attrs&trustAttrCrossOrganization != 0 {
		flags = append(flags, "CROSS_ORGANIZATION")
	}
	if attrs&trustAttrWithinForest != 0 {
		flags = append(flags, "WITHIN_FOREST")
	}
	if attrs&trustAttrTreatAsExternal != 0 {
		flags = append(flags, "TREAT_AS_EXTERNAL")
	}
	if attrs&trustAttrUsesRC4Encryption != 0 {
		flags = append(flags, "RC4_ENCRYPTION")
	}
	if attrs&trustAttrUsesAESKeys != 0 {
		flags = append(flags, "AES_KEYS")
	}
	if attrs&trustAttrCrossOrgNoTGTDeleg != 0 {
		flags = append(flags, "NO_TGT_DELEGATION")
	}
	if attrs&trustAttrPIMTrust != 0 {
		flags = append(flags, "PIM_TRUST")
	}
	if attrs&trustAttrCrossOrgEnableTGTDe != 0 {
		flags = append(flags, "ENABLE_TGT_DELEGATION")
	}

	if len(flags) == 0 {
		return fmt.Sprintf("0x%X", attrs)
	}
	return strings.Join(flags, " | ")
}

// trustParseSID converts a binary SID to string form (S-1-5-21-...)
func trustParseSID(b []byte) string {
	if len(b) < 8 {
		return ""
	}

	revision := b[0]
	subAuthCount := int(b[1])

	// 6-byte big-endian authority
	var authority uint64
	for i := 2; i < 8; i++ {
		authority = (authority << 8) | uint64(b[i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthCount; i++ {
		offset := 8 + i*4
		if offset+4 > len(b) {
			break
		}
		subAuth := binary.LittleEndian.Uint32(b[offset : offset+4])
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// trustDNToDomain converts DC=north,DC=sevenkingdoms,DC=local to north.sevenkingdoms.local
func trustDNToDomain(dn string) string {
	var parts []string
	for _, component := range strings.Split(dn, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	if len(parts) == 0 {
		return dn
	}
	return strings.Join(parts, ".")
}
