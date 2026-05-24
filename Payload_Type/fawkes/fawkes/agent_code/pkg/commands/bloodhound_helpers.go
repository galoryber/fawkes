package commands

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func bhGetDomainSID(conn *ldap.Conn, baseDN string) (string, error) {
	sr := ldap.NewSearchRequest(
		baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=*)",
		[]string{"objectSid"},
		nil,
	)
	result, err := conn.Search(sr)
	if err != nil {
		return "", err
	}
	if len(result.Entries) == 0 {
		return "", fmt.Errorf("no domain object found")
	}
	sid := bhFormatSID(result.Entries[0].GetRawAttributeValue("objectSid"))
	if sid == "" {
		return "", fmt.Errorf("empty objectSid")
	}
	return sid, nil
}

func bhFormatSID(raw []byte) string {
	if len(raw) < 8 {
		return ""
	}
	revision := raw[0]
	subAuthCount := int(raw[1])
	authority := uint64(raw[2])<<40 | uint64(raw[3])<<32 | uint64(raw[4])<<24 |
		uint64(raw[5])<<16 | uint64(raw[6])<<8 | uint64(raw[7])
	result := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthCount && 8+4*i+4 <= len(raw); i++ {
		subAuth := binary.LittleEndian.Uint32(raw[8+4*i:])
		result += fmt.Sprintf("-%d", subAuth)
	}
	return result
}

func bhFormatGUID(raw []byte) string {
	if len(raw) != 16 {
		return ""
	}
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%012x}",
		binary.LittleEndian.Uint32(raw[0:4]),
		binary.LittleEndian.Uint16(raw[4:6]),
		binary.LittleEndian.Uint16(raw[6:8]),
		raw[8], raw[9],
		raw[10:16])
}

func bhDNToDomain(baseDN string) string {
	var parts []string
	for _, component := range strings.Split(baseDN, ",") {
		component = strings.TrimSpace(component)
		if strings.HasPrefix(strings.ToUpper(component), "DC=") {
			parts = append(parts, component[3:])
		}
	}
	return strings.ToUpper(strings.Join(parts, "."))
}

func bhParseUint(s string) uint64 {
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseUint(s, 10, 64)
	return v
}

func bhParseFileTime(s string) int64 {
	if s == "" || s == "0" {
		return 0
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ft <= 0 {
		return 0
	}
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return 0
	}
	return (ft - epochDiff) / 10000000
}

func bhParseADTime(s string) int64 {
	if s == "" {
		return 0
	}
	s = strings.TrimSuffix(s, "Z")
	s = strings.TrimSuffix(s, ".0")
	if len(s) < 14 {
		return 0
	}
	year, _ := strconv.Atoi(s[0:4])
	month, _ := strconv.Atoi(s[4:6])
	day, _ := strconv.Atoi(s[6:8])
	hour, _ := strconv.Atoi(s[8:10])
	min, _ := strconv.Atoi(s[10:12])
	sec, _ := strconv.Atoi(s[12:14])
	if year == 0 || month == 0 || day == 0 {
		return 0
	}
	return bhDateToUnix(year, month, day, hour, min, sec)
}

func bhDateToUnix(year, month, day, hour, min, sec int) int64 {
	if month <= 2 {
		year--
		month += 12
	}
	days := 365*year + year/4 - year/100 + year/400 + (153*(month-3)+2)/5 + day - 719469
	return int64(days)*86400 + int64(hour)*3600 + int64(min)*60 + int64(sec)
}

func bhParseGPLink(gpLink string) []bhGPOLink {
	if gpLink == "" {
		return nil
	}
	var links []bhGPOLink
	for _, part := range strings.Split(gpLink, "]") {
		part = strings.TrimLeft(part, "[")
		if part == "" {
			continue
		}
		fields := strings.SplitN(part, ";", 2)
		if len(fields) != 2 {
			continue
		}
		ldapPath := fields[0]
		enforced := fields[1] == "2"

		ldapPath = strings.TrimPrefix(strings.ToUpper(ldapPath), "LDAP://")
		for _, comp := range strings.Split(ldapPath, ",") {
			comp = strings.TrimSpace(comp)
			if strings.HasPrefix(comp, "CN=") {
				guid := comp[3:]
				if strings.HasPrefix(guid, "{") {
					links = append(links, bhGPOLink{
						GUID:       guid,
						IsEnforced: enforced,
					})
					break
				}
			}
		}
	}
	return links
}

func bhFuncLevelName(level string) string {
	switch level {
	case "0":
		return "2000"
	case "1":
		return "2003 Interim"
	case "2":
		return "2003"
	case "3":
		return "2008"
	case "4":
		return "2008 R2"
	case "5":
		return "2012"
	case "6":
		return "2012 R2"
	case "7":
		return "2016"
	default:
		return level
	}
}

func bhPagedSearch(conn *ldap.Conn, baseDN, filter string, attrs []string, limit int) []*ldap.Entry {
	sr := ldap.NewSearchRequest(
		baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 30, false,
		filter, attrs, nil,
	)
	pageSize := uint32(500)
	if limit > 0 && limit < 500 {
		pageSize = uint32(limit)
	}
	result, err := conn.SearchWithPaging(sr, pageSize)
	if err != nil {
		return nil
	}
	entries := result.Entries
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries
}

func bhCountTrusts(domains []bhDomain) int {
	count := 0
	for _, d := range domains {
		count += len(d.Trusts)
	}
	return count
}

func bhToInterfaceSlice[T any](s []T) []interface{} {
	if len(s) == 0 {
		return []interface{}{}
	}
	out := make([]interface{}, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
