package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

func ldapQueryBloodHound(conn *ldap.Conn, args ldapQueryArgs, baseDN string) string {
	domain := bhDNToDomain(baseDN)
	domainUpper := strings.ToUpper(domain)

	domainSID, err := bhGetDomainSID(conn, baseDN)
	if err != nil {
		domainSID = ""
	}

	// Build SID-to-name cache for group membership resolution
	sidCache := make(map[string]string)
	dnToSID := make(map[string]string)
	dnToType := make(map[string]string)

	// Collect each object type
	users := bhCollectUsers(conn, baseDN, domainUpper, domainSID, sidCache, dnToSID, dnToType, args.Limit)
	computers := bhCollectComputers(conn, baseDN, domainUpper, domainSID, sidCache, dnToSID, dnToType, args.Limit)
	groups := bhCollectGroups(conn, baseDN, domainUpper, domainSID, sidCache, dnToSID, dnToType, args.Limit)
	ous := bhCollectOUs(conn, baseDN, domainUpper, domainSID, dnToSID, args.Limit)
	gpos := bhCollectGPOs(conn, baseDN, domainUpper, domainSID, dnToSID, args.Limit)
	domains := bhCollectDomain(conn, baseDN, domainUpper, domainSID)

	// Resolve group memberships using DN-to-SID cache
	bhResolveGroupMembers(groups, dnToSID, dnToType)

	output := bhOutput{
		Computers: bhFile{
			Meta: bhMeta{Type: "computers", Count: len(computers), Version: 6},
			Data: bhToInterfaceSlice(computers),
		},
		Users: bhFile{
			Meta: bhMeta{Type: "users", Count: len(users), Version: 6},
			Data: bhToInterfaceSlice(users),
		},
		Groups: bhFile{
			Meta: bhMeta{Type: "groups", Count: len(groups), Version: 6},
			Data: bhToInterfaceSlice(groups),
		},
		Domains: bhFile{
			Meta: bhMeta{Type: "domains", Count: len(domains), Version: 6},
			Data: bhToInterfaceSlice(domains),
		},
		OUs: bhFile{
			Meta: bhMeta{Type: "ous", Count: len(ous), Version: 6},
			Data: bhToInterfaceSlice(ous),
		},
		GPOs: bhFile{
			Meta: bhMeta{Type: "gpos", Count: len(gpos), Version: 6},
			Data: bhToInterfaceSlice(gpos),
		},
		Summary: bhSummary{
			Domain:    domainUpper,
			DomainSID: domainSID,
			Users:     len(users),
			Computers: len(computers),
			Groups:    len(groups),
			OUs:       len(ous),
			GPOs:      len(gpos),
			Trusts:    bhCountTrusts(domains),
		},
	}

	data, err := json.Marshal(output)
	if err != nil {
		return fmt.Sprintf(`{"error":"marshal: %v"}`, err)
	}
	return string(data)
}

func bhCollectUsers(conn *ldap.Conn, baseDN, domain, domainSID string,
	sidCache map[string]string, dnToSID, dnToType map[string]string, limit int) []bhUser {

	attrs := []string{
		"objectSid", "sAMAccountName", "userPrincipalName", "distinguishedName",
		"displayName", "description", "mail", "title", "homeDirectory",
		"userAccountControl", "adminCount", "memberOf", "primaryGroupID",
		"servicePrincipalName", "msDS-AllowedToDelegateTo", "sIDHistory",
		"pwdLastSet", "lastLogonTimestamp", "whenCreated",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(&(objectCategory=person)(objectClass=user))", attrs, limit)

	var users []bhUser
	for _, e := range entries {
		sid := bhFormatSID(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		sam := e.GetAttributeValue("sAMAccountName")
		name := strings.ToUpper(sam) + "@" + domain
		uac := bhParseUint(e.GetAttributeValue("userAccountControl"))
		spns := e.GetAttributeValues("servicePrincipalName")
		delegateTo := e.GetAttributeValues("msDS-AllowedToDelegateTo")

		sidCache[sid] = name
		dn := e.DN
		dnToSID[strings.ToLower(dn)] = sid
		dnToType[strings.ToLower(dn)] = "User"

		primaryGID := bhParseUint(e.GetAttributeValue("primaryGroupID"))
		primaryGroupSID := ""
		if primaryGID > 0 && domainSID != "" {
			primaryGroupSID = fmt.Sprintf("%s-%d", domainSID, primaryGID)
		}

		var allowedToDelegate []bhTypedPrincipal
		for _, spn := range delegateTo {
			allowedToDelegate = append(allowedToDelegate, bhTypedPrincipal{
				ObjectIdentifier: spn,
				ObjectType:       "Computer",
			})
		}

		u := bhUser{
			ObjectIdentifier:  sid,
			PrimaryGroupSID:   primaryGroupSID,
			SPNTargets:        []interface{}{},
			HasSIDHistory:     []interface{}{},
			AllowedToDelegate: allowedToDelegate,
			Aces:              []interface{}{},
			Properties: bhUserProps{
				Name:                    name,
				Domain:                  domain,
				DomainSID:               domainSID,
				DistinguishedName:       dn,
				Description:             e.GetAttributeValue("description"),
				WhenCreated:             bhParseADTime(e.GetAttributeValue("whenCreated")),
				Enabled:                 uac&0x2 == 0,
				LastLogonTimestamp:       bhParseFileTime(e.GetAttributeValue("lastLogonTimestamp")),
				PwdLastSet:              bhParseFileTime(e.GetAttributeValue("pwdLastSet")),
				DontReqPreauth:          uac&0x400000 != 0,
				PasswordNotReqd:         uac&0x20 != 0,
				UnconstrainedDelegation: uac&0x80000 != 0,
				Sensitive:               uac&0x100000 != 0,
				ServicePrincipalNames:   spns,
				HasSPN:                  len(spns) > 0,
				AdminCount:              e.GetAttributeValue("adminCount") == "1",
				DisplayName:             e.GetAttributeValue("displayName"),
				Email:                   e.GetAttributeValue("mail"),
				Title:                   e.GetAttributeValue("title"),
				HomeDirectory:           e.GetAttributeValue("homeDirectory"),
				SIDHistory:              []string{},
				TrustedToAuth:           uac&0x1000000 != 0,
			},
		}
		if u.Properties.ServicePrincipalNames == nil {
			u.Properties.ServicePrincipalNames = []string{}
		}
		users = append(users, u)
	}
	return users
}

func bhCollectComputers(conn *ldap.Conn, baseDN, domain, domainSID string,
	sidCache map[string]string, dnToSID, dnToType map[string]string, limit int) []bhComputer {

	attrs := []string{
		"objectSid", "sAMAccountName", "dNSHostName", "distinguishedName",
		"description", "operatingSystem", "operatingSystemVersion",
		"userAccountControl", "primaryGroupID",
		"msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"ms-Mcs-AdmPwd", "ms-LAPS-Password", "ms-LAPS-EncryptedPassword",
		"pwdLastSet", "lastLogonTimestamp", "whenCreated",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(objectClass=computer)", attrs, limit)

	var computers []bhComputer
	for _, e := range entries {
		sid := bhFormatSID(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		sam := e.GetAttributeValue("sAMAccountName")
		dns := e.GetAttributeValue("dNSHostName")
		name := strings.ToUpper(dns)
		if name == "" {
			name = strings.TrimSuffix(strings.ToUpper(sam), "$") + "." + domain
		}
		uac := bhParseUint(e.GetAttributeValue("userAccountControl"))
		delegateTo := e.GetAttributeValues("msDS-AllowedToDelegateTo")

		sidCache[sid] = name
		dn := e.DN
		dnToSID[strings.ToLower(dn)] = sid
		dnToType[strings.ToLower(dn)] = "Computer"

		primaryGID := bhParseUint(e.GetAttributeValue("primaryGroupID"))
		primaryGroupSID := ""
		if primaryGID > 0 && domainSID != "" {
			primaryGroupSID = fmt.Sprintf("%s-%d", domainSID, primaryGID)
		}

		hasLAPS := e.GetAttributeValue("ms-Mcs-AdmPwd") != "" ||
			e.GetAttributeValue("ms-LAPS-Password") != "" ||
			len(e.GetRawAttributeValue("ms-LAPS-EncryptedPassword")) > 0

		var allowedToDelegate []bhTypedPrincipal
		for _, spn := range delegateTo {
			allowedToDelegate = append(allowedToDelegate, bhTypedPrincipal{
				ObjectIdentifier: spn,
				ObjectType:       "Computer",
			})
		}

		c := bhComputer{
			ObjectIdentifier:   sid,
			PrimaryGroupSID:    primaryGroupSID,
			AllowedToDelegate:  allowedToDelegate,
			AllowedToAct:       []bhTypedPrincipal{},
			HasSIDHistory:      []interface{}{},
			Sessions:           bhSessionResult{Results: []interface{}{}, Collected: false},
			PrivilegedSessions: bhSessionResult{Results: []interface{}{}, Collected: false},
			RegistrySessions:   bhSessionResult{Results: []interface{}{}, Collected: false},
			LocalAdmins:        bhLocalGroupResult{Results: []interface{}{}, Collected: false},
			RemoteDesktopUsers: bhLocalGroupResult{Results: []interface{}{}, Collected: false},
			DcomUsers:          bhLocalGroupResult{Results: []interface{}{}, Collected: false},
			PSRemoteUsers:      bhLocalGroupResult{Results: []interface{}{}, Collected: false},
			Aces:               []interface{}{},
			Properties: bhComputerProps{
				Name:                    name,
				Domain:                  domain,
				DomainSID:               domainSID,
				DistinguishedName:       dn,
				Description:             e.GetAttributeValue("description"),
				OperatingSystem:         e.GetAttributeValue("operatingSystem"),
				Enabled:                 uac&0x2 == 0,
				UnconstrainedDelegation: uac&0x80000 != 0,
				LastLogon:               bhParseFileTime(e.GetAttributeValue("lastLogonTimestamp")),
				LastLogonTimestamp:       bhParseFileTime(e.GetAttributeValue("lastLogonTimestamp")),
				PwdLastSet:              bhParseFileTime(e.GetAttributeValue("pwdLastSet")),
				WhenCreated:             bhParseADTime(e.GetAttributeValue("whenCreated")),
				HasLAPS:                 hasLAPS,
				TrustedToAuth:           uac&0x1000000 != 0,
			},
		}
		if c.AllowedToDelegate == nil {
			c.AllowedToDelegate = []bhTypedPrincipal{}
		}
		computers = append(computers, c)
	}
	return computers
}

func bhCollectGroups(conn *ldap.Conn, baseDN, domain, domainSID string,
	sidCache map[string]string, dnToSID, dnToType map[string]string, limit int) []bhGroup {

	attrs := []string{
		"objectSid", "cn", "sAMAccountName", "distinguishedName",
		"description", "adminCount", "member", "groupType", "whenCreated",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(objectClass=group)", attrs, limit)

	var groups []bhGroup
	for _, e := range entries {
		sid := bhFormatSID(e.GetRawAttributeValue("objectSid"))
		if sid == "" {
			continue
		}
		sam := e.GetAttributeValue("sAMAccountName")
		cn := e.GetAttributeValue("cn")
		name := strings.ToUpper(sam)
		if name == "" {
			name = strings.ToUpper(cn)
		}
		name += "@" + domain

		sidCache[sid] = name
		dn := e.DN
		dnToSID[strings.ToLower(dn)] = sid
		dnToType[strings.ToLower(dn)] = "Group"

		// member DNs stored for later resolution
		memberDNs := e.GetAttributeValues("member")

		g := bhGroup{
			ObjectIdentifier: sid,
			Aces:             []interface{}{},
			Properties: bhGroupProps{
				Name:              name,
				Domain:            domain,
				DomainSID:         domainSID,
				DistinguishedName: dn,
				Description:       e.GetAttributeValue("description"),
				AdminCount:        e.GetAttributeValue("adminCount") == "1",
				WhenCreated:       bhParseADTime(e.GetAttributeValue("whenCreated")),
			},
		}

		// Temporarily store member DNs as unresolved typed principals
		var members []bhTypedPrincipal
		for _, mDN := range memberDNs {
			members = append(members, bhTypedPrincipal{
				ObjectIdentifier: strings.ToLower(mDN),
				ObjectType:       "Base",
			})
		}
		g.Members = members
		groups = append(groups, g)
	}
	return groups
}

func bhCollectOUs(conn *ldap.Conn, baseDN, domain, domainSID string,
	dnToSID map[string]string, limit int) []bhOU {

	attrs := []string{
		"objectGUID", "ou", "distinguishedName", "description",
		"gpLink", "gPOptions", "whenCreated",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(objectClass=organizationalUnit)", attrs, limit)

	var ous []bhOU
	for _, e := range entries {
		guid := bhFormatGUID(e.GetRawAttributeValue("objectGUID"))
		if guid == "" {
			continue
		}
		name := e.GetAttributeValue("ou")
		dn := e.DN

		dnToSID[strings.ToLower(dn)] = guid

		gpOptions := bhParseUint(e.GetAttributeValue("gPOptions"))
		links := bhParseGPLink(e.GetAttributeValue("gpLink"))

		o := bhOU{
			ObjectIdentifier: guid,
			ChildObjects:     []interface{}{},
			Links:            links,
			Aces:             []interface{}{},
			Properties: bhOUProps{
				Name:              strings.ToUpper(name) + "@" + domain,
				Domain:            domain,
				DomainSID:         domainSID,
				DistinguishedName: dn,
				Description:       e.GetAttributeValue("description"),
				WhenCreated:       bhParseADTime(e.GetAttributeValue("whenCreated")),
				BlocksInheritance: gpOptions&1 != 0,
			},
		}
		ous = append(ous, o)
	}
	return ous
}

func bhCollectGPOs(conn *ldap.Conn, baseDN, domain, domainSID string,
	dnToSID map[string]string, limit int) []bhGPO {

	attrs := []string{
		"objectGUID", "cn", "displayName", "distinguishedName",
		"description", "gPCFileSysPath", "whenCreated",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(objectClass=groupPolicyContainer)", attrs, limit)

	var gpos []bhGPO
	for _, e := range entries {
		guid := e.GetAttributeValue("cn")
		if guid == "" {
			guid = bhFormatGUID(e.GetRawAttributeValue("objectGUID"))
		}
		if guid == "" {
			continue
		}
		dn := e.DN
		displayName := e.GetAttributeValue("displayName")

		dnToSID[strings.ToLower(dn)] = guid

		g := bhGPO{
			ObjectIdentifier: guid,
			Aces:             []interface{}{},
			Properties: bhGPOProps{
				Name:              strings.ToUpper(displayName) + "@" + domain,
				Domain:            domain,
				DomainSID:         domainSID,
				DistinguishedName: dn,
				Description:       e.GetAttributeValue("description"),
				GPCFileSysPath:    e.GetAttributeValue("gPCFileSysPath"),
				WhenCreated:       bhParseADTime(e.GetAttributeValue("whenCreated")),
			},
		}
		gpos = append(gpos, g)
	}
	return gpos
}

func bhCollectDomain(conn *ldap.Conn, baseDN, domain, domainSID string) []bhDomain {
	attrs := []string{
		"objectSid", "distinguishedName", "msDS-Behavior-Version",
		"whenCreated",
	}

	sr := ldap.NewSearchRequest(
		baseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
		0, 10, false,
		"(objectClass=domain)",
		attrs, nil,
	)
	result, err := conn.Search(sr)
	if err != nil || len(result.Entries) == 0 {
		sr.Filter = "(objectClass=*)"
		result, err = conn.Search(sr)
		if err != nil || len(result.Entries) == 0 {
			return nil
		}
	}

	e := result.Entries[0]
	sid := bhFormatSID(e.GetRawAttributeValue("objectSid"))
	if sid == "" {
		sid = domainSID
	}

	funcLevel := e.GetAttributeValue("msDS-Behavior-Version")

	trusts := bhCollectTrusts(conn, baseDN)

	d := bhDomain{
		ObjectIdentifier: sid,
		ChildObjects:     []interface{}{},
		Links:            []interface{}{},
		Trusts:           trusts,
		Aces:             []interface{}{},
		Properties: bhDomainProps{
			Name:              domain,
			Domain:            domain,
			DomainSID:         sid,
			DistinguishedName: baseDN,
			FunctionalLevel:   bhFuncLevelName(funcLevel),
			WhenCreated:       bhParseADTime(e.GetAttributeValue("whenCreated")),
		},
	}

	return []bhDomain{d}
}

func bhCollectTrusts(conn *ldap.Conn, baseDN string) []bhTrust {
	attrs := []string{
		"cn", "trustPartner", "trustDirection", "trustType",
		"trustAttributes", "securityIdentifier",
	}

	entries := bhPagedSearch(conn, baseDN,
		"(objectClass=trustedDomain)", attrs, 100)

	var trusts []bhTrust
	for _, e := range entries {
		trustDir := int(bhParseUint(e.GetAttributeValue("trustDirection")))
		trustType := int(bhParseUint(e.GetAttributeValue("trustType")))
		trustAttrs := bhParseUint(e.GetAttributeValue("trustAttributes"))

		targetSID := bhFormatSID(e.GetRawAttributeValue("securityIdentifier"))
		if targetSID == "" {
			targetSID = "UNKNOWN"
		}

		t := bhTrust{
			TargetDomainSID:     targetSID,
			TargetDomainName:    strings.ToUpper(e.GetAttributeValue("trustPartner")),
			IsTransitive:        trustAttrs&1 == 0,
			SidFilteringEnabled: trustAttrs&4 != 0,
			TrustDirection:      trustDir,
			TrustType:           trustType,
		}
		trusts = append(trusts, t)
	}
	return trusts
}

func bhResolveGroupMembers(groups []bhGroup, dnToSID, dnToType map[string]string) {
	for i := range groups {
		resolved := make([]bhTypedPrincipal, 0, len(groups[i].Members))
		for _, m := range groups[i].Members {
			dnLower := m.ObjectIdentifier
			sid, ok := dnToSID[dnLower]
			if !ok {
				resolved = append(resolved, bhTypedPrincipal{
					ObjectIdentifier: dnLower,
					ObjectType:       "Base",
				})
				continue
			}
			objType := dnToType[dnLower]
			if objType == "" {
				objType = "Base"
			}
			resolved = append(resolved, bhTypedPrincipal{
				ObjectIdentifier: sid,
				ObjectType:       objType,
			})
		}
		groups[i].Members = resolved
		if groups[i].Members == nil {
			groups[i].Members = []bhTypedPrincipal{}
		}
	}
}
