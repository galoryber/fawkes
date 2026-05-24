package commands

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// BloodHound CE v6 JSON ingest format types.

type bhMeta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type bhFile struct {
	Meta bhMeta        `json:"meta"`
	Data []interface{} `json:"data"`
}

type bhUser struct {
	ObjectIdentifier   string            `json:"ObjectIdentifier"`
	Properties         bhUserProps       `json:"Properties"`
	PrimaryGroupSID    string            `json:"PrimaryGroupSID"`
	SPNTargets         []interface{}     `json:"SPNTargets"`
	HasSIDHistory      []interface{}     `json:"HasSIDHistory"`
	AllowedToDelegate  []bhTypedPrincipal `json:"AllowedToDelegate"`
	Aces               []interface{}     `json:"Aces"`
}

type bhUserProps struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	DomainSID               string   `json:"domainsid"`
	DistinguishedName       string   `json:"distinguishedname"`
	Description             string   `json:"description,omitempty"`
	WhenCreated             int64    `json:"whencreated"`
	Enabled                 bool     `json:"enabled"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp       int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	DontReqPreauth          bool     `json:"dontreqpreauth"`
	PasswordNotReqd         bool     `json:"passwordnotreqd"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	Sensitive               bool     `json:"sensitive"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	HasSPN                  bool     `json:"hasspn"`
	AdminCount              bool     `json:"admincount"`
	DisplayName             string   `json:"displayname,omitempty"`
	Email                   string   `json:"email,omitempty"`
	Title                   string   `json:"title,omitempty"`
	HomeDirectory           string   `json:"homedirectory,omitempty"`
	SIDHistory              []string `json:"sidhistory"`
	TrustedToAuth           bool     `json:"trustedtoauth"`
}

type bhComputer struct {
	ObjectIdentifier    string                 `json:"ObjectIdentifier"`
	Properties          bhComputerProps        `json:"Properties"`
	PrimaryGroupSID     string                 `json:"PrimaryGroupSID"`
	AllowedToDelegate   []bhTypedPrincipal     `json:"AllowedToDelegate"`
	AllowedToAct        []bhTypedPrincipal     `json:"AllowedToAct"`
	HasSIDHistory       []interface{}          `json:"HasSIDHistory"`
	Sessions            bhSessionResult        `json:"Sessions"`
	PrivilegedSessions  bhSessionResult        `json:"PrivilegedSessions"`
	RegistrySessions    bhSessionResult        `json:"RegistrySessions"`
	LocalAdmins         bhLocalGroupResult     `json:"LocalAdmins"`
	RemoteDesktopUsers  bhLocalGroupResult     `json:"RemoteDesktopUsers"`
	DcomUsers           bhLocalGroupResult     `json:"DcomUsers"`
	PSRemoteUsers       bhLocalGroupResult     `json:"PSRemoteUsers"`
	Aces                []interface{}          `json:"Aces"`
}

type bhComputerProps struct {
	Name                    string `json:"name"`
	Domain                  string `json:"domain"`
	DomainSID               string `json:"domainsid"`
	DistinguishedName       string `json:"distinguishedname"`
	Description             string `json:"description,omitempty"`
	OperatingSystem         string `json:"operatingsystem,omitempty"`
	Enabled                 bool   `json:"enabled"`
	UnconstrainedDelegation bool   `json:"unconstraineddelegation"`
	LastLogon               int64  `json:"lastlogon"`
	LastLogonTimestamp       int64  `json:"lastlogontimestamp"`
	PwdLastSet              int64  `json:"pwdlastset"`
	WhenCreated             int64  `json:"whencreated"`
	HasLAPS                 bool   `json:"haslaps"`
	TrustedToAuth           bool   `json:"trustedtoauth"`
}

type bhGroup struct {
	ObjectIdentifier string            `json:"ObjectIdentifier"`
	Properties       bhGroupProps      `json:"Properties"`
	Members          []bhTypedPrincipal `json:"Members"`
	Aces             []interface{}     `json:"Aces"`
}

type bhGroupProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description,omitempty"`
	AdminCount        bool   `json:"admincount"`
	WhenCreated       int64  `json:"whencreated"`
}

type bhDomain struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       bhDomainProps  `json:"Properties"`
	ChildObjects     []interface{}  `json:"ChildObjects"`
	Links            []interface{}  `json:"Links"`
	Trusts           []bhTrust      `json:"Trusts"`
	Aces             []interface{}  `json:"Aces"`
}

type bhDomainProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	FunctionalLevel   string `json:"functionallevel,omitempty"`
	WhenCreated       int64  `json:"whencreated"`
}

type bhTrust struct {
	TargetDomainSID     string `json:"TargetDomainSid"`
	TargetDomainName    string `json:"TargetDomainName"`
	IsTransitive        bool   `json:"IsTransitive"`
	SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
	TrustDirection      int    `json:"TrustDirection"`
	TrustType           int    `json:"TrustType"`
}

type bhOU struct {
	ObjectIdentifier string         `json:"ObjectIdentifier"`
	Properties       bhOUProps      `json:"Properties"`
	ChildObjects     []interface{}  `json:"ChildObjects"`
	Links            []bhGPOLink    `json:"Links"`
	Aces             []interface{}  `json:"Aces"`
}

type bhOUProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description,omitempty"`
	WhenCreated       int64  `json:"whencreated"`
	BlocksInheritance bool   `json:"blocksinheritance"`
}

type bhGPO struct {
	ObjectIdentifier string      `json:"ObjectIdentifier"`
	Properties       bhGPOProps  `json:"Properties"`
	Aces             []interface{} `json:"Aces"`
}

type bhGPOProps struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description,omitempty"`
	GPCFileSysPath    string `json:"gpcfilesyspath,omitempty"`
	WhenCreated       int64  `json:"whencreated"`
}

type bhTypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type bhGPOLink struct {
	GUID             string `json:"GUID"`
	IsEnforced       bool   `json:"IsEnforced"`
}

type bhSessionResult struct {
	Results   []interface{} `json:"Results"`
	Collected bool          `json:"Collected"`
}

type bhLocalGroupResult struct {
	Results   []interface{} `json:"Results"`
	Collected bool          `json:"Collected"`
}

type bhOutput struct {
	Computers bhFile `json:"computers"`
	Users     bhFile `json:"users"`
	Groups    bhFile `json:"groups"`
	Domains   bhFile `json:"domains"`
	OUs       bhFile `json:"ous"`
	GPOs      bhFile `json:"gpos"`
	Summary   bhSummary `json:"summary"`
}

type bhSummary struct {
	Domain     string `json:"domain"`
	DomainSID  string `json:"domain_sid"`
	Users      int    `json:"users"`
	Computers  int    `json:"computers"`
	Groups     int    `json:"groups"`
	OUs        int    `json:"ous"`
	GPOs       int    `json:"gpos"`
	Trusts     int    `json:"trusts"`
}

// ldapQueryBloodHound collects comprehensive AD data and formats it
// as BloodHound CE v6 JSON for graph analysis.
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
	// Read domain object
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

	// Collect trusts
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

// bhResolveGroupMembers resolves the temporary DN-based member references
// in group objects to SID-based ObjectIdentifiers.
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

// --- Helpers ---

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

// bhParseFileTime converts Windows FILETIME (100-ns intervals since 1601-01-01) to Unix seconds.
func bhParseFileTime(s string) int64 {
	if s == "" || s == "0" {
		return 0
	}
	ft, err := strconv.ParseInt(s, 10, 64)
	if err != nil || ft <= 0 {
		return 0
	}
	// FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
	// Difference: 11644473600 seconds = 116444736000000000 100-ns intervals
	const epochDiff = 116444736000000000
	if ft < epochDiff {
		return 0
	}
	return (ft - epochDiff) / 10000000
}

// bhParseADTime parses AD generalized time format "20060102150405.0Z" to Unix seconds.
func bhParseADTime(s string) int64 {
	if s == "" {
		return 0
	}
	// AD format: "20060102150405.0Z" or "20060102150405Z"
	s = strings.TrimSuffix(s, "Z")
	s = strings.TrimSuffix(s, ".0")
	if len(s) < 14 {
		return 0
	}
	// Parse manually: YYYYMMDDHHMMSS
	year, _ := strconv.Atoi(s[0:4])
	month, _ := strconv.Atoi(s[4:6])
	day, _ := strconv.Atoi(s[6:8])
	hour, _ := strconv.Atoi(s[8:10])
	min, _ := strconv.Atoi(s[10:12])
	sec, _ := strconv.Atoi(s[12:14])
	if year == 0 || month == 0 || day == 0 {
		return 0
	}
	// Build Unix timestamp via date arithmetic
	// Use a simplified Julian day calculation
	return bhDateToUnix(year, month, day, hour, min, sec)
}

func bhDateToUnix(year, month, day, hour, min, sec int) int64 {
	// Days from year 0 to given date, then subtract Unix epoch days
	if month <= 2 {
		year--
		month += 12
	}
	days := 365*year + year/4 - year/100 + year/400 + (153*(month-3)+2)/5 + day - 719469
	return int64(days)*86400 + int64(hour)*3600 + int64(min)*60 + int64(sec)
}

// bhParseGPLink parses AD gpLink format "[LDAP://cn={GUID},cn=policies,...;0]..."
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

		// Extract GUID from the LDAP path
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
