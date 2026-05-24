package commands

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
