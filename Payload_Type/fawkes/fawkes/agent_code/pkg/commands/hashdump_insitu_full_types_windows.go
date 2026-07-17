//go:build windows
// +build windows

package commands

// Report types for hashdump in-situ full output (Phase 2B/2C JSON projection).

// insituFullNodeReport is the JSON-shaped record for a single walked
// LogonSessionList node, with Phase 2C-i structured fields layered on top
// of the Phase 2B walk metadata.
type insituFullNodeReport struct {
	Address          string                       `json:"address"`
	Flink            string                       `json:"flink"`
	Blink            string                       `json:"blink"`
	ParsedLUID       string                       `json:"parsed_luid,omitempty"`
	ParsedUserName   string                       `json:"parsed_username,omitempty"`
	ParsedDomain     string                       `json:"parsed_domain,omitempty"`
	ParsedAuthPkg    string                       `json:"parsed_auth_package,omitempty"`
	ParsedLogonType  string                       `json:"parsed_logon_type,omitempty"`
	ParsedLogonSrv   string                       `json:"parsed_logon_server,omitempty"`
	CredentialsPtr   string                       `json:"credentials_ptr,omitempty"`
	Phase1Match      bool                         `json:"phase1_luid_match"`
	Phase1Source     string                       `json:"phase1_match_source,omitempty"`
	MatchedUsers     []string                     `json:"matched_users,omitempty"`
	ParseErrors      []string                     `json:"parse_errors,omitempty"`
	RawPreviewHex    string                       `json:"raw_preview_hex"`
	Credentials      []insituFullCredentialReport `json:"credentials,omitempty"`
	CredentialWalkErr string                      `json:"credential_walk_err,omitempty"`
}

// insituFullCredentialReport is the JSON projection of a single
// KIWI_MSV1_0_CREDENTIAL_LIST entry walked from a session's credentials_ptr
// (Phase 2C-ii-a).
type insituFullCredentialReport struct {
	Address             string                             `json:"address"`
	AuthPackageId       uint32                             `json:"auth_package_id"`
	AuthPackage         string                             `json:"auth_package"`
	RawHex              string                             `json:"raw_hex,omitempty"`
	PrimaryCredsAddr    string                             `json:"primary_credentials_address,omitempty"`
	ParsedUserName      string                             `json:"parsed_username,omitempty"`
	ParsedDomain        string                             `json:"parsed_domain,omitempty"`
	EncryptedAddress    string                             `json:"encrypted_address,omitempty"`
	EncryptedLength     uint16                             `json:"encrypted_length,omitempty"`
	EncryptedHexPreview string                             `json:"encrypted_hex_preview,omitempty"`
	ParseErrors         []string                           `json:"parse_errors,omitempty"`
	PrimaryReadErr      string                             `json:"primary_read_err,omitempty"`
	Decrypted           *insituFullDecryptedReport         `json:"decrypted,omitempty"`
	DecryptErr          string                             `json:"decrypt_err,omitempty"`
	AdditionalEntries   []insituFullPrimaryCredEntryReport `json:"additional_entries,omitempty"`
}

// insituFullPrimaryCredEntryReport is a single entry from the inner
// PRIMARY_CREDENTIALS chain (entries beyond the first are reported here).
type insituFullPrimaryCredEntryReport struct {
	CredentialName      string                     `json:"credential_name"`
	EncryptedAddress    string                     `json:"encrypted_address,omitempty"`
	EncryptedLength     uint16                     `json:"encrypted_length,omitempty"`
	Decrypted           *insituFullDecryptedReport `json:"decrypted,omitempty"`
	DecryptErr          string                     `json:"decrypt_err,omitempty"`
}

// insituFullDecryptedReport is the JSON projection of a successfully
// decrypted-and-parsed credential blob (Phase 2C-ii-c).
type insituFullDecryptedReport struct {
	Algorithm        string `json:"algorithm"`
	PlaintextLength  int    `json:"plaintext_length"`
	CredentialName   string `json:"credential_name,omitempty"`
	Layout           string `json:"layout,omitempty"`
	IsIso            bool   `json:"is_iso,omitempty"`
	IsNtOwfPassword  bool   `json:"is_nt_owf_password,omitempty"`
	IsLmOwfPassword  bool   `json:"is_lm_owf_password,omitempty"`
	IsShaOwPassword  bool   `json:"is_sha_owf_password,omitempty"`
	NtHashHex        string `json:"nt_hash_hex,omitempty"`
	LmHashHex        string `json:"lm_hash_hex,omitempty"`
	ShaHashHex       string `json:"sha_hash_hex,omitempty"`
	DumpLine         string `json:"dump_line,omitempty"`
	HeaderUserNameLength    uint16 `json:"header_username_length,omitempty"`
	HeaderUserNameMaxLen    uint16 `json:"header_username_max_length,omitempty"`
	HeaderLogonDomainLength uint16 `json:"header_logon_domain_length,omitempty"`
	HeaderLogonDomainMaxLen uint16 `json:"header_logon_domain_max_length,omitempty"`
	ParseErr                string `json:"parse_err,omitempty"`

	KerberosKeys      []insituFullKerbKeyReport `json:"kerberos_keys,omitempty"`
	PlaintextPassword string                    `json:"plaintext_password,omitempty"`
	PlaintextDomain   string                    `json:"plaintext_domain,omitempty"`
	PlaintextUser     string                    `json:"plaintext_user,omitempty"`
}

// insituFullKerbKeyReport is a single extracted Kerberos key.
type insituFullKerbKeyReport struct {
	EncType string `json:"enc_type"`
	KeyHex  string `json:"key_hex"`
}

// insituFullSummary captures the top-level metadata of a hashdump in-situ
// full run.
type insituFullSummary struct {
	Phase1SessionCount       int                    `json:"phase1_session_count"`
	LsassProtection          *insituFullProtectionReport `json:"lsass_protection,omitempty"`
	LSASSPID                 uint32                 `json:"lsass_pid"`
	LsasrvBase               string                 `json:"lsasrv_base"`
	LsasrvSize               uint32                 `json:"lsasrv_size"`
	AnchorAddr               string                 `json:"logon_session_list_anchor"`
	StructLayout             string                 `json:"struct_layout"`
	CryptoLayout             string                 `json:"crypto_layout,omitempty"`
	PrimaryCredentialLayout  string                 `json:"primary_credential_layout,omitempty"`
	LsaCrypto                *insituFullCryptoReport `json:"lsa_crypto,omitempty"`
	LsaCryptoErr             string                 `json:"lsa_crypto_err,omitempty"`
	NodesWalked              int                    `json:"nodes_walked"`
	NodesMatched             int                    `json:"nodes_matched_to_phase1"`
	NodesStructParsed        int                    `json:"nodes_with_structured_luid"`
	NodesWithCredentials     int                    `json:"nodes_with_credential_list"`
	CredentialBlobsCaptured  int                    `json:"credential_blobs_captured"`
	CredentialBlobsDecrypted int                    `json:"credential_blobs_decrypted"`
	HashesExtracted          int                    `json:"hashes_extracted"`
	KerberosKeysExtracted    int                    `json:"kerberos_keys_extracted,omitempty"`
	PlaintextCredsExtracted  int                    `json:"plaintext_creds_extracted,omitempty"`
	UnmatchedLUIDs           []string               `json:"phase1_luids_not_seen_in_walk,omitempty"`
	Nodes                    []insituFullNodeReport `json:"nodes"`
}

// insituFullProtectionReport is the JSON projection of the LSA protection
// state read from the registry.
type insituFullProtectionReport struct {
	RunAsPPL                 string `json:"run_as_ppl"`
	RunAsPPLDetected         bool   `json:"run_as_ppl_detected"`
	RunAsPPLValue            uint32 `json:"run_as_ppl_value"`
	LsaCfgFlags              string `json:"lsa_cfg_flags"`
	LsaCfgFlagsDetected      bool   `json:"lsa_cfg_flags_detected"`
	LsaCfgFlagsValue         uint32 `json:"lsa_cfg_flags_value"`
	PPLActive                bool   `json:"ppl_active"`
	CredentialGuardActive    bool   `json:"credential_guard_active"`
	Summary                  string `json:"summary"`
	RegistryError            string `json:"registry_error,omitempty"`
}

func newProtectionReport(s LsassProtectionState) *insituFullProtectionReport {
	return &insituFullProtectionReport{
		RunAsPPL:              s.RunAsPPLLabel(),
		RunAsPPLDetected:      s.RunAsPPLDetected,
		RunAsPPLValue:         s.RunAsPPL,
		LsaCfgFlags:           s.LsaCfgFlagsLabel(),
		LsaCfgFlagsDetected:   s.LsaCfgFlagsDetected,
		LsaCfgFlagsValue:      s.LsaCfgFlags,
		PPLActive:             s.PPLActive(),
		CredentialGuardActive: s.CredentialGuardActive(),
		Summary:               s.Summary(),
		RegistryError:         s.Error,
	}
}

// insituFullCryptoReport is the JSON projection of the Phase 2C-ii-b key
// extraction.
type insituFullCryptoReport struct {
	IVAddress   string `json:"iv_address"`
	IVHex       string `json:"iv_hex,omitempty"`
	IVErr       string `json:"iv_err,omitempty"`
	H3DesGlobal string `json:"h3deskey_global"`
	H3DesKey    *insituFullBcryptKeyReport `json:"h3deskey,omitempty"`
	H3DesErr    string `json:"h3deskey_err,omitempty"`
	HAesGlobal  string `json:"haeskey_global"`
	HAesKey     *insituFullBcryptKeyReport `json:"haeskey,omitempty"`
	HAesErr     string `json:"haeskey_err,omitempty"`
}

// insituFullBcryptKeyReport is the JSON projection of one resolved BCrypt
// key (h3DesKey or hAesKey).
type insituFullBcryptKeyReport struct {
	HandleAddress  string `json:"handle_address"`
	HandleSize     uint32 `json:"handle_size"`
	HandleTag      string `json:"handle_tag"`
	HandleTagValid bool   `json:"handle_tag_valid"`
	HAlgorithm     string `json:"h_algorithm,omitempty"`
	KeyAddress     string `json:"key_address"`
	KeySize        uint32 `json:"key_size"`
	KeyTag         string `json:"key_tag"`
	KeyTagValid    bool   `json:"key_tag_valid"`
	KeyType        uint32 `json:"key_type"`
	KeyBits        uint32 `json:"key_bits"`
	CbSecret       uint32 `json:"cb_secret"`
	KeyHex         string `json:"key_hex,omitempty"`
}
