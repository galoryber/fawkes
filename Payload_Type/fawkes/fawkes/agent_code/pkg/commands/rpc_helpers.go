package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"github.com/oiweiwei/go-msrpc/ssp/krb5"
	krbconfig "github.com/oiweiwei/gokrb5.fork/v9/config"
)

// rpcCredential creates a go-msrpc credential from username, domain, password, and/or hash.
// It handles domain\user formatting and LM:NT hash parsing.
// Callers should ZeroString their own password/hash args after calling this.
func rpcCredential(username, domain, password, hash string) (sspcred.Credential, error) {
	credUser := username
	if domain != "" {
		credUser = domain + `\` + username
	}

	if hash != "" {
		return sspcred.NewFromNTHash(credUser, stripLMPrefix(hash)), nil
	}
	if password != "" {
		return sspcred.NewFromPassword(credUser, password), nil
	}
	return nil, fmt.Errorf("either -password or -hash is required")
}

// rpcSecurityContext creates a GSSAPI security context with SPNEGO and NTLM
// mechanisms and the given timeout. This is the standard context for DCE-RPC
// connections using named pipes or TCP.
func rpcSecurityContext(cred sspcred.Credential, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), timeout)
}

// rpcKerberosConfig builds a go-msrpc KRB5 security config for DCE-RPC
// Kerberos authentication. The domain is uppercased to form the Kerberos realm.
// kdcAddr is typically the DC IP address.
func rpcKerberosConfig(cred sspcred.Credential, domain, kdcAddr string) *krb5.Config {
	realm := strings.ToUpper(domain)

	kc := krbconfig.New()
	kc.LibDefaults.DefaultRealm = realm
	kc.LibDefaults.DNSLookupKDC = false
	kc.LibDefaults.DNSLookupRealm = false
	kc.LibDefaults.UDPPreferenceLimit = 1
	kc.LibDefaults.AllowWeakCrypto = true
	kc.LibDefaults.DefaultTGSEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	kc.LibDefaults.DefaultTktEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	kc.LibDefaults.PermittedEnctypes = []string{"aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "rc4-hmac"}
	kc.Realms = []krbconfig.Realm{{
		Realm:       realm,
		KDC:         []string{kdcAddr + ":88"},
		AdminServer: []string{kdcAddr + ":749"},
	}}
	lowDomain := strings.ToLower(domain)
	kc.DomainRealm = krbconfig.DomainRealm{
		lowDomain:       realm,
		"." + lowDomain: realm,
	}

	return &krb5.Config{
		Credential:         cred,
		KRB5Config:         krb5.ParsedLibDefaults(kc),
		DCEStyle:           true,
		DisablePAFXFAST:    true,
		AnyServiceClassSPN: true,
	}
}

// rpcKerberosCredential creates a credential with the realm (uppercase domain)
// as the domain prefix, which is required for Kerberos authentication.
func rpcKerberosCredential(username, domain, password, hash string) (sspcred.Credential, error) {
	realm := strings.ToUpper(domain)
	credUser := realm + `\` + username

	if hash != "" {
		return sspcred.NewFromNTHash(credUser, stripLMPrefix(hash)), nil
	}
	if password != "" {
		return sspcred.NewFromPassword(credUser, password), nil
	}
	return nil, fmt.Errorf("either -password or -hash is required")
}

func ensureKRB5Mechanism() {
	func() { defer func() { _ = recover() }(); gssapi.AddMechanism(ssp.KRB5) }()
}

func ensureSPNEGOMechanism() {
	func() { defer func() { _ = recover() }(); gssapi.AddMechanism(ssp.SPNEGO) }()
}

func ensureNTLMMechanism() {
	func() { defer func() { _ = recover() }(); gssapi.AddMechanism(ssp.NTLM) }()
}
