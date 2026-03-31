package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
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
		h := hash
		if parts := strings.SplitN(h, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			h = parts[1]
		}
		return sspcred.NewFromNTHash(credUser, h), nil
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
