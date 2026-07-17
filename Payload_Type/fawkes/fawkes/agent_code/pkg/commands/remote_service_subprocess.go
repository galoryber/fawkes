package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
)

type svcctlParams struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	BinPath     string `json:"binpath"`
	StartType   string `json:"start_type"`
}

type svcctlResult struct {
	Text string `json:"text"`
}

func svcctlSubprocessConnect(ctx context.Context, server string, cred sspcred.Credential, desiredAccess uint32) (svcctl.SvcctlClient, *svcctl.Handle, dcerpc.Conn, error) {
	cc, err := dcerpc.Dial(ctx, server,
		dcerpc.WithEndpoint("ncacn_np:[svcctl]"),
		dcerpc.WithCredentials(cred),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("DCE-RPC connection failed: %w", err)
	}

	cli, err := svcctl.NewSvcctlClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		cc.Close(ctx)
		return nil, nil, nil, fmt.Errorf("failed to create SVCCTL client: %w", err)
	}

	scmResp, err := cli.OpenSCMW(ctx, &svcctl.OpenSCMWRequest{
		MachineName:   server,
		DesiredAccess: desiredAccess,
	})
	if err != nil {
		cc.Close(ctx)
		return nil, nil, nil, fmt.Errorf("failed to open SCM: %w", err)
	}
	if scmResp.Return != 0 {
		cc.Close(ctx)
		return nil, nil, nil, fmt.Errorf("OpenSCManagerW error: 0x%08x", scmResp.Return)
	}

	return cli, scmResp.SCM, cc, nil
}

func rpcHelperSvcctlList(req rpcHelperRequest) (json.RawMessage, error) {
	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect|scManagerEnumerateService)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	resp, err := cli.EnumServicesStatusW(ctx, &svcctl.EnumServicesStatusWRequest{
		ServiceManager: scm,
		ServiceType:    svcWin32,
		ServiceState:   svcStateAll,
		BufferLength:   0,
	})
	if err != nil && resp == nil {
		return nil, fmt.Errorf("EnumServicesStatusW failed: %v", err)
	}

	needed := resp.BytesNeededLength
	if needed == 0 {
		result := svcctlResult{Text: "No services found"}
		out, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal result: %v", err)
		}
		return out, nil
	}

	resp, err = cli.EnumServicesStatusW(ctx, &svcctl.EnumServicesStatusWRequest{
		ServiceManager: scm,
		ServiceType:    svcWin32,
		ServiceState:   svcStateAll,
		BufferLength:   needed,
	})
	if err != nil && resp == nil {
		return nil, fmt.Errorf("EnumServicesStatusW failed: %v", err)
	}

	services := parseEnumServiceStatusW(resp.Buffer, resp.ServicesReturned)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Services on %s (%d total):\n\n", req.Server, len(services)))
	sb.WriteString(fmt.Sprintf("%-40s %-8s %s\n", "SERVICE NAME", "STATE", "DISPLAY NAME"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")
	for _, svc := range services {
		sb.WriteString(fmt.Sprintf("%-40s %-8s %s\n",
			truncateStr(svc.serviceName, 39),
			remoteSvcStateName(svc.currentState),
			svc.displayName,
		))
	}

	result := svcctlResult{Text: sb.String()}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperSvcctlQuery(req rpcHelperRequest) (json.RawMessage, error) {
	var p svcctlParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("-name is required for query")
	}

	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    p.Name,
		DesiredAccess:  svcQueryConfig | svcQueryStatus,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open service %q: %v", p.Name, err)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	cfgResp, err := cli.QueryServiceConfigW(ctx, &svcctl.QueryServiceConfigWRequest{
		Service:      svcResp.Service,
		BufferLength: 8192,
	})
	if err != nil {
		return nil, fmt.Errorf("QueryServiceConfigW failed: %v", err)
	}

	statusResp, err := cli.QueryServiceStatus(ctx, &svcctl.QueryServiceStatusRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return nil, fmt.Errorf("QueryServiceStatus failed: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service: %s\n", p.Name))
	sb.WriteString(fmt.Sprintf("  Display Name : %s\n", cfgResp.ServiceConfig.DisplayName))
	sb.WriteString(fmt.Sprintf("  Binary Path  : %s\n", cfgResp.ServiceConfig.BinaryPathName))
	sb.WriteString(fmt.Sprintf("  Service Type : %s\n", remoteSvcTypeName(cfgResp.ServiceConfig.ServiceType)))
	sb.WriteString(fmt.Sprintf("  Start Type   : %s\n", remoteSvcStartTypeName(cfgResp.ServiceConfig.StartType)))
	sb.WriteString(fmt.Sprintf("  Run As       : %s\n", cfgResp.ServiceConfig.ServiceStartName))
	if cfgResp.ServiceConfig.Dependencies != "" {
		sb.WriteString(fmt.Sprintf("  Dependencies : %s\n", cfgResp.ServiceConfig.Dependencies))
	}
	sb.WriteString(fmt.Sprintf("  State        : %s\n", remoteSvcStateName(statusResp.ServiceStatus.CurrentState)))

	result := svcctlResult{Text: sb.String()}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperSvcctlCreate(req rpcHelperRequest) (json.RawMessage, error) {
	var p svcctlParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Name == "" || p.BinPath == "" {
		return nil, fmt.Errorf("-name and -binpath required for create")
	}

	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect|scManagerCreateService)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	displayName := p.DisplayName
	if displayName == "" {
		displayName = p.Name
	}

	createResp, err := cli.CreateServiceW(ctx, &svcctl.CreateServiceWRequest{
		ServiceManager: scm,
		ServiceName:    p.Name,
		DisplayName:    displayName,
		DesiredAccess:  svcAllAccess,
		ServiceType:    svcWin32OwnProcess,
		StartType:      parseStartType(p.StartType),
		ErrorControl:   1,
		BinaryPathName: p.BinPath,
	})
	if err != nil {
		return nil, fmt.Errorf("CreateServiceW failed: %v", err)
	}
	if createResp.Return != 0 {
		return nil, fmt.Errorf("CreateServiceW error: 0x%08x", createResp.Return)
	}
	_, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: createResp.Service})

	result := svcctlResult{Text: fmt.Sprintf("Service %q created (binary: %s, start: %s)", p.Name, p.BinPath, p.StartType)}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperSvcctlStart(req rpcHelperRequest) (json.RawMessage, error) {
	var p svcctlParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("-name required for start")
	}

	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    p.Name,
		DesiredAccess:  svcStart | svcQueryStatus,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open service %q: %v", p.Name, err)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	startResp, err := cli.StartServiceW(ctx, &svcctl.StartServiceWRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return nil, fmt.Errorf("StartServiceW failed: %v", err)
	}
	if startResp.Return != 0 {
		return nil, fmt.Errorf("StartServiceW error: 0x%08x", startResp.Return)
	}

	result := svcctlResult{Text: fmt.Sprintf("Service %q started", p.Name)}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperSvcctlStop(req rpcHelperRequest) (json.RawMessage, error) {
	var p svcctlParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("-name required for stop")
	}

	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    p.Name,
		DesiredAccess:  svcStop | svcQueryStatus,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open service %q: %v", p.Name, err)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	controlResp, err := cli.ControlService(ctx, &svcctl.ControlServiceRequest{
		Service: svcResp.Service,
		Control: svcControlStop,
	})
	if err != nil {
		return nil, fmt.Errorf("ControlService(Stop) failed: %v", err)
	}
	if controlResp.Return != 0 {
		return nil, fmt.Errorf("ControlService(Stop) error: 0x%08x", controlResp.Return)
	}

	result := svcctlResult{Text: fmt.Sprintf("Service %q stopped", p.Name)}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}

func rpcHelperSvcctlDelete(req rpcHelperRequest) (json.RawMessage, error) {
	var p svcctlParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Name == "" {
		return nil, fmt.Errorf("-name required for delete")
	}

	ctx, cancel, cred, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, scm, cc, err := svcctlSubprocessConnect(ctx, req.Server, cred, scManagerConnect)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    p.Name,
		DesiredAccess:  svcDelete,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open service %q: %v", p.Name, err)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	deleteResp, err := cli.DeleteService(ctx, &svcctl.DeleteServiceRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return nil, fmt.Errorf("DeleteService failed: %v", err)
	}
	if deleteResp.Return != 0 {
		return nil, fmt.Errorf("DeleteService error: 0x%08x", deleteResp.Return)
	}

	result := svcctlResult{Text: fmt.Sprintf("Service %q deleted", p.Name)}
	out, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %v", err)
	}
	return out, nil
}
