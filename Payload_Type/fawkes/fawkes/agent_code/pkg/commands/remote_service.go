package commands

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	svcctl "github.com/oiweiwei/go-msrpc/msrpc/scmr/svcctl/v2"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

// SCM access rights
const (
	scManagerConnect         = 0x0001
	scManagerEnumerateService = 0x0004
	scManagerCreateService   = 0x0002
	scManagerAllAccess       = 0xF003F
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

func (c *RemoteServiceCommand) Execute(task structs.Task) structs.CommandResult {
	var args remoteServiceArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" || args.Server == "" {
		return structs.CommandResult{
			Output: "Usage: remote-service -action <list|query|create|start|stop|delete> -server <host> [options]\n\n" +
				"Actions:\n" +
				"  list   — Enumerate all services\n" +
				"  query  — Query a specific service's config and status\n" +
				"  create — Create a new service\n" +
				"  start  — Start a service\n" +
				"  stop   — Stop a service\n" +
				"  delete — Delete a service\n\n" +
				"Options:\n" +
				"  -server       Target host (required)\n" +
				"  -name         Service name (required for query/create/start/stop/delete)\n" +
				"  -display_name Display name (for create)\n" +
				"  -binpath      Binary path (required for create)\n" +
				"  -start_type   Start type: auto, demand, disabled (default: demand)\n" +
				"  -username     Username for authentication\n" +
				"  -password     Password for authentication\n" +
				"  -hash         NTLM hash for pass-the-hash (LM:NT or just NT)\n" +
				"  -domain       Domain for authentication\n" +
				"  -timeout      Timeout in seconds (default: 30)\n",
			Status:    "success",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return remoteSvcList(args)
	case "query":
		return remoteSvcQuery(args)
	case "create":
		return remoteSvcCreate(args)
	case "start":
		return remoteSvcStart(args)
	case "stop":
		return remoteSvcStop(args)
	case "delete":
		return remoteSvcDelete(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: list, query, create, start, stop, delete", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// remoteSvcConnect establishes a DCE-RPC connection to the remote SVCCTL service
// and opens the SCM. Returns the client, SCM handle, context, cancel func, and cleanup func.
func remoteSvcConnect(args remoteServiceArgs, desiredAccess uint32) (svcctl.SvcctlClient, *svcctl.Handle, context.Context, context.CancelFunc, func(), error) {
	credUser := args.Username
	if args.Domain != "" {
		credUser = args.Domain + `\` + args.Username
	}

	var cred sspcred.Credential
	if args.Hash != "" {
		hash := args.Hash
		if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			hash = parts[1]
		}
		cred = sspcred.NewFromNTHash(credUser, hash)
	} else if args.Password != "" {
		cred = sspcred.NewFromPassword(credUser, args.Password)
	} else {
		return nil, nil, nil, nil, nil, fmt.Errorf("either -password or -hash is required for remote service access")
	}

	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), time.Duration(args.Timeout)*time.Second)

	cc, err := dcerpc.Dial(ctx, args.Server,
		dcerpc.WithEndpoint("ncacn_np:[ntsvcs]"),
		dcerpc.WithCredentials(cred),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("DCE-RPC connection failed: %v", err)
	}

	cli, err := svcctl.NewSvcctlClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(args.Server))
	if err != nil {
		cc.Close(ctx)
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to create SVCCTL client: %v", err)
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
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open SCM: %v", err)
	}
	if scmResp.Return != 0 {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("OpenSCManagerW error: 0x%08x", scmResp.Return)
	}

	return cli, scmResp.SCM, ctx, cancel, cleanup, nil
}

func remoteSvcList(args remoteServiceArgs) structs.CommandResult {
	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect|scManagerEnumerateService)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	// First call to get required buffer size
	resp, err := cli.EnumServicesStatusW(ctx, &svcctl.EnumServicesStatusWRequest{
		ServiceManager: scm,
		ServiceType:    svcWin32,
		ServiceState:   svcStateAll,
		BufferLength:   0,
	})
	if err != nil && resp == nil {
		return structs.CommandResult{Output: fmt.Sprintf("EnumServicesStatusW failed: %v", err), Status: "error", Completed: true}
	}

	needed := resp.BytesNeededLength
	if needed == 0 {
		return structs.CommandResult{Output: "No services found", Status: "success", Completed: true}
	}

	// Second call with proper buffer size
	resp, err = cli.EnumServicesStatusW(ctx, &svcctl.EnumServicesStatusWRequest{
		ServiceManager: scm,
		ServiceType:    svcWin32,
		ServiceState:   svcStateAll,
		BufferLength:   needed,
	})
	if err != nil && resp == nil {
		return structs.CommandResult{Output: fmt.Sprintf("EnumServicesStatusW failed: %v", err), Status: "error", Completed: true}
	}
	if resp.Return != 0 && resp.ServicesReturned == 0 {
		return structs.CommandResult{Output: fmt.Sprintf("EnumServicesStatusW error: 0x%08x", resp.Return), Status: "error", Completed: true}
	}

	services := parseEnumServiceStatusW(resp.Buffer, resp.ServicesReturned)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Services on %s (%d total):\n\n", args.Server, len(services)))
	sb.WriteString(fmt.Sprintf("%-40s %-8s %s\n", "SERVICE NAME", "STATE", "DISPLAY NAME"))
	sb.WriteString(strings.Repeat("-", 90) + "\n")

	for _, svc := range services {
		sb.WriteString(fmt.Sprintf("%-40s %-8s %s\n",
			truncateStr(svc.serviceName, 39),
			remoteSvcStateName(svc.currentState),
			svc.displayName,
		))
	}

	return structs.CommandResult{Output: sb.String(), Status: "success", Completed: true}
}

func remoteSvcQuery(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for query action", Status: "error", Completed: true}
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcQueryConfig | svcQueryStatus,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Failed to open service %q: %v", args.Name, err), Status: "error", Completed: true}
	}
	if svcResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("OpenServiceW error for %q: 0x%08x", args.Name, svcResp.Return), Status: "error", Completed: true}
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	// Query config
	cfgResp, err := cli.QueryServiceConfigW(ctx, &svcctl.QueryServiceConfigWRequest{
		Service:      svcResp.Service,
		BufferLength: 8192,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("QueryServiceConfigW failed: %v", err), Status: "error", Completed: true}
	}

	// Query status
	statusResp, err := cli.QueryServiceStatus(ctx, &svcctl.QueryServiceStatusRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("QueryServiceStatus failed: %v", err), Status: "error", Completed: true}
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Service: %s\n", args.Name))
	sb.WriteString(fmt.Sprintf("  Display Name : %s\n", cfgResp.ServiceConfig.DisplayName))
	sb.WriteString(fmt.Sprintf("  Binary Path  : %s\n", cfgResp.ServiceConfig.BinaryPathName))
	sb.WriteString(fmt.Sprintf("  Service Type : %s\n", remoteSvcTypeName(cfgResp.ServiceConfig.ServiceType)))
	sb.WriteString(fmt.Sprintf("  Start Type   : %s\n", remoteSvcStartTypeName(cfgResp.ServiceConfig.StartType)))
	sb.WriteString(fmt.Sprintf("  Run As       : %s\n", cfgResp.ServiceConfig.ServiceStartName))
	if cfgResp.ServiceConfig.Dependencies != "" {
		sb.WriteString(fmt.Sprintf("  Dependencies : %s\n", cfgResp.ServiceConfig.Dependencies))
	}
	sb.WriteString(fmt.Sprintf("  State        : %s\n", remoteSvcStateName(statusResp.ServiceStatus.CurrentState)))

	return structs.CommandResult{Output: sb.String(), Status: "success", Completed: true}
}

func remoteSvcCreate(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for create action", Status: "error", Completed: true}
	}
	if args.BinPath == "" {
		return structs.CommandResult{Output: "Error: -binpath is required for create action", Status: "error", Completed: true}
	}

	startType := parseStartType(args.StartType)
	displayName := args.DisplayName
	if displayName == "" {
		displayName = args.Name
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerCreateService)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
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
		StartType:      startType,
		ErrorControl:   1, // SERVICE_ERROR_NORMAL
		BinaryPathName: args.BinPath,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("CreateServiceW failed: %v", err), Status: "error", Completed: true}
	}
	if createResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("CreateServiceW error: 0x%08x", createResp.Return), Status: "error", Completed: true}
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: createResp.Service}) }()

	return structs.CommandResult{
		Output:    fmt.Sprintf("Service %q created on %s\n  Binary: %s\n  Start Type: %s", args.Name, args.Server, args.BinPath, remoteSvcStartTypeName(startType)),
		Status:    "success",
		Completed: true,
	}
}

func remoteSvcStart(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for start action", Status: "error", Completed: true}
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcStart | svcQueryStatus,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Failed to open service %q: %v", args.Name, err), Status: "error", Completed: true}
	}
	if svcResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("OpenServiceW error: 0x%08x", svcResp.Return), Status: "error", Completed: true}
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	startResp, err := cli.StartServiceW(ctx, &svcctl.StartServiceWRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("StartServiceW failed: %v", err), Status: "error", Completed: true}
	}
	if startResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("StartServiceW error: 0x%08x", startResp.Return), Status: "error", Completed: true}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Service %q started on %s", args.Name, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func remoteSvcStop(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for stop action", Status: "error", Completed: true}
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcStop | svcQueryStatus,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Failed to open service %q: %v", args.Name, err), Status: "error", Completed: true}
	}
	if svcResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("OpenServiceW error: 0x%08x", svcResp.Return), Status: "error", Completed: true}
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	ctrlResp, err := cli.ControlService(ctx, &svcctl.ControlServiceRequest{
		Service: svcResp.Service,
		Control: svcControlStop,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("ControlService(STOP) failed: %v", err), Status: "error", Completed: true}
	}
	if ctrlResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("ControlService(STOP) error: 0x%08x", ctrlResp.Return), Status: "error", Completed: true}
	}

	state := remoteSvcStateName(ctrlResp.ServiceStatus.CurrentState)
	return structs.CommandResult{
		Output:    fmt.Sprintf("Service %q stop requested on %s (current state: %s)", args.Name, args.Server, state),
		Status:    "success",
		Completed: true,
	}
}

func remoteSvcDelete(args remoteServiceArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for delete action", Status: "error", Completed: true}
	}

	cli, scm, ctx, cancel, cleanup, err := remoteSvcConnect(args, scManagerConnect)
	if err != nil {
		return structs.CommandResult{Output: err.Error(), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: scm}) }()

	svcResp, err := cli.OpenServiceW(ctx, &svcctl.OpenServiceWRequest{
		ServiceManager: scm,
		ServiceName:    args.Name,
		DesiredAccess:  svcDelete,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Failed to open service %q: %v", args.Name, err), Status: "error", Completed: true}
	}
	if svcResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("OpenServiceW error: 0x%08x", svcResp.Return), Status: "error", Completed: true}
	}
	defer func() { _, _ = cli.CloseService(ctx, &svcctl.CloseServiceRequest{ServiceObject: svcResp.Service}) }()

	delResp, err := cli.DeleteService(ctx, &svcctl.DeleteServiceRequest{
		Service: svcResp.Service,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("DeleteService failed: %v", err), Status: "error", Completed: true}
	}
	if delResp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("DeleteService error: 0x%08x", delResp.Return), Status: "error", Completed: true}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Service %q marked for deletion on %s", args.Name, args.Server),
		Status:    "success",
		Completed: true,
	}
}

// parsedService holds parsed enum results
type parsedService struct {
	serviceName  string
	displayName  string
	serviceType  uint32
	currentState uint32
}

// parseEnumServiceStatusW parses the raw buffer from EnumServicesStatusW.
// Each ENUM_SERVICE_STATUSW entry is:
//   - 4 bytes: lpServiceName (pointer/offset into buffer)
//   - 4 bytes: lpDisplayName (pointer/offset into buffer)
//   - 7 x 4 bytes: SERVICE_STATUS (dwServiceType, dwCurrentState, dwControlsAccepted,
//     dwWin32ExitCode, dwServiceSpecificExitCode, dwCheckPoint, dwWaitHint)
//
// Total: 36 bytes per entry (on wire, pointers are 4 bytes each)
func parseEnumServiceStatusW(buf []byte, count uint32) []parsedService {
	// The RPC response uses a different layout than in-memory ENUM_SERVICE_STATUSW.
	// The buffer contains the SERVICE_STATUS structs followed by the string data.
	// Each entry in the buffer is:
	//   offset 0: service name offset (4 bytes, relative to buffer start)
	//   offset 4: display name offset (4 bytes, relative to buffer start)
	//   offset 8: ServiceStatus (7 x 4 = 28 bytes)
	// Total entry size: 36 bytes
	const entrySize = 36
	var services []parsedService

	for i := uint32(0); i < count; i++ {
		offset := i * entrySize
		if int(offset+entrySize) > len(buf) {
			break
		}

		svcNameOff := binary.LittleEndian.Uint32(buf[offset:])
		dispNameOff := binary.LittleEndian.Uint32(buf[offset+4:])
		svcType := binary.LittleEndian.Uint32(buf[offset+8:])
		curState := binary.LittleEndian.Uint32(buf[offset+12:])

		svcName := readUTF16StringFromBuf(buf, svcNameOff)
		dispName := readUTF16StringFromBuf(buf, dispNameOff)

		services = append(services, parsedService{
			serviceName:  svcName,
			displayName:  dispName,
			serviceType:  svcType,
			currentState: curState,
		})
	}

	return services
}

// readUTF16StringFromBuf reads a null-terminated UTF-16LE string from buf at the given byte offset.
func readUTF16StringFromBuf(buf []byte, offset uint32) string {
	if int(offset) >= len(buf) {
		return ""
	}
	var runes []uint16
	for i := int(offset); i+1 < len(buf); i += 2 {
		ch := binary.LittleEndian.Uint16(buf[i:])
		if ch == 0 {
			break
		}
		runes = append(runes, ch)
	}
	return string(utf16.Decode(runes))
}

func remoteSvcStateName(state uint32) string {
	switch state {
	case svcStateStopped:
		return "STOPPED"
	case svcStateStartPending:
		return "START_PENDING"
	case svcStateStopPending:
		return "STOP_PENDING"
	case svcStateRunning:
		return "RUNNING"
	case svcStateContinuePending:
		return "CONTINUE_PENDING"
	case svcStatePausePending:
		return "PAUSE_PENDING"
	case svcStatePaused:
		return "PAUSED"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

func remoteSvcTypeName(t uint32) string {
	switch {
	case t&svcWin32OwnProcess != 0 && t&svcWin32ShareProcess != 0:
		return "WIN32_OWN_PROCESS | WIN32_SHARE_PROCESS"
	case t&svcWin32OwnProcess != 0:
		return "WIN32_OWN_PROCESS"
	case t&svcWin32ShareProcess != 0:
		return "WIN32_SHARE_PROCESS"
	case t == 1:
		return "KERNEL_DRIVER"
	case t == 2:
		return "FILE_SYSTEM_DRIVER"
	default:
		return fmt.Sprintf("TYPE(0x%x)", t)
	}
}

func remoteSvcStartTypeName(t uint32) string {
	switch t {
	case svcStartBoot:
		return "BOOT_START"
	case svcStartSystem:
		return "SYSTEM_START"
	case svcStartAuto:
		return "AUTO_START"
	case svcStartDemand:
		return "DEMAND_START"
	case svcStartDisabled:
		return "DISABLED"
	default:
		return fmt.Sprintf("START_TYPE(%d)", t)
	}
}

func parseStartType(s string) uint32 {
	switch strings.ToLower(s) {
	case "auto":
		return svcStartAuto
	case "disabled":
		return svcStartDisabled
	case "demand", "manual", "":
		return svcStartDemand
	default:
		return svcStartDemand
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-1] + "…"
}
