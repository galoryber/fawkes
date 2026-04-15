package commands

import (
	"context"
	"fmt"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	"github.com/oiweiwei/go-msrpc/ssp"

	_ "github.com/oiweiwei/go-msrpc/msrpc/erref/win32"
)

type RemoteRegCommand struct{}

func (c *RemoteRegCommand) Name() string { return "remote-reg" }
func (c *RemoteRegCommand) Description() string {
	return "Read/write registry keys on remote Windows hosts via WinReg RPC"
}

type remoteRegArgs struct {
	Action   string `json:"action"`
	Server   string `json:"server"`
	Hive     string `json:"hive"`
	Path     string `json:"path"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	RegType  string `json:"reg_type"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	Timeout  int    `json:"timeout"`
}

func (c *RemoteRegCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[remoteRegArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	defer structs.ZeroString(&args.Password)
	defer structs.ZeroString(&args.Hash)

	if args.Action == "" || args.Server == "" {
		return successResult("Usage: remote-reg -action <query|set|enum|delete> -server <host> [options]\n\n" +
			"Actions:\n" +
			"  query  — Read a registry value\n" +
			"  enum   — List subkeys and values under a key\n" +
			"  set    — Write a registry value\n" +
			"  delete — Delete a registry key or value\n\n" +
			"Options:\n" +
			"  -server   Target host (required)\n" +
			"  -hive     Registry hive: HKLM, HKCU, HKU, HKCR (default: HKLM)\n" +
			"  -path     Registry key path (e.g., SOFTWARE\\Microsoft\\Windows)\n" +
			"  -name     Value name (for query/set/delete value)\n" +
			"  -data     Value data (for set)\n" +
			"  -reg_type Value type: REG_SZ, REG_DWORD, REG_BINARY, REG_QWORD, REG_EXPAND_SZ (for set)\n" +
			"  -username Username for authentication\n" +
			"  -password Password for authentication\n" +
			"  -hash     NTLM hash for pass-the-hash (LM:NT or just NT)\n" +
			"  -domain   Domain for authentication\n" +
			"  -timeout  Timeout in seconds (default: 30)\n")
	}

	if args.Hive == "" {
		args.Hive = "HKLM"
	}
	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	switch strings.ToLower(args.Action) {
	case "query":
		return remoteRegQuery(args)
	case "enum":
		return remoteRegEnum(args)
	case "set":
		return remoteRegSet(args)
	case "delete":
		return remoteRegDelete(args)
	default:
		return errorf("Unknown action: %s\nAvailable: query, enum, set, delete", args.Action)
	}
}

// remoteRegConnect establishes a DCE-RPC connection to the remote winreg service
// and opens the specified hive. Returns the client, hive key handle, context, and cancel func.
func remoteRegConnect(args remoteRegArgs) (winreg.WinregClient, *winreg.Key, context.Context, context.CancelFunc, func(), error) {
	cred, credErr := rpcCredential(args.Username, args.Domain, args.Password, args.Hash)
	structs.ZeroString(&args.Password)
	structs.ZeroString(&args.Hash)
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

	hiveKey, err := openRemoteHive(ctx, cli, args.Hive)
	if err != nil {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open hive %s: %w", args.Hive, err)
	}

	return cli, hiveKey, ctx, cancel, cleanup, nil
}

func openRemoteHive(ctx context.Context, cli winreg.WinregClient, hive string) (*winreg.Key, error) {
	desiredAccess := uint32(0x02000000) // MAXIMUM_ALLOWED

	switch strings.ToUpper(hive) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		resp, err := cli.OpenLocalMachine(ctx, &winreg.OpenLocalMachineRequest{DesiredAccess: desiredAccess})
		if err != nil {
			return nil, err
		}
		if resp.Return != 0 {
			return nil, fmt.Errorf("error code 0x%08x", resp.Return)
		}
		return resp.Key, nil
	case "HKCU", "HKEY_CURRENT_USER":
		resp, err := cli.OpenCurrentUser(ctx, &winreg.OpenCurrentUserRequest{DesiredAccess: desiredAccess})
		if err != nil {
			return nil, err
		}
		if resp.Return != 0 {
			return nil, fmt.Errorf("error code 0x%08x", resp.Return)
		}
		return resp.Key, nil
	case "HKU", "HKEY_USERS":
		resp, err := cli.OpenUsers(ctx, &winreg.OpenUsersRequest{DesiredAccess: desiredAccess})
		if err != nil {
			return nil, err
		}
		if resp.Return != 0 {
			return nil, fmt.Errorf("error code 0x%08x", resp.Return)
		}
		return resp.Key, nil
	case "HKCR", "HKEY_CLASSES_ROOT":
		resp, err := cli.OpenClassesRoot(ctx, &winreg.OpenClassesRootRequest{DesiredAccess: desiredAccess})
		if err != nil {
			return nil, err
		}
		if resp.Return != 0 {
			return nil, fmt.Errorf("error code 0x%08x", resp.Return)
		}
		return resp.Key, nil
	default:
		return nil, fmt.Errorf("unsupported hive: %s (use HKLM, HKCU, HKU, or HKCR)", hive)
	}
}

func openRemoteSubKey(ctx context.Context, cli winreg.WinregClient, parentKey *winreg.Key, path string) (*winreg.Key, error) {
	if path == "" {
		return parentKey, nil
	}

	resp, err := cli.BaseRegOpenKey(ctx, &winreg.BaseRegOpenKeyRequest{
		Key:           parentKey,
		SubKey:        &winreg.UnicodeString{Buffer: path},
		DesiredAccess: 0x02000000, // MAXIMUM_ALLOWED
	})
	if err != nil {
		return nil, err
	}
	if resp.Return != 0 {
		return nil, fmt.Errorf("error code 0x%08x opening key %s", resp.Return, path)
	}
	return resp.ResultKey, nil
}
