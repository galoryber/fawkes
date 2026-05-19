package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"

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

	action := strings.ToLower(args.Action)

	opMap := map[string]string{
		"query":  "winreg-query",
		"enum":   "winreg-enum",
		"set":    "winreg-set",
		"delete": "winreg-delete",
	}
	op, ok := opMap[action]
	if !ok {
		return errorf("Unknown action: %s\nAvailable: query, enum, set, delete", args.Action)
	}

	params, _ := json.Marshal(winregParams{
		Hive:    args.Hive,
		Path:    args.Path,
		Name:    args.Name,
		Data:    args.Data,
		RegType: args.RegType,
	})

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
		return errorf("Error: %v", err)
	}

	var result winregResult
	if err := json.Unmarshal(output, &result); err != nil {
		return errorf("Error parsing result: %v", err)
	}
	return successResult(result.Text)
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
