package commands

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	"github.com/oiweiwei/go-msrpc/ssp"
	sspcred "github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

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
	var args remoteRegArgs
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
			Output: "Usage: remote-reg -action <query|set|enum|delete> -server <host> [options]\n\n" +
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
				"  -timeout  Timeout in seconds (default: 30)\n",
			Status:    "success",
			Completed: true,
		}
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
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s\nAvailable: query, enum, set, delete", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// remoteRegConnect establishes a DCE-RPC connection to the remote winreg service
// and opens the specified hive. Returns the client, hive key handle, context, and cancel func.
func remoteRegConnect(args remoteRegArgs) (winreg.WinregClient, *winreg.Key, context.Context, context.CancelFunc, func(), error) {
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
		return nil, nil, nil, nil, nil, fmt.Errorf("either -password or -hash is required for remote registry access")
	}

	ctx, cancel := context.WithTimeout(gssapi.NewSecurityContext(context.Background(),
		gssapi.WithCredential(cred),
		gssapi.WithMechanismFactory(ssp.SPNEGO),
		gssapi.WithMechanismFactory(ssp.NTLM),
	), time.Duration(args.Timeout)*time.Second)

	cc, err := dcerpc.Dial(ctx, "ncacn_ip_tcp:"+args.Server,
		epm.EndpointMapper(ctx,
			net.JoinHostPort(args.Server, "135"),
			dcerpc.WithInsecure(),
		))
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

	hiveKey, err := openRemoteHive(ctx, cli, args.Hive)
	if err != nil {
		cleanup()
		cancel()
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to open hive %s: %v", args.Hive, err)
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

func remoteRegQuery(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey})

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err), Status: "error", Completed: true}
	}
	if args.Path != "" {
		defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})
	}

	if args.Name == "" {
		return structs.CommandResult{
			Output:    "Error: -name is required for query action (use enum to list all values)",
			Status:    "error",
			Completed: true,
		}
	}

	// Query the value
	bufSize := uint32(65536)
	resp, err := cli.BaseRegQueryValue(ctx, &winreg.BaseRegQueryValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: args.Name},
		Type:       0,
		Data:       make([]byte, bufSize),
		DataLength: bufSize,
		Length:     bufSize,
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error querying value '%s': %v", args.Name, err), Status: "error", Completed: true}
	}
	if resp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("Error querying value '%s': error code 0x%08x", args.Name, resp.Return), Status: "error", Completed: true}
	}

	output := formatRemoteRegValue(args.Name, resp.Type, resp.Data[:resp.Length])
	return structs.CommandResult{
		Output:    fmt.Sprintf("Remote Registry: %s\\%s\\%s on %s\n\n%s", args.Hive, args.Path, args.Name, args.Server, output),
		Status:    "success",
		Completed: true,
	}
}

func remoteRegEnum(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey})

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err), Status: "error", Completed: true}
	}
	if args.Path != "" {
		defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})
	}

	// Get key info for buffer sizing
	infoResp, err := cli.BaseRegQueryInfoKey(ctx, &winreg.BaseRegQueryInfoKeyRequest{
		Key:      subKey,
		ClassIn:  &winreg.UnicodeString{Buffer: "", MaximumLength: 256},
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error querying key info: %v", err), Status: "error", Completed: true}
	}

	var output strings.Builder
	keyPath := args.Hive
	if args.Path != "" {
		keyPath += `\` + args.Path
	}
	output.WriteString(fmt.Sprintf("Remote Registry: %s on %s\n\n", keyPath, args.Server))

	// Enumerate subkeys
	subkeys := []string{}
	maxKeyLen := infoResp.MaxSubKeyLength + 1
	if maxKeyLen < 256 {
		maxKeyLen = 256
	}
	for i := uint32(0); ; i++ {
		enumResp, err := cli.BaseRegEnumKey(ctx, &winreg.BaseRegEnumKeyRequest{
			Key:   subKey,
			Index: i,
			NameIn: &winreg.UnicodeString{
				MaximumLength: uint16(maxKeyLen * 2),
			},
		})
		if err != nil {
			break
		}
		if enumResp.Return != 0 {
			break // ERROR_NO_MORE_ITEMS (259) or other
		}
		if enumResp.NameOut != nil {
			subkeys = append(subkeys, enumResp.NameOut.Buffer)
		}
	}

	if len(subkeys) > 0 {
		output.WriteString(fmt.Sprintf("Subkeys (%d):\n", len(subkeys)))
		for _, sk := range subkeys {
			output.WriteString(fmt.Sprintf("  %s\n", sk))
		}
		output.WriteString("\n")
	}

	// Enumerate values
	maxValNameLen := infoResp.MaxValueNameLength + 1
	if maxValNameLen < 256 {
		maxValNameLen = 256
	}
	maxValDataLen := infoResp.MaxValueLength
	if maxValDataLen < 65536 {
		maxValDataLen = 65536
	}

	valueCount := 0
	var valOutput strings.Builder
	for i := uint32(0); ; i++ {
		enumResp, err := cli.BaseRegEnumValue(ctx, &winreg.BaseRegEnumValueRequest{
			Key:   subKey,
			Index: i,
			ValueNameIn: &winreg.UnicodeString{
				MaximumLength: uint16(maxValNameLen * 2),
			},
			Data:       make([]byte, maxValDataLen),
			DataLength: maxValDataLen,
			Length:     maxValDataLen,
		})
		if err != nil {
			break
		}
		if enumResp.Return != 0 {
			break
		}

		valName := ""
		if enumResp.ValueNameOut != nil {
			valName = enumResp.ValueNameOut.Buffer
		}
		displayName := valName
		if displayName == "" {
			displayName = "(Default)"
		}

		valOutput.WriteString(fmt.Sprintf("  %-30s  %-16s  %s\n",
			displayName,
			remoteRegTypeName(enumResp.Type),
			formatRemoteRegValueShort(enumResp.Type, enumResp.Data[:enumResp.Length]),
		))
		valueCount++
	}

	if valueCount > 0 {
		output.WriteString(fmt.Sprintf("Values (%d):\n", valueCount))
		output.WriteString(valOutput.String())
	}

	if len(subkeys) == 0 && valueCount == 0 {
		output.WriteString("(empty key)")
	}

	return structs.CommandResult{
		Output:    output.String(),
		Status:    "success",
		Completed: true,
	}
}

func remoteRegSet(args remoteRegArgs) structs.CommandResult {
	if args.Name == "" {
		return structs.CommandResult{Output: "Error: -name is required for set action", Status: "error", Completed: true}
	}
	if args.RegType == "" {
		args.RegType = "REG_SZ"
	}

	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey})

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err), Status: "error", Completed: true}
	}
	if args.Path != "" {
		defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})
	}

	valType, valData, err := encodeRemoteRegValue(args.Data, args.RegType)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error encoding value: %v", err), Status: "error", Completed: true}
	}

	resp, err := cli.BaseRegSetValue(ctx, &winreg.BaseRegSetValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: args.Name},
		Type:       valType,
		Data:       valData,
		DataLength: uint32(len(valData)),
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error setting value: %v", err), Status: "error", Completed: true}
	}
	if resp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("Error setting value: error code 0x%08x", resp.Return), Status: "error", Completed: true}
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully set %s\\%s\\%s = %s (%s) on %s", args.Hive, args.Path, args.Name, args.Data, args.RegType, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func remoteRegDelete(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error: %v", err), Status: "error", Completed: true}
	}
	defer cancel()
	defer cleanup()
	defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey})

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error opening key %s\\%s: %v", args.Hive, args.Path, err), Status: "error", Completed: true}
	}
	if args.Path != "" {
		defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})
	}

	if args.Name != "" {
		// Delete a value
		resp, err := cli.BaseRegDeleteValue(ctx, &winreg.BaseRegDeleteValueRequest{
			Key:       subKey,
			ValueName: &winreg.UnicodeString{Buffer: args.Name},
		})
		if err != nil {
			return structs.CommandResult{Output: fmt.Sprintf("Error deleting value '%s': %v", args.Name, err), Status: "error", Completed: true}
		}
		if resp.Return != 0 {
			return structs.CommandResult{Output: fmt.Sprintf("Error deleting value '%s': error code 0x%08x", args.Name, resp.Return), Status: "error", Completed: true}
		}
		return structs.CommandResult{
			Output:    fmt.Sprintf("Successfully deleted value '%s' from %s\\%s on %s", args.Name, args.Hive, args.Path, args.Server),
			Status:    "success",
			Completed: true,
		}
	}

	// Delete a key (must specify path)
	if args.Path == "" {
		return structs.CommandResult{Output: "Error: -path is required for key deletion", Status: "error", Completed: true}
	}

	// Split path to get parent and leaf key
	lastSep := strings.LastIndex(args.Path, `\`)
	var parentPath, leafKey string
	if lastSep == -1 {
		parentPath = ""
		leafKey = args.Path
	} else {
		parentPath = args.Path[:lastSep]
		leafKey = args.Path[lastSep+1:]
	}

	// Need to close the subKey first since we opened it, then reopen parent
	cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})

	parentKey := hiveKey
	if parentPath != "" {
		parentKey, err = openRemoteSubKey(ctx, cli, hiveKey, parentPath)
		if err != nil {
			return structs.CommandResult{Output: fmt.Sprintf("Error opening parent key: %v", err), Status: "error", Completed: true}
		}
		defer cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: parentKey})
	}

	resp, err := cli.BaseRegDeleteKey(ctx, &winreg.BaseRegDeleteKeyRequest{
		Key:    parentKey,
		SubKey: &winreg.UnicodeString{Buffer: leafKey},
	})
	if err != nil {
		return structs.CommandResult{Output: fmt.Sprintf("Error deleting key '%s': %v", leafKey, err), Status: "error", Completed: true}
	}
	if resp.Return != 0 {
		return structs.CommandResult{Output: fmt.Sprintf("Error deleting key '%s': error code 0x%08x (key must be empty)", leafKey, resp.Return), Status: "error", Completed: true}
	}
	return structs.CommandResult{
		Output:    fmt.Sprintf("Successfully deleted key %s\\%s on %s", args.Hive, args.Path, args.Server),
		Status:    "success",
		Completed: true,
	}
}

func remoteRegTypeName(t uint32) string {
	switch t {
	case winreg.RegString:
		return "REG_SZ"
	case winreg.RegExpandString:
		return "REG_EXPAND_SZ"
	case winreg.RegBinary:
		return "REG_BINARY"
	case winreg.RegDword:
		return "REG_DWORD"
	case winreg.RegMultistring:
		return "REG_MULTI_SZ"
	case winreg.RegQword:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("TYPE(%d)", t)
	}
}

func formatRemoteRegValue(name string, valType uint32, data []byte) string {
	decoded, err := winreg.DecodeValue(valType, data)
	if err != nil {
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: (decode error: %v)\nRaw:   %s", name, remoteRegTypeName(valType), err, hex.EncodeToString(data))
	}

	typeName := remoteRegTypeName(valType)

	switch v := decoded.(type) {
	case string:
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %s", name, typeName, v)
	case uint32:
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %d (0x%X)", name, typeName, v, v)
	case uint64:
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %d (0x%X)", name, typeName, v, v)
	case []string:
		s := fmt.Sprintf("Name:  %s\nType:  %s\nValue:\n", name, typeName)
		for i, item := range v {
			s += fmt.Sprintf("  [%d] %s\n", i, item)
		}
		return s
	case []byte:
		if len(v) <= 64 {
			return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %s", name, typeName, hex.EncodeToString(v))
		}
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %s... (%d bytes)", name, typeName, hex.EncodeToString(v[:64]), len(v))
	default:
		return fmt.Sprintf("Name:  %s\nType:  %s\nValue: %v", name, typeName, v)
	}
}

func formatRemoteRegValueShort(valType uint32, data []byte) string {
	decoded, err := winreg.DecodeValue(valType, data)
	if err != nil {
		return fmt.Sprintf("(error: %v)", err)
	}

	switch v := decoded.(type) {
	case string:
		return v
	case uint32:
		return fmt.Sprintf("%d (0x%X)", v, v)
	case uint64:
		return fmt.Sprintf("%d (0x%X)", v, v)
	case []string:
		return "[" + strings.Join(v, ", ") + "]"
	case []byte:
		if len(v) <= 32 {
			return hex.EncodeToString(v)
		}
		return fmt.Sprintf("%s... (%d bytes)", hex.EncodeToString(v[:32]), len(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

func encodeRemoteRegValue(data, regType string) (uint32, []byte, error) {
	switch strings.ToUpper(regType) {
	case "REG_SZ":
		encoded, err := winreg.EncodeValue(data, winreg.RegString)
		return winreg.RegString, encoded, err
	case "REG_EXPAND_SZ":
		encoded, err := winreg.EncodeValue(data, winreg.RegExpandString)
		return winreg.RegExpandString, encoded, err
	case "REG_DWORD":
		val, err := strconv.ParseUint(data, 10, 32)
		if err != nil {
			val, err = strconv.ParseUint(strings.TrimPrefix(data, "0x"), 16, 32)
			if err != nil {
				return 0, nil, fmt.Errorf("invalid DWORD value '%s'", data)
			}
		}
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(val))
		return winreg.RegDword, b, nil
	case "REG_QWORD":
		val, err := strconv.ParseUint(data, 10, 64)
		if err != nil {
			val, err = strconv.ParseUint(strings.TrimPrefix(data, "0x"), 16, 64)
			if err != nil {
				return 0, nil, fmt.Errorf("invalid QWORD value '%s'", data)
			}
		}
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, val)
		return winreg.RegQword, b, nil
	case "REG_BINARY":
		binData, err := hex.DecodeString(strings.TrimPrefix(data, "0x"))
		if err != nil {
			return 0, nil, fmt.Errorf("invalid hex data: %v", err)
		}
		return winreg.RegBinary, binData, nil
	default:
		return 0, nil, fmt.Errorf("unsupported type '%s' (use REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, or REG_BINARY)", regType)
	}
}
