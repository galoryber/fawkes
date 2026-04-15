package commands

import (
	"context"
	"fmt"
	"strings"

	"fawkes/pkg/structs"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

func remoteRegQuery(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey}) }()

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return errorf("Error opening key %s\\%s: %v", args.Hive, args.Path, err)
	}
	if args.Path != "" {
		defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey}) }()
	}

	if args.Name == "" {
		return errorResult("Error: -name is required for query action (use enum to list all values)")
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
		return errorf("Error querying value '%s': %v", args.Name, err)
	}
	if resp.Return != 0 {
		return errorf("Error querying value '%s': error code 0x%08x", args.Name, resp.Return)
	}

	output := formatRemoteRegValue(args.Name, resp.Type, resp.Data[:resp.Length])
	return successf("Remote Registry: %s\\%s\\%s on %s\n\n%s", args.Hive, args.Path, args.Name, args.Server, output)
}

func remoteRegEnum(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey}) }()

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return errorf("Error opening key %s\\%s: %v", args.Hive, args.Path, err)
	}
	if args.Path != "" {
		defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey}) }()
	}

	// Get key info for buffer sizing
	infoResp, err := cli.BaseRegQueryInfoKey(ctx, &winreg.BaseRegQueryInfoKeyRequest{
		Key:     subKey,
		ClassIn: &winreg.UnicodeString{Buffer: "", MaximumLength: 256},
	})
	if err != nil {
		return errorf("Error querying key info: %v", err)
	}

	var output strings.Builder
	keyPath := args.Hive
	if args.Path != "" {
		keyPath += `\` + args.Path
	}
	output.WriteString(fmt.Sprintf("Remote Registry: %s on %s\n\n", keyPath, args.Server))

	// Enumerate subkeys
	subkeys := remoteRegEnumSubkeys(ctx, cli, subKey, infoResp.MaxSubKeyLength)

	if len(subkeys) > 0 {
		output.WriteString(fmt.Sprintf("Subkeys (%d):\n", len(subkeys)))
		for _, sk := range subkeys {
			output.WriteString(fmt.Sprintf("  %s\n", sk))
		}
		output.WriteString("\n")
	}

	// Enumerate values
	valueCount, valOutput := remoteRegEnumValues(ctx, cli, subKey, infoResp.MaxValueNameLength, infoResp.MaxValueLength)

	if valueCount > 0 {
		output.WriteString(fmt.Sprintf("Values (%d):\n", valueCount))
		output.WriteString(valOutput)
	}

	if len(subkeys) == 0 && valueCount == 0 {
		output.WriteString("(empty key)")
	}

	return successResult(output.String())
}

func remoteRegEnumSubkeys(ctx context.Context, cli winreg.WinregClient, subKey *winreg.Key, maxSubKeyLength uint32) []string {
	var subkeys []string
	maxKeyLen := maxSubKeyLength + 1
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
	return subkeys
}

func remoteRegEnumValues(ctx context.Context, cli winreg.WinregClient, subKey *winreg.Key, maxValueNameLength, maxValueLength uint32) (int, string) {
	maxValNameLen := maxValueNameLength + 1
	if maxValNameLen < 256 {
		maxValNameLen = 256
	}
	maxValDataLen := maxValueLength
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
	return valueCount, valOutput.String()
}

func remoteRegSet(args remoteRegArgs) structs.CommandResult {
	if args.Name == "" {
		return errorResult("Error: -name is required for set action")
	}
	if args.RegType == "" {
		args.RegType = "REG_SZ"
	}

	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey}) }()

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return errorf("Error opening key %s\\%s: %v", args.Hive, args.Path, err)
	}
	if args.Path != "" {
		defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey}) }()
	}

	valType, valData, err := encodeRemoteRegValue(args.Data, args.RegType)
	if err != nil {
		return errorf("Error encoding value: %v", err)
	}

	resp, err := cli.BaseRegSetValue(ctx, &winreg.BaseRegSetValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: args.Name},
		Type:       valType,
		Data:       valData,
		DataLength: uint32(len(valData)),
	})
	if err != nil {
		return errorf("Error setting value: %v", err)
	}
	if resp.Return != 0 {
		return errorf("Error setting value: error code 0x%08x", resp.Return)
	}

	return successf("Successfully set %s\\%s\\%s = %s (%s) on %s", args.Hive, args.Path, args.Name, args.Data, args.RegType, args.Server)
}

func remoteRegDelete(args remoteRegArgs) structs.CommandResult {
	cli, hiveKey, ctx, cancel, cleanup, err := remoteRegConnect(args)
	if err != nil {
		return errorf("Error: %v", err)
	}
	defer cancel()
	defer cleanup()
	defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hiveKey}) }()

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, args.Path)
	if err != nil {
		return errorf("Error opening key %s\\%s: %v", args.Hive, args.Path, err)
	}
	if args.Path != "" {
		defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey}) }()
	}

	if args.Name != "" {
		// Delete a value
		resp, err := cli.BaseRegDeleteValue(ctx, &winreg.BaseRegDeleteValueRequest{
			Key:       subKey,
			ValueName: &winreg.UnicodeString{Buffer: args.Name},
		})
		if err != nil {
			return errorf("Error deleting value '%s': %v", args.Name, err)
		}
		if resp.Return != 0 {
			return errorf("Error deleting value '%s': error code 0x%08x", args.Name, resp.Return)
		}
		return successf("Successfully deleted value '%s' from %s\\%s on %s", args.Name, args.Hive, args.Path, args.Server)
	}

	// Delete a key (must specify path)
	if args.Path == "" {
		return errorResult("Error: -path is required for key deletion")
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
	_, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: subKey})

	parentKey := hiveKey
	if parentPath != "" {
		parentKey, err = openRemoteSubKey(ctx, cli, hiveKey, parentPath)
		if err != nil {
			return errorf("Error opening parent key: %v", err)
		}
		defer func() { _, _ = cli.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: parentKey}) }()
	}

	resp, err := cli.BaseRegDeleteKey(ctx, &winreg.BaseRegDeleteKeyRequest{
		Key:    parentKey,
		SubKey: &winreg.UnicodeString{Buffer: leafKey},
	})
	if err != nil {
		return errorf("Error deleting key '%s': %v", leafKey, err)
	}
	if resp.Return != 0 {
		return errorf("Error deleting key '%s': error code 0x%08x (key must be empty)", leafKey, resp.Return)
	}
	return successf("Successfully deleted key %s\\%s on %s", args.Hive, args.Path, args.Server)
}
