package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

type winregParams struct {
	Hive    string `json:"hive"`
	Path    string `json:"path"`
	Name    string `json:"name"`
	Data    string `json:"data"`
	RegType string `json:"reg_type"`
}

type winregResult struct {
	Text string `json:"text"`
}

func winregSubprocessConnect(ctx context.Context, server string) (winreg.WinregClient, dcerpc.Conn, error) {
	cc, err := dcerpc.Dial(ctx, server,
		dcerpc.WithEndpoint("ncacn_np:[winreg]"),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("DCE-RPC connection failed: %w", err)
	}

	cli, err := winreg.NewWinregClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithTargetName(server))
	if err != nil {
		cc.Close(ctx)
		return nil, nil, fmt.Errorf("failed to create WinReg client: %w", err)
	}

	return cli, cc, nil
}

func rpcHelperWinregQuery(req rpcHelperRequest) (json.RawMessage, error) {
	var p winregParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Hive == "" {
		p.Hive = "HKLM"
	}

	ctx, cancel, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, cc, err := winregSubprocessConnect(ctx, req.Server)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)

	hiveKey, err := openRemoteHive(ctx, cli, p.Hive)
	if err != nil {
		return nil, fmt.Errorf("failed to open hive %s: %w", p.Hive, err)
	}

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, p.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key %s: %w", p.Path, err)
	}

	queryName := p.Name
	if queryName == "" {
		queryName = ""
	}

	resp, err := cli.BaseRegQueryValue(ctx, &winreg.BaseRegQueryValueRequest{
		Key:        subKey,
		ValueName:  &winreg.UnicodeString{Buffer: queryName},
		Data:       make([]byte, 65536),
		DataLength: 65536,
	})
	if err != nil {
		return nil, fmt.Errorf("query value %q: %w", queryName, err)
	}

	displayName := p.Name
	if displayName == "" {
		displayName = "(Default)"
	}
	result := winregResult{Text: formatRemoteRegValue(displayName, resp.Type, resp.Data)}
	out, _ := json.Marshal(result)
	return out, nil
}

func rpcHelperWinregEnum(req rpcHelperRequest) (json.RawMessage, error) {
	var p winregParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Hive == "" {
		p.Hive = "HKLM"
	}

	ctx, cancel, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, cc, err := winregSubprocessConnect(ctx, req.Server)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)

	hiveKey, err := openRemoteHive(ctx, cli, p.Hive)
	if err != nil {
		return nil, fmt.Errorf("failed to open hive %s: %w", p.Hive, err)
	}

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, p.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key %s: %w", p.Path, err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Registry: %s\\%s on %s\n\n", p.Hive, p.Path, req.Server))

	// Enumerate subkeys
	sb.WriteString("Subkeys:\n")
	subkeyCount := 0
	for i := uint32(0); ; i++ {
		enumResp, err := cli.BaseRegEnumKey(ctx, &winreg.BaseRegEnumKeyRequest{
			Key:   subKey,
			Index: i,
			NameIn: &winreg.UnicodeString{
				MaximumLength: 512,
			},
		})
		if err != nil || enumResp.Return != 0 {
			break
		}
		if enumResp.NameOut != nil {
			sb.WriteString(fmt.Sprintf("  [%s]\n", enumResp.NameOut.Buffer))
			subkeyCount++
		}
	}
	if subkeyCount == 0 {
		sb.WriteString("  (none)\n")
	}

	// Enumerate values
	sb.WriteString("\nValues:\n")
	valueCount := 0
	for i := uint32(0); ; i++ {
		enumResp, err := cli.BaseRegEnumValue(ctx, &winreg.BaseRegEnumValueRequest{
			Key:   subKey,
			Index: i,
			ValueNameIn: &winreg.UnicodeString{
				MaximumLength: 512,
			},
			Data:       make([]byte, 65536),
			DataLength: 65536,
			Length:     65536,
		})
		if err != nil || enumResp.Return != 0 {
			break
		}
		name := "(Default)"
		if enumResp.ValueNameOut != nil && enumResp.ValueNameOut.Buffer != "" {
			name = enumResp.ValueNameOut.Buffer
		}
		sb.WriteString(fmt.Sprintf("  %s\n", formatRemoteRegValue(name, enumResp.Type, enumResp.Data)))
		valueCount++
	}
	if valueCount == 0 {
		sb.WriteString("  (none)\n")
	}

	result := winregResult{Text: sb.String()}
	out, _ := json.Marshal(result)
	return out, nil
}

func rpcHelperWinregSet(req rpcHelperRequest) (json.RawMessage, error) {
	var p winregParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Hive == "" {
		p.Hive = "HKLM"
	}

	ctx, cancel, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, cc, err := winregSubprocessConnect(ctx, req.Server)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)

	hiveKey, err := openRemoteHive(ctx, cli, p.Hive)
	if err != nil {
		return nil, fmt.Errorf("failed to open hive %s: %w", p.Hive, err)
	}

	subKey, err := openRemoteSubKey(ctx, cli, hiveKey, p.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open key %s: %w", p.Path, err)
	}

	regType, data, err := encodeRemoteRegValue(p.RegType, p.Data)
	if err != nil {
		return nil, err
	}

	resp, err := cli.BaseRegSetValue(ctx, &winreg.BaseRegSetValueRequest{
		Key:       subKey,
		ValueName: &winreg.UnicodeString{Buffer: p.Name},
		Type:      regType,
		Data:      data,
		DataLength: uint32(len(data)),
	})
	if err != nil {
		return nil, fmt.Errorf("set value: %w", err)
	}
	if resp.Return != 0 {
		return nil, fmt.Errorf("SetValue error: 0x%08x", resp.Return)
	}

	result := winregResult{Text: fmt.Sprintf("Successfully set %s\\%s\\%s", p.Hive, p.Path, p.Name)}
	out, _ := json.Marshal(result)
	return out, nil
}

func rpcHelperWinregDelete(req rpcHelperRequest) (json.RawMessage, error) {
	var p winregParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return nil, fmt.Errorf("invalid params: %v", err)
	}
	if p.Hive == "" {
		p.Hive = "HKLM"
	}

	ctx, cancel, err := rpcHelperCredAndContext(req)
	if err != nil {
		return nil, err
	}
	defer cancel()

	cli, cc, err := winregSubprocessConnect(ctx, req.Server)
	if err != nil {
		return nil, err
	}
	defer cc.Close(ctx)

	hiveKey, err := openRemoteHive(ctx, cli, p.Hive)
	if err != nil {
		return nil, fmt.Errorf("failed to open hive %s: %w", p.Hive, err)
	}

	if p.Name != "" {
		subKey, err := openRemoteSubKey(ctx, cli, hiveKey, p.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to open key %s: %w", p.Path, err)
		}
		resp, err := cli.BaseRegDeleteValue(ctx, &winreg.BaseRegDeleteValueRequest{
			Key:       subKey,
			ValueName: &winreg.UnicodeString{Buffer: p.Name},
		})
		if err != nil {
			return nil, fmt.Errorf("delete value: %w", err)
		}
		if resp.Return != 0 {
			return nil, fmt.Errorf("DeleteValue error: 0x%08x", resp.Return)
		}
		result := winregResult{Text: fmt.Sprintf("Successfully deleted value %s from %s\\%s", p.Name, p.Hive, p.Path)}
		out, _ := json.Marshal(result)
		return out, nil
	}

	resp, err := cli.BaseRegDeleteKey(ctx, &winreg.BaseRegDeleteKeyRequest{
		Key:    hiveKey,
		SubKey: &winreg.UnicodeString{Buffer: p.Path},
	})
	if err != nil {
		return nil, fmt.Errorf("delete key: %w", err)
	}
	if resp.Return != 0 {
		return nil, fmt.Errorf("DeleteKey error: 0x%08x", resp.Return)
	}
	result := winregResult{Text: fmt.Sprintf("Successfully deleted key %s\\%s", p.Hive, p.Path)}
	out, _ := json.Marshal(result)
	return out, nil
}
