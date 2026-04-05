package commands

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
)

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
