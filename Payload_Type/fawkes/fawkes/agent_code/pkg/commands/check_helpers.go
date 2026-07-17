package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"fawkes/pkg/structs"
)

// checkTCPPort tests if a TCP port is reachable within the given timeout.
// Returns "open", "timeout", or "closed: <reason>".
func checkTCPPort(ctx context.Context, host, port string, timeout time.Duration) string {
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		if isTimeout(err) {
			return "timeout"
		}
		return fmt.Sprintf("closed: %v", err)
	}
	conn.Close()
	return "open"
}

func checkResult(v any) structs.CommandResult {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return errorf("failed to marshal result: %v", err)
	}
	return successResult(string(data))
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
