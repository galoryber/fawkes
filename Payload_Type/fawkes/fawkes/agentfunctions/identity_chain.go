package agentfunctions

import (
	"fmt"
	"strings"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// updateCallbackIdentity updates the callback description to reflect the current
// impersonation state after a token operation (stealtoken, maketoken, rev2self).
func updateCallbackIdentity(taskID int, callbackID string, operation, user string) {
	desc := formatIdentityDescription(operation, user)
	if _, err := mythicrpc.SendMythicRPCCallbackUpdate(mythicrpc.MythicRPCCallbackUpdateMessage{
		AgentCallbackID: &callbackID,
		Description:     &desc,
	}); err != nil {
		logging.LogError(err, "Failed to update callback identity", "operation", operation, "user", user)
	}
	logOperationEvent(taskID,
		fmt.Sprintf("[IDENTITY] %s -> %s", operation, user), false)
}

// formatIdentityDescription creates a concise identity description for the callback.
func formatIdentityDescription(operation, user string) string {
	switch operation {
	case "stealtoken":
		return fmt.Sprintf("Impersonating: %s (via stealtoken)", user)
	case "maketoken":
		return fmt.Sprintf("Impersonating: %s (via maketoken)", user)
	case "rev2self":
		return fmt.Sprintf("Reverted to: %s", user)
	case "getsystem":
		return fmt.Sprintf("Elevated: %s (via getsystem)", user)
	default:
		return fmt.Sprintf("Identity: %s (%s)", user, operation)
	}
}

// classifyIdentityLevel returns a privilege level label for OPSEC context.
func classifyIdentityLevel(user string) string {
	upper := strings.ToUpper(user)
	if strings.Contains(upper, "SYSTEM") || strings.Contains(upper, "NT AUTHORITY") {
		return "SYSTEM"
	}
	if strings.Contains(upper, "ADMIN") || strings.Contains(upper, "DA ") ||
		strings.Contains(upper, "DOMAIN ADMIN") || strings.Contains(upper, "ENTERPRISE ADMIN") {
		return "admin"
	}
	return "user"
}

// identityContextForOPSEC returns a string describing the current impersonation
// state for inclusion in OPSEC warnings on lateral movement commands.
func identityContextForOPSEC(callbackDesc string) string {
	if callbackDesc == "" {
		return ""
	}
	if strings.HasPrefix(callbackDesc, "Impersonating:") {
		return callbackDesc
	}
	return ""
}
