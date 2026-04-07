package agentfunctions

import (
	"sync"

	"github.com/MythicMeta/MythicContainer/logging"
	"github.com/MythicMeta/MythicContainer/mythicrpc"
)

// tagTypeCache caches tag type IDs to avoid repeated RPC calls.
// Thread-safe: ProcessResponse hooks run concurrently.
var (
	tagTypeCache   = make(map[string]int)
	tagTypeCacheMu sync.RWMutex
)

// Tag type definitions — name, description, and color for each category.
type tagTypeDef struct {
	Name        string
	Description string
	Color       string // Mythic UI colors: red, orange, yellow, green, blue, purple, grey
}

var tagTypes = map[string]tagTypeDef{
	"CREDENTIAL":  {"CREDENTIAL", "Credential discovered", "orange"},
	"PLAINTEXT":   {"PLAINTEXT_CRED", "Plaintext password discovered", "red"},
	"HASH":        {"HASH_CRED", "Password hash discovered", "orange"},
	"TICKET":      {"KERBEROS_TICKET", "Kerberos ticket captured", "orange"},
	"KEY":         {"CRYPTO_KEY", "Cryptographic key discovered", "orange"},
	"EDR":         {"EDR_DETECTED", "EDR/AV product detected on host", "yellow"},
	"PRIVESC":     {"PRIVESC_VECTOR", "Privilege escalation vector found", "purple"},
	"SYSTEM":      {"SYSTEM_ACCESS", "SYSTEM-level access obtained", "red"},
	"ELEVATED":    {"ELEVATED_ACCESS", "Admin-level access obtained", "orange"},
	"LATERAL":     {"LATERAL_MOVEMENT", "Lateral movement executed", "blue"},
	"IMPACT":      {"IMPACT_ACTION", "Destructive/impact action performed", "red"},
	"DATA_STAGED": {"DATA_STAGED", "Data staged for exfiltration", "purple"},
}

// getOrCreateTagType looks up or creates a tag type, caching the result.
func getOrCreateTagType(taskID int, category string) (int, bool) {
	tagTypeCacheMu.RLock()
	if id, ok := tagTypeCache[category]; ok {
		tagTypeCacheMu.RUnlock()
		return id, true
	}
	tagTypeCacheMu.RUnlock()

	def, ok := tagTypes[category]
	if !ok {
		return 0, false
	}

	resp, err := mythicrpc.SendMythicRPCTagTypeGetOrCreate(mythicrpc.MythicRPCTagTypeGetOrCreateMessage{
		TaskID:                        taskID,
		GetOrCreateTagTypeName:        &def.Name,
		GetOrCreateTagTypeDescription: &def.Description,
		GetOrCreateTagTypeColor:       &def.Color,
	})
	if err != nil || !resp.Success {
		if err != nil {
			logging.LogError(err, "Failed to get/create tag type", "category", category)
		}
		return 0, false
	}

	tagTypeCacheMu.Lock()
	tagTypeCache[category] = resp.TagType.ID
	tagTypeCacheMu.Unlock()

	return resp.TagType.ID, true
}

// tagTask tags a task with the given category and source description.
func tagTask(taskID int, category string, source string) {
	typeID, ok := getOrCreateTagType(taskID, category)
	if !ok {
		return
	}

	_, err := mythicrpc.SendMythicRPCTagCreate(mythicrpc.MythicRPCTagCreateMessage{
		TagTypeID: typeID,
		Source:    source,
		TaskID:    &taskID,
	})
	if err != nil {
		logging.LogError(err, "Failed to create tag", "category", category, "taskID", taskID)
	}
}
