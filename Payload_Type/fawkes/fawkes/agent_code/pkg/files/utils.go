package files

import (
	"strings"

	"github.com/google/uuid"
)

// generateUUID generates a UUID without dashes
func generateUUID() string {
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}
