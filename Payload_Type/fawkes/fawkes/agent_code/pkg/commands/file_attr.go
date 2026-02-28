package commands

import (
	"fmt"
	"os"
	"strings"

	"fawkes/pkg/structs"
)

// FileAttrCommand gets or sets file attributes (hidden, immutable, etc.)
type FileAttrCommand struct{}

func (c *FileAttrCommand) Name() string { return "file-attr" }
func (c *FileAttrCommand) Description() string {
	return "Get or set file attributes — hidden, readonly, immutable, system (T1564.001)"
}

type fileAttrArgs struct {
	Path  string `json:"path"`  // file path
	Attrs string `json:"attrs"` // optional: "+hidden,-readonly,+immutable" to set
}

func (c *FileAttrCommand) Execute(task structs.Task) structs.CommandResult {
	var args fileAttrArgs
	if result, ok := parseArgs(task.Params, &args); !ok {
		return result
	}

	if args.Path == "" {
		return errorResult("Error: -path is required")
	}

	// Verify file exists
	if _, err := os.Lstat(args.Path); err != nil {
		return errorf("Error: %v", err)
	}

	if args.Attrs != "" {
		return setFileAttrs(args.Path, args.Attrs)
	}
	return getFileAttrs(args.Path)
}

// parseAttrChanges parses "+hidden,-readonly,+immutable" into add/remove lists
func parseAttrChanges(attrs string) (add []string, remove []string, err error) {
	for _, part := range strings.Split(attrs, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "+") {
			add = append(add, strings.ToLower(part[1:]))
		} else if strings.HasPrefix(part, "-") {
			remove = append(remove, strings.ToLower(part[1:]))
		} else {
			return nil, nil, fmt.Errorf("invalid attribute: %q (use +attr or -attr)", part)
		}
	}
	if len(add) == 0 && len(remove) == 0 {
		return nil, nil, fmt.Errorf("no valid attributes specified")
	}
	return add, remove, nil
}

// contains checks if a string slice contains a value
func attrContains(slice []string, val string) bool {
	for _, s := range slice {
		if s == val {
			return true
		}
	}
	return false
}
