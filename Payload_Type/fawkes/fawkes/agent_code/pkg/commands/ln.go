package commands

import (
	"os"

	"fawkes/pkg/structs"
)

// LnCommand creates symbolic or hard links
type LnCommand struct{}

func (c *LnCommand) Name() string        { return "ln" }
func (c *LnCommand) Description() string { return "Create symbolic or hard links (T1036)" }

type lnArgs struct {
	Target   string `json:"target"`   // existing file or directory
	Link     string `json:"link"`     // path for new link
	Symbolic bool   `json:"symbolic"` // true = symlink, false = hard link
	Force    bool   `json:"force"`    // overwrite existing link
}

func (c *LnCommand) Execute(task structs.Task) structs.CommandResult {
	var args lnArgs
	if result, ok := parseArgs(task.Params, &args); !ok {
		return result
	}

	if args.Target == "" || args.Link == "" {
		return errorResult("Error: both -target and -link are required")
	}

	// Verify target exists (unless symbolic — symlinks can point to non-existent paths)
	if !args.Symbolic {
		if _, err := os.Stat(args.Target); err != nil {
			return errorf("Error: target does not exist: %v", err)
		}
	}

	// Remove existing link if force is set
	if args.Force {
		if info, err := os.Lstat(args.Link); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || info.Mode().IsRegular() {
				os.Remove(args.Link)
			} else {
				return errorf("Error: %s exists and is not a regular file or symlink", args.Link)
			}
		}
	}

	var err error
	linkType := "hard"
	if args.Symbolic {
		linkType = "symbolic"
		err = os.Symlink(args.Target, args.Link)
	} else {
		err = os.Link(args.Target, args.Link)
	}

	if err != nil {
		return errorf("Error creating %s link: %v", linkType, err)
	}

	return successf("[+] Created %s link: %s -> %s", linkType, args.Link, args.Target)
}
