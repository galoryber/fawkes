package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"fawkes/pkg/structs"
)

type ChmodCommand struct{}

func (c *ChmodCommand) Name() string        { return "chmod" }
func (c *ChmodCommand) Description() string { return "Modify file and directory permissions (T1222)" }

type chmodArgs struct {
	Path      string `json:"path"`      // file or directory
	Mode      string `json:"mode"`      // octal mode (e.g., "755", "644") or symbolic (e.g., "+x", "u+rw")
	Recursive bool   `json:"recursive"` // apply recursively to directory contents
}

func (c *ChmodCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -path <file> -mode <permissions> [-recursive true]",
			Status:    "error",
			Completed: true,
		}
	}

	var args chmodArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error parsing parameters: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if args.Path == "" {
		return structs.CommandResult{
			Output:    "Error: path parameter is required",
			Status:    "error",
			Completed: true,
		}
	}

	if args.Mode == "" {
		return structs.CommandResult{
			Output:    "Error: mode parameter is required (e.g., '755', '644', '+x', 'u+rw')",
			Status:    "error",
			Completed: true,
		}
	}

	// Resolve path
	path := args.Path
	if strings.HasPrefix(path, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			path = filepath.Join(home, path[1:])
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	// Parse the mode
	mode, err := chmodParseMode(args.Mode, info.Mode())
	if err != nil {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: %v", err),
			Status:    "error",
			Completed: true,
		}
	}

	if !args.Recursive || !info.IsDir() {
		// Single file or non-recursive
		before := info.Mode()
		if err := os.Chmod(path, mode); err != nil {
			return structs.CommandResult{
				Output:    fmt.Sprintf("Error: %v", err),
				Status:    "error",
				Completed: true,
			}
		}
		return structs.CommandResult{
			Output:    chmodFormatResult(path, before, mode),
			Status:    "success",
			Completed: true,
		}
	}

	// Recursive directory chmod
	var sb strings.Builder
	changed := 0
	errors := 0

	walkErr := filepath.Walk(path, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			errors++
			sb.WriteString(fmt.Sprintf("[-] %s — %v\n", p, err))
			return nil
		}

		before := fi.Mode()
		if err := os.Chmod(p, mode); err != nil {
			errors++
			sb.WriteString(fmt.Sprintf("[-] %s — %v\n", p, err))
			return nil
		}
		changed++
		if before.Perm() != mode.Perm() {
			sb.WriteString(fmt.Sprintf("[+] %s  %s → %s\n", p, chmodFormatPerm(before), chmodFormatPerm(mode)))
		}
		return nil
	})

	if walkErr != nil {
		sb.WriteString(fmt.Sprintf("[-] Walk error: %v\n", walkErr))
	}

	sb.WriteString(fmt.Sprintf("\n[*] %d items changed", changed))
	if errors > 0 {
		sb.WriteString(fmt.Sprintf(", %d errors", errors))
	}

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// chmodParseMode parses an octal mode string (e.g., "755") or symbolic mode (e.g., "+x", "u+rw")
func chmodParseMode(modeStr string, current os.FileMode) (os.FileMode, error) {
	// Try octal first
	if n, err := strconv.ParseUint(modeStr, 8, 32); err == nil {
		if n > 0777 {
			return 0, fmt.Errorf("invalid octal mode '%s': value too large (max 777)", modeStr)
		}
		return os.FileMode(n), nil
	}

	// Symbolic mode parsing: [ugoa][+-=][rwx]
	return chmodParseSymbolic(modeStr, current)
}

// chmodParseSymbolic parses symbolic chmod notation like "+x", "u+rw", "go-w", "a=rx"
func chmodParseSymbolic(modeStr string, current os.FileMode) (os.FileMode, error) {
	perm := current.Perm()

	for _, part := range strings.Split(modeStr, ",") {
		part = strings.TrimSpace(part)
		if len(part) < 2 {
			return 0, fmt.Errorf("invalid symbolic mode '%s'", part)
		}

		// Find the operator position
		opIdx := strings.IndexAny(part, "+-=")
		if opIdx < 0 {
			return 0, fmt.Errorf("invalid symbolic mode '%s': missing operator (+, -, =)", part)
		}

		// Parse who: u, g, o, a (default: a)
		who := part[:opIdx]
		if who == "" {
			who = "a"
		}
		op := part[opIdx]
		perms := part[opIdx+1:]

		// Build the permission bits
		var bits os.FileMode
		for _, ch := range perms {
			switch ch {
			case 'r':
				bits |= 4
			case 'w':
				bits |= 2
			case 'x':
				bits |= 1
			default:
				return 0, fmt.Errorf("invalid permission character '%c' in '%s'", ch, part)
			}
		}

		// Apply to each target
		for _, w := range who {
			var shift uint
			switch w {
			case 'u':
				shift = 6
			case 'g':
				shift = 3
			case 'o':
				shift = 0
			case 'a':
				// Apply to all
				shifted := bits<<6 | bits<<3 | bits
				switch op {
				case '+':
					perm |= shifted
				case '-':
					perm &^= shifted
				case '=':
					perm = shifted
				}
				continue
			default:
				return 0, fmt.Errorf("invalid who character '%c' in '%s'", w, part)
			}

			shifted := bits << shift
			switch op {
			case '+':
				perm |= shifted
			case '-':
				perm &^= shifted
			case '=':
				mask := os.FileMode(7) << shift
				perm = (perm &^ mask) | shifted
			}
		}
	}

	return perm, nil
}

func chmodFormatResult(path string, before, after os.FileMode) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[+] %s\n", path))
	sb.WriteString(fmt.Sprintf("    Before: %s (%04o)\n", chmodFormatPerm(before), before.Perm()))
	sb.WriteString(fmt.Sprintf("    After:  %s (%04o)\n", chmodFormatPerm(after), after.Perm()))
	if runtime.GOOS == "windows" {
		sb.WriteString("    Note: Windows file permissions have limited POSIX mapping\n")
	}
	return sb.String()
}

func chmodFormatPerm(mode os.FileMode) string {
	var buf [9]byte
	const rwx = "rwx"
	for i := 0; i < 9; i++ {
		if mode&(1<<uint(8-i)) != 0 {
			buf[i] = rwx[i%3]
		} else {
			buf[i] = '-'
		}
	}
	return string(buf[:])
}
