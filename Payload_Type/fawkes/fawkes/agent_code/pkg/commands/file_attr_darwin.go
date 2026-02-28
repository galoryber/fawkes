//go:build darwin

package commands

import (
	"fmt"
	"os"
	"strings"
	"syscall"

	"fawkes/pkg/structs"
)

// macOS BSD file flags (from sys/stat.h)
const (
	ufHidden    = 0x00008000 // UF_HIDDEN
	ufImmutable = 0x00000002 // UF_IMMUTABLE (user)
	ufAppend    = 0x00000004 // UF_APPEND (user)
	sfImmutable = 0x00020000 // SF_IMMUTABLE (system, requires root)
	sfAppend    = 0x00040000 // SF_APPEND (system, requires root)
)

type darwinAttrDef struct {
	name string
	flag uint32
}

var darwinAttrDefs = []darwinAttrDef{
	{"hidden", ufHidden},
	{"immutable", ufImmutable},
	{"append", ufAppend},
	{"sys_immutable", sfImmutable},
	{"sys_append", sfAppend},
}

func getFileAttrs(path string) structs.CommandResult {
	info, err := os.Lstat(path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errorResult("Error: could not get BSD flags")
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("[*] File attributes for: %s\n", path))
	sb.WriteString(fmt.Sprintf("    Raw flags: 0x%08X\n", sys.Flags))
	sb.WriteString("    Flags:\n")

	found := false
	for _, def := range darwinAttrDefs {
		if sys.Flags&def.flag != 0 {
			sb.WriteString(fmt.Sprintf("      [+] %s\n", def.name))
			found = true
		}
	}
	if !found {
		sb.WriteString("      (none)\n")
	}

	return successResult(sb.String())
}

func setFileAttrs(path string, attrsStr string) structs.CommandResult {
	add, remove, err := parseAttrChanges(attrsStr)
	if err != nil {
		return errorf("Error: %v", err)
	}

	// Get current flags
	info, err := os.Lstat(path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errorResult("Error: could not get BSD flags")
	}

	flags := sys.Flags

	// Apply changes
	var changed []string
	for _, def := range darwinAttrDefs {
		if attrContains(add, def.name) {
			if flags&def.flag == 0 {
				flags |= def.flag
				changed = append(changed, "+"+def.name)
			}
		}
		if attrContains(remove, def.name) {
			if flags&def.flag != 0 {
				flags &^= def.flag
				changed = append(changed, "-"+def.name)
			}
		}
	}

	if len(changed) == 0 {
		return successf("[*] No attribute changes needed for %s", path)
	}

	if err := syscall.Chflags(path, int(flags)); err != nil {
		return errorf("Error setting flags (may require root for system flags): %v", err)
	}

	return successf("[+] Updated attributes on %s: %s", path, strings.Join(changed, ", "))
}
