//go:build windows

package commands

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	fileAttributeCompressed = 0x800
	fileAttributeEncrypted  = 0x4000
)

func statPlatformInfo(sb *strings.Builder, info os.FileInfo, path string) {
	sys, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return
	}

	// File attributes
	attrs := []string{}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_READONLY != 0 {
		attrs = append(attrs, "ReadOnly")
	}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_HIDDEN != 0 {
		attrs = append(attrs, "Hidden")
	}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_SYSTEM != 0 {
		attrs = append(attrs, "System")
	}
	if sys.FileAttributes&syscall.FILE_ATTRIBUTE_ARCHIVE != 0 {
		attrs = append(attrs, "Archive")
	}
	if sys.FileAttributes&fileAttributeCompressed != 0 {
		attrs = append(attrs, "Compressed")
	}
	if sys.FileAttributes&fileAttributeEncrypted != 0 {
		attrs = append(attrs, "Encrypted")
	}
	if len(attrs) > 0 {
		sb.WriteString(fmt.Sprintf(" Attrs: %s\n", strings.Join(attrs, ", ")))
	}

	// Creation time (Windows-specific)
	ct := time.Unix(0, sys.CreationTime.Nanoseconds())
	sb.WriteString(fmt.Sprintf("Create: %s\n", ct.Format(time.RFC3339)))

	// Access time
	at := time.Unix(0, sys.LastAccessTime.Nanoseconds())
	sb.WriteString(fmt.Sprintf("Access: %s\n", at.Format(time.RFC3339)))
}
