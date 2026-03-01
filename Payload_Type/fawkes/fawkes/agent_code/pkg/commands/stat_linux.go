//go:build linux

package commands

import (
	"fmt"
	"os"
	"os/user"
	"strings"
	"syscall"
	"time"
)

func statPlatformInfo(sb *strings.Builder, info os.FileInfo, path string) {
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}

	sb.WriteString(fmt.Sprintf(" Inode: %d\n", sys.Ino))
	sb.WriteString(fmt.Sprintf(" Links: %d\n", sys.Nlink))

	ownerName := fmt.Sprintf("%d", sys.Uid)
	if u, err := user.LookupId(fmt.Sprintf("%d", sys.Uid)); err == nil {
		ownerName = u.Username
	}
	groupName := fmt.Sprintf("%d", sys.Gid)
	if g, err := user.LookupGroupId(fmt.Sprintf("%d", sys.Gid)); err == nil {
		groupName = g.Name
	}
	sb.WriteString(fmt.Sprintf(" Owner: %s (%d)\n", ownerName, sys.Uid))
	sb.WriteString(fmt.Sprintf(" Group: %s (%d)\n", groupName, sys.Gid))
	sb.WriteString(fmt.Sprintf("Device: %d,%d\n", sys.Dev>>8, sys.Dev&0xff))

	atime := time.Unix(sys.Atim.Sec, sys.Atim.Nsec)
	ctime := time.Unix(sys.Ctim.Sec, sys.Ctim.Nsec)
	sb.WriteString(fmt.Sprintf("Access: %s\n", atime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Change: %s\n", ctime.Format(time.RFC3339)))
}
