package commands

import (
	"bufio"
	"os"
	"strings"
)

func getMountInfo() ([]mountInfoEntry, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var entries []mountInfoEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		entries = append(entries, mountInfoEntry{
			device:     fields[0],
			mntPoint: fields[1],
			mntType:  fields[2],
			mntOpts:  fields[3],
		})
	}

	return entries, nil
}
