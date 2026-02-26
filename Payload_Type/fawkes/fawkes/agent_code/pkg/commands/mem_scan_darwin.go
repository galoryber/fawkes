//go:build darwin

package commands

import "fmt"

func scanProcessMemory(pid int, searchBytes []byte, maxResults int, contextBytes int) ([]memScanMatch, int, uint64, error) {
	return nil, 0, 0, fmt.Errorf("mem-scan is not supported on macOS (requires task_for_pid entitlement)")
}
