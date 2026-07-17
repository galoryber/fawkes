package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type pstFileInfo struct {
	Path     string
	Type     string // PST or OST
	Size     int64
	Modified time.Time
	User     string
	Source   string // "default path", "registry", "roaming"
	Profile  string // Outlook profile name (from registry)
	Locked   bool
}

func findPSTFiles(dir string) []pstFileInfo {
	var results []pstFileInfo
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".pst" && ext != ".ost" {
			continue
		}

		fullPath := filepath.Join(dir, entry.Name())
		fi, err := entry.Info()
		if err != nil {
			continue
		}

		fileType := "PST"
		if ext == ".ost" {
			fileType = "OST"
		}

		locked := isFileLocked(fullPath)

		results = append(results, pstFileInfo{
			Path:     fullPath,
			Type:     fileType,
			Size:     fi.Size(),
			Modified: fi.ModTime(),
			Locked:   locked,
		})
	}
	return results
}

func isFileLocked(path string) bool {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return true
	}
	f.Close()
	return false
}

func deduplicatePSTFiles(files []pstFileInfo) []pstFileInfo {
	seen := make(map[string]int)
	var result []pstFileInfo
	for _, f := range files {
		normalPath := strings.ToLower(f.Path)
		if idx, exists := seen[normalPath]; exists {
			if f.Profile != "" && result[idx].Profile == "" {
				result[idx] = f
			}
			continue
		}
		seen[normalPath] = len(result)
		result = append(result, f)
	}
	return result
}

func formatSize(bytes int64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
