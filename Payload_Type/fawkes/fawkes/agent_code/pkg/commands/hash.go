package commands

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"fawkes/pkg/structs"
)

type HashCommand struct{}

func (c *HashCommand) Name() string { return "hash" }
func (c *HashCommand) Description() string {
	return "Compute file hashes — MD5, SHA-1, SHA-256, SHA-512 (T1083)"
}

type hashArgs struct {
	Path      string `json:"path"`      // file or directory to hash
	Algorithm string `json:"algorithm"` // md5, sha1, sha256, sha512 (default: sha256)
	Recursive bool   `json:"recursive"` // recurse into subdirectories (default: false)
	Pattern   string `json:"pattern"`   // glob pattern filter (e.g., "*.exe")
	MaxFiles  int    `json:"max_files"` // limit number of files (default: 500)
}

type hashResult struct {
	Path string
	Hash string
	Size int64
	Err  string
}

func (c *HashCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return structs.CommandResult{
			Output:    "Error: parameters required. Use -path <file_or_dir> [-algorithm md5|sha1|sha256|sha512] [-recursive true] [-pattern *.exe]",
			Status:    "error",
			Completed: true,
		}
	}

	var args hashArgs
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

	if args.Algorithm == "" {
		args.Algorithm = "sha256"
	}
	args.Algorithm = strings.ToLower(args.Algorithm)

	if args.MaxFiles <= 0 {
		args.MaxFiles = 500
	}

	// Validate algorithm
	if !hashValidAlgorithm(args.Algorithm) {
		return structs.CommandResult{
			Output:    fmt.Sprintf("Error: unsupported algorithm '%s'. Use md5, sha1, sha256, or sha512", args.Algorithm),
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

	var results []hashResult

	if !info.IsDir() {
		// Single file
		r := hashFile(path, args.Algorithm)
		r.Size = info.Size()
		results = append(results, r)
	} else {
		// Directory
		results = hashDirectory(path, args)
	}

	// Format output
	var sb strings.Builder
	algUpper := strings.ToUpper(args.Algorithm)
	sb.WriteString(fmt.Sprintf("[*] %s hashes (%d files):\n", algUpper, len(results)))
	sb.WriteString(strings.Repeat("-", 60) + "\n")

	errCount := 0
	for _, r := range results {
		if r.Err != "" {
			errCount++
			sb.WriteString(fmt.Sprintf("[-] %s — %s\n", r.Path, r.Err))
		} else {
			sb.WriteString(fmt.Sprintf("%s  %s  (%s)\n", r.Hash, r.Path, hashFormatSize(r.Size)))
		}
	}

	sb.WriteString(strings.Repeat("-", 60) + "\n")
	sb.WriteString(fmt.Sprintf("[*] %d files hashed", len(results)-errCount))
	if errCount > 0 {
		sb.WriteString(fmt.Sprintf(", %d errors", errCount))
	}
	sb.WriteString("\n")

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

func hashValidAlgorithm(alg string) bool {
	switch alg {
	case "md5", "sha1", "sha256", "sha512":
		return true
	}
	return false
}

func hashNewHasher(alg string) hash.Hash {
	switch alg {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha256":
		return sha256.New()
	case "sha512":
		return sha512.New()
	default:
		return sha256.New()
	}
}

func hashFile(path, algorithm string) hashResult {
	f, err := os.Open(path)
	if err != nil {
		return hashResult{Path: path, Err: err.Error()}
	}
	defer f.Close()

	h := hashNewHasher(algorithm)
	if _, err := io.Copy(h, f); err != nil {
		return hashResult{Path: path, Err: err.Error()}
	}

	info, _ := f.Stat()
	var size int64
	if info != nil {
		size = info.Size()
	}

	return hashResult{
		Path: path,
		Hash: hex.EncodeToString(h.Sum(nil)),
		Size: size,
	}
}

func hashDirectory(root string, args hashArgs) []hashResult {
	var results []hashResult
	count := 0

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if info.IsDir() {
			if !args.Recursive && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= args.MaxFiles {
			return filepath.SkipAll
		}

		// Pattern filter
		if args.Pattern != "" {
			matched, _ := filepath.Match(args.Pattern, filepath.Base(path))
			if !matched {
				return nil
			}
		}

		r := hashFile(path, args.Algorithm)
		r.Size = info.Size()
		results = append(results, r)
		count++
		return nil
	}

	_ = filepath.Walk(root, walkFn)

	// Sort by path
	sort.Slice(results, func(i, j int) bool {
		return results[i].Path < results[j].Path
	})

	return results
}

func hashFormatSize(bytes int64) string {
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
