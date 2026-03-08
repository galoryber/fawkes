package commands

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"fawkes/pkg/structs"
)

// SecureDeleteCommand implements secure file deletion with overwrite
type SecureDeleteCommand struct{}

func (c *SecureDeleteCommand) Name() string {
	return "secure-delete"
}

func (c *SecureDeleteCommand) Description() string {
	return "Securely delete files by overwriting with random data before removal"
}

type secureDeleteArgs struct {
	Path   string `json:"path"`
	Passes int    `json:"passes"` // number of overwrite passes (default 3)
}

const secureDeleteDefaultPasses = 3

func (c *SecureDeleteCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: no parameters provided")
	}

	var args secureDeleteArgs
	if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	if args.Passes <= 0 {
		args.Passes = secureDeleteDefaultPasses
	}

	info, err := os.Lstat(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	if info.IsDir() {
		count, errs := secureDeleteDir(args.Path, args.Passes)
		output := fmt.Sprintf("[+] Securely deleted directory: %s (%d files, %d passes per file)", args.Path, count, args.Passes)
		if len(errs) > 0 {
			output += fmt.Sprintf("\n[!] %d errors encountered:", len(errs))
			for _, e := range errs {
				output += fmt.Sprintf("\n    - %s", e)
			}
		}
		return structs.CommandResult{
			Output:    output,
			Status:    "success",
			Completed: true,
		}
	}

	size := info.Size()
	if err := secureDeleteFile(args.Path, size, args.Passes); err != nil {
		return errorf("Error securely deleting file: %v", err)
	}

	return structs.CommandResult{
		Output:    fmt.Sprintf("[+] Securely deleted: %s (%s, %d passes)", args.Path, formatFileSize(size), args.Passes),
		Status:    "success",
		Completed: true,
	}
}

// secureDeleteFile overwrites a file with random data then removes it
func secureDeleteFile(path string, size int64, passes int) error {
	for i := 0; i < passes; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("open for overwrite pass %d: %w", i+1, err)
		}

		// Overwrite with random data in 32KB chunks
		remaining := size
		buf := make([]byte, 32768)
		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}
			if _, err := rand.Read(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("generate random data: %w", err)
			}
			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("overwrite pass %d: %w", i+1, err)
			}
			remaining -= n
		}

		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("sync pass %d: %w", i+1, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("close pass %d: %w", i+1, err)
		}
	}

	return os.Remove(path)
}

// secureDeleteDir recursively securely deletes all files in a directory
func secureDeleteDir(dirPath string, passes int) (int, []string) {
	var count int
	var errs []string

	_ = filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, infoErr))
			return nil
		}
		if err := secureDeleteFile(path, info.Size(), passes); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
		} else {
			count++
		}
		return nil
	})

	// Remove empty directories
	os.RemoveAll(dirPath)

	return count, errs
}
