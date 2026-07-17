package commands

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func TestRemovePKCS7Padding(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"empty", []byte{}, ""},
		{"single pad byte", []byte("hello\x03\x03\x03"), "hello"},
		{"full block pad", []byte{0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08}, ""},
		{"one byte pad", []byte("testing\x01"), "testing"},
		{"no valid padding", []byte("abcdefgh"), "abcdefgh"},
		{"password-check format", []byte("password-check\x02\x02"), "password-check"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := removePKCS7Padding(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(result) != tt.expected {
				t.Errorf("got %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestFirefoxLoginsJSONParsing(t *testing.T) {
	loginsJSON := `{
		"logins": [
			{
				"hostname": "https://example.com",
				"encryptedUsername": "dGVzdA==",
				"encryptedPassword": "cGFzcw=="
			},
			{
				"hostname": "https://bank.example.com",
				"encryptedUsername": "",
				"encryptedPassword": ""
			}
		]
	}`

	var logins firefoxLoginsJSON
	if err := json.Unmarshal([]byte(loginsJSON), &logins); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	if len(logins.Logins) != 2 {
		t.Fatalf("expected 2 logins, got %d", len(logins.Logins))
	}
	if logins.Logins[0].Hostname != "https://example.com" {
		t.Errorf("hostname mismatch: %s", logins.Logins[0].Hostname)
	}
	if logins.Logins[0].EncryptedUsername != "dGVzdA==" {
		t.Errorf("username mismatch: %s", logins.Logins[0].EncryptedUsername)
	}
	if logins.Logins[1].EncryptedUsername != "" {
		t.Errorf("expected empty username for second entry")
	}
}

func TestSHA1Hash(t *testing.T) {
	result := sha1Hash([]byte("test"))
	if len(result) != 20 {
		t.Errorf("SHA1 hash should be 20 bytes, got %d", len(result))
	}
}

func TestHMACSHA1(t *testing.T) {
	result := hmacSHA1([]byte("key"), []byte("data"))
	if len(result) != 20 {
		t.Errorf("HMAC-SHA1 should be 20 bytes, got %d", len(result))
	}
}

func TestFirefoxLoginEntryFields(t *testing.T) {
	entry := firefoxLoginEntry{
		Browser:  "Firefox",
		URL:      "https://example.com",
		Username: "user@example.com",
		Password: "secret123",
	}
	if entry.Browser != "Firefox" {
		t.Error("Browser mismatch")
	}
	if entry.URL != "https://example.com" {
		t.Error("URL mismatch")
	}
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func TestDecryptFirefoxField_3DES(t *testing.T) {
	masterKey := []byte("AABBCCDDEEFF001122334455") // 24-byte 3DES key
	iv := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")
	plaintext := "testuser"

	padded := pkcs7Pad([]byte(plaintext), des.BlockSize)
	block, err := des.NewTripleDESCipher(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	derParams, _ := asn1.Marshal(struct {
		IV []byte
	}{IV: iv})

	derFull, _ := asn1.Marshal(struct {
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}
		Ciphertext []byte
	}{
		AlgorithmInfo: struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7},
			Params:    asn1.RawValue{FullBytes: derParams},
		},
		Ciphertext: ciphertext,
	})

	b64 := base64.StdEncoding.EncodeToString(derFull)
	result, err := decryptFirefoxField(b64, masterKey)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if result != plaintext {
		t.Errorf("got %q, want %q", result, plaintext)
	}
}

func TestDecryptFirefoxField_Empty(t *testing.T) {
	result, err := decryptFirefoxField("", []byte("AABBCCDDEEFF001122334455"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty, got %q", result)
	}
}

func TestDecryptFirefoxField_BadBase64(t *testing.T) {
	_, err := decryptFirefoxField("not-valid-base64!!!", []byte("AABBCCDDEEFF001122334455"))
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestDecryptFirefoxField_BadDER(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte{0x01, 0x02, 0x03})
	_, err := decryptFirefoxField(b64, []byte("AABBCCDDEEFF001122334455"))
	if err == nil {
		t.Error("expected error for invalid DER")
	}
}

func TestDecryptFirefoxField_WrongKeyLength(t *testing.T) {
	iv := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")
	derParams, _ := asn1.Marshal(struct{ IV []byte }{IV: iv})
	derFull, _ := asn1.Marshal(struct {
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}
		Ciphertext []byte
	}{
		AlgorithmInfo: struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7},
			Params:    asn1.RawValue{FullBytes: derParams},
		},
		Ciphertext: []byte{1, 2, 3, 4, 5, 6, 7, 8},
	})
	b64 := base64.StdEncoding.EncodeToString(derFull)

	_, err := decryptFirefoxField(b64, []byte("short"))
	if err == nil {
		t.Error("expected error for wrong key length")
	}
}

func TestDecryptNSSEntry_UnsupportedAlgorithm(t *testing.T) {
	derData, _ := asn1.Marshal(struct {
		AlgorithmInfo struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}
		Ciphertext []byte
	}{
		AlgorithmInfo: struct {
			Algorithm asn1.ObjectIdentifier
			Params    asn1.RawValue
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			Params:    asn1.RawValue{FullBytes: []byte{0x05, 0x00}},
		},
		Ciphertext: []byte{1, 2, 3, 4},
	})

	_, err := decryptNSSEntry(derData, []byte("salt"), nil)
	if err == nil {
		t.Error("expected error for unsupported algorithm")
	}
}

func TestDecryptNSSEntry_BadDER(t *testing.T) {
	_, err := decryptNSSEntry([]byte{0xFF, 0xFF}, []byte("salt"), nil)
	if err == nil {
		t.Error("expected error for invalid DER")
	}
}

func TestDecryptPBES2_RoundTrip(t *testing.T) {
	globalSalt := []byte("global-salt-bytes")
	salt := []byte("pbkdf2-salt-1234")
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	iterations := 100
	plaintext := "password-check\x02\x02"

	combinedPwd := append(globalSalt, []byte(nil)...)
	key := pbkdf2.Key(combinedPwd, salt, iterations, 32, sha256.New)

	padded := pkcs7Pad([]byte(plaintext), aes.BlockSize)
	aesBlock, _ := aes.NewCipher(key)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(aesBlock, iv).CryptBlocks(ciphertext, padded)

	pbes2Params, _ := asn1.Marshal(struct {
		KDF struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
				KeyLength  int
			}
		}
		Encryption struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}
	}{
		KDF: struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
				KeyLength  int
			}
		}{
			Algorithm: oidPBKDF2,
			Params: struct {
				Salt       []byte
				Iterations int
				KeyLength  int
			}{Salt: salt, Iterations: iterations, KeyLength: 32},
		},
		Encryption: struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}{
			Algorithm: oidAES256CBC,
			IV:        iv,
		},
	})

	result, err := decryptPBES2(pbes2Params, ciphertext, globalSalt, nil)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(result) != plaintext {
		t.Errorf("got %q, want %q", result, plaintext)
	}
}

func TestDecryptPBES2_UnsupportedKDF(t *testing.T) {
	params, _ := asn1.Marshal(struct {
		KDF struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
			}
		}
		Encryption struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}
	}{
		KDF: struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
			}
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			Params: struct {
				Salt       []byte
				Iterations int
			}{Salt: []byte("salt"), Iterations: 1},
		},
		Encryption: struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}{
			Algorithm: oidAES256CBC,
			IV:        make([]byte, 16),
		},
	})

	_, err := decryptPBES2(params, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, []byte("salt"), nil)
	if err == nil {
		t.Error("expected error for unsupported KDF")
	}
}

func TestDecryptPBES2_UnsupportedEncryption(t *testing.T) {
	params, _ := asn1.Marshal(struct {
		KDF struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
			}
		}
		Encryption struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}
	}{
		KDF: struct {
			Algorithm asn1.ObjectIdentifier
			Params    struct {
				Salt       []byte
				Iterations int
			}
		}{
			Algorithm: oidPBKDF2,
			Params: struct {
				Salt       []byte
				Iterations int
			}{Salt: []byte("salt"), Iterations: 1},
		},
		Encryption: struct {
			Algorithm asn1.ObjectIdentifier
			IV        []byte
		}{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5},
			IV:        make([]byte, 16),
		},
	})

	_, err := decryptPBES2(params, make([]byte, 16), []byte("salt"), nil)
	if err == nil {
		t.Error("expected error for unsupported encryption")
	}
}

func TestDecryptPBES2_BadParams(t *testing.T) {
	_, err := decryptPBES2([]byte{0xFF, 0xFF}, make([]byte, 16), []byte("salt"), nil)
	if err == nil {
		t.Error("expected error for invalid PBES2 params")
	}
}

func TestOIDConstants(t *testing.T) {
	if !oidPBES2.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}) {
		t.Error("oidPBES2 mismatch")
	}
	if !oidPBKDF2.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}) {
		t.Error("oidPBKDF2 mismatch")
	}
	if !oidAES256CBC.Equal(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}) {
		t.Error("oidAES256CBC mismatch")
	}
	if !oidPBESHA1TriDES.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 5, 1, 3}) {
		t.Error("oidPBESHA1TriDES mismatch")
	}
}
