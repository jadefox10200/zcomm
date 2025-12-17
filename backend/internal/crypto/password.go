package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

// Argon2 parameters
const (
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
	SaltLen       = 16
)

// HashPassword hashes a password using Argon2id
func HashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the password
	hash := argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, Argon2KeyLen)

	// Encode to base64 for storage
	saltB64 := base64.StdEncoding.EncodeToString(salt)
	hashB64 := base64.StdEncoding.EncodeToString(hash)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		Argon2Memory, Argon2Time, Argon2Threads, saltB64, hashB64), nil
}

// VerifyPassword verifies a password against an Argon2 hash
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return false, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	// Parse parameters (parts[3] = "m=65536,t=1,p=4")
	var memory, time uint32
	var threads uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, fmt.Errorf("failed to parse parameters: %w", err)
	}

	// Decode salt and hash
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	hash, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Hash the password with the same parameters
	testHash := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(hash)))

	// Compare in constant time
	return subtle.ConstantTimeCompare(hash, testHash) == 1, nil
}

// DeriveKey derives a 32-byte key from a password using Argon2
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, Argon2Time, Argon2Memory, Argon2Threads, 32)
}

// EncryptPrivateKey encrypts a private key with a password
// Returns base64-encoded: salt || nonce || ciphertext
func EncryptPrivateKey(privateKey []byte, password string) (string, error) {
	// Generate random salt
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key from password
	key := DeriveKey(password, salt)
	var key32 [32]byte
	copy(key32[:], key)

	// Generate random nonce
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt using secretbox (XSalsa20-Poly1305)
	encrypted := secretbox.Seal(nil, privateKey, &nonce, &key32)

	// Concatenate: salt || nonce || ciphertext
	result := make([]byte, SaltLen+24+len(encrypted))
	copy(result[0:], salt)
	copy(result[SaltLen:], nonce[:])
	copy(result[SaltLen+24:], encrypted)

	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptPrivateKey decrypts a private key with a password
// Expects base64-encoded: salt || nonce || ciphertext
func DecryptPrivateKey(encryptedKey string, password string) ([]byte, error) {
	// Decode from base64
	data, err := base64.StdEncoding.DecodeString(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted key: %w", err)
	}

	// Check minimum length
	if len(data) < SaltLen+24 {
		return nil, fmt.Errorf("encrypted key too short")
	}

	// Extract salt, nonce, and ciphertext
	salt := data[0:SaltLen]
	var nonce [24]byte
	copy(nonce[:], data[SaltLen:SaltLen+24])
	ciphertext := data[SaltLen+24:]

	// Derive decryption key from password
	key := DeriveKey(password, salt)
	var key32 [32]byte
	copy(key32[:], key)

	// Decrypt using secretbox
	decrypted, ok := secretbox.Open(nil, ciphertext, &nonce, &key32)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt private key - incorrect password?")
	}

	return decrypted, nil
}
