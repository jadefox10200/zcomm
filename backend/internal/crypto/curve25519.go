package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// KeyPair represents a Curve25519 key pair
type KeyPair struct {
	PublicKey  [32]byte
	PrivateKey [32]byte
}

// GenerateKeyPair generates a new Curve25519 key pair
func GenerateKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	return &KeyPair{
		PublicKey:  *publicKey,
		PrivateKey: *privateKey,
	}, nil
}

// PublicKeyToBase64 converts a public key to base64 string
func PublicKeyToBase64(publicKey [32]byte) string {
	return base64.StdEncoding.EncodeToString(publicKey[:])
}

// PublicKeyFromBase64 converts a base64 string to a public key
func PublicKeyFromBase64(s string) ([32]byte, error) {
	var key [32]byte
	decoded, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return key, fmt.Errorf("failed to decode base64: %w", err)
	}
	if len(decoded) != 32 {
		return key, fmt.Errorf("invalid key length: %d", len(decoded))
	}
	copy(key[:], decoded)
	return key, nil
}

// Encrypt encrypts a message using Curve25519 (NaCl box)
func Encrypt(message []byte, recipientPublicKey, senderPrivateKey [32]byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	encrypted := box.Seal(nonce[:], message, &nonce, &recipientPublicKey, &senderPrivateKey)
	return encrypted, nil
}

// Decrypt decrypts a message using Curve25519 (NaCl box)
func Decrypt(encrypted []byte, senderPublicKey, recipientPrivateKey [32]byte) ([]byte, error) {
	if len(encrypted) < 24 {
		return nil, fmt.Errorf("encrypted message too short")
	}

	var nonce [24]byte
	copy(nonce[:], encrypted[:24])

	decrypted, ok := box.Open(nil, encrypted[24:], &nonce, &senderPublicKey, &recipientPrivateKey)
	if !ok {
		return nil, fmt.Errorf("failed to decrypt message")
	}

	return decrypted, nil
}

// SharedKey computes a shared secret using Curve25519
func SharedKey(publicKey, privateKey [32]byte) ([32]byte, error) {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &privateKey, &publicKey)
	return sharedKey, nil
}
