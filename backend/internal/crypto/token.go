package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateToken generates a simple random token for authentication
// In production, use a proper JWT library
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
