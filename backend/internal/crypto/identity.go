package crypto

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// GeneratePhoneStyleID generates a phone-number-style ID (e.g., "5551234567")
// Format: 10-digit number similar to US phone number
func GeneratePhoneStyleID() (string, error) {
	// Generate a 10-digit number
	// First digit: 2-9 (avoid 0 and 1)
	// Remaining digits: 0-9

	firstDigit, err := rand.Int(rand.Reader, big.NewInt(8))
	if err != nil {
		return "", fmt.Errorf("failed to generate first digit: %w", err)
	}

	id := fmt.Sprintf("%d", firstDigit.Int64()+2)

	for i := 0; i < 9; i++ {
		digit, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate digit: %w", err)
		}
		id += fmt.Sprintf("%d", digit.Int64())
	}

	return id, nil
}

// FormatPhoneStyleID formats an ID into a readable format (555) 123-4567
func FormatPhoneStyleID(id string) string {
	if len(id) != 10 {
		return id
	}
	return fmt.Sprintf("(%s) %s-%s", id[0:3], id[3:6], id[6:10])
}

// NormalizeDeskID removes non-digit characters from a desk ID for canonical matching
func NormalizeDeskID(id string) string {
	var normalized string
	for _, r := range id {
		if r >= '0' && r <= '9' {
			normalized += string(r)
		}
	}
	return normalized
}
