package crypto

import (
	"encoding/base64"
	"log"
)

// EncryptedMessageBodies holds the two encrypted copies of a message
type EncryptedMessageBodies struct {
	SenderBody    string // Base64-encoded encrypted body for sender
	RecipientBody string // Base64-encoded encrypted body for recipient
}

// GetSenderBody returns the sender's encrypted body, falling back to the legacy body field
func GetSenderBody(senderBody, legacyBody string) string {
	log.Printf("🔑 GetSenderBody called - senderBody len: %d, legacyBody len: %d", len(senderBody), len(legacyBody))
	if len(senderBody) > 20 {
		log.Printf("  senderBody preview: %s...", senderBody[:20])
	}
	if senderBody != "" {
		log.Printf("  ✓ Returning senderBody")
		return senderBody
	}
	log.Printf("  ⚠️  Falling back to legacyBody")
	return legacyBody
}

// GetRecipientBody returns the recipient's encrypted body, falling back to the legacy body field
func GetRecipientBody(recipientBody, legacyBody string) string {
	log.Printf("🔑 GetRecipientBody called - recipientBody len: %d, legacyBody len: %d", len(recipientBody), len(legacyBody))
	if len(recipientBody) > 20 {
		log.Printf("  recipientBody preview: %s...", recipientBody[:20])
	}
	if recipientBody != "" {
		log.Printf("  ✓ Returning recipientBody")
		return recipientBody
	}
	log.Printf("  ⚠️  Falling back to legacyBody")
	return legacyBody
}

// PrepareBodyForStorage prepares an encrypted message body for database storage
// The body should already be base64-encoded encrypted data from the frontend
// This function just validates and returns it directly - NO additional encoding
func PrepareBodyForStorage(encryptedBase64Body string) string {
	// The body is already base64-encoded encrypted data (nonce + ciphertext)
	// Just store it directly
	return encryptedBase64Body
}

// DecodeBodyFromStorage decodes a base64-encoded message body from database storage
func DecodeBodyFromStorage(encodedBody string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encodedBody)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}
