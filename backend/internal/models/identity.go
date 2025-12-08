package models

// Identity represents a user identity in the system
type Identity struct {
	ID        string `json:"id"`         // Phone-number-style ID
	PublicKey string `json:"public_key"` // Curve25519 public key (base64)
	Name      string `json:"name"`       // Optional display name
}
