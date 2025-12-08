package models

import "time"

// Account represents a user account with authentication
type Account struct {
	ID           string    `json:"id"`           // Unique account ID
	Username     string    `json:"username"`     // Username for login
	PasswordHash string    `json:"-"`            // Argon2 hashed password (not exposed in JSON)
	DisplayName  string    `json:"display_name"` // Display name
	CreatedAt    time.Time `json:"created_at"`   // When the account was created
	UpdatedAt    time.Time `json:"updated_at"`   // When the account was last updated
	Desks        []string  `json:"desks"`        // List of desk IDs (zIDs) this account owns
	ActiveDesk   string    `json:"active_desk"`  // Currently active desk ID

	// Security questions for password recovery (hashed answers)
	BirthdayHash     string `json:"-"` // Hash of birthday (YYYY-MM-DD format)
	FirstPetNameHash string `json:"-"` // Hash of first pet name
	MotherMaidenHash string `json:"-"` // Hash of mother's maiden name
}

// Desk represents a desk/identity that belongs to an account
type Desk struct {
	ID        string    `json:"id"`         // Phone-number-style ID (zID)
	AccountID string    `json:"account_id"` // Parent account ID
	PublicKey string    `json:"public_key"` // Curve25519 public key (base64)
	Name      string    `json:"name"`       // Display name for this desk
	CreatedAt time.Time `json:"created_at"` // When the desk was created

	// Settings for miv rendering
	AutoIndent        bool   `json:"auto_indent"`        // Enable auto-indent for epistle-style rendering
	FontFamily        string `json:"font_family"`        // Default font family
	FontSize          string `json:"font_size"`          // Default font size
	DefaultSalutation string `json:"default_salutation"` // Default salutation (e.g., "Dear [User]")
	DefaultClosure    string `json:"default_closure"`    // Default closure/signature
}

// RegisterRequest represents an account registration request
type RegisterRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=32"`
	Password    string `json:"password" binding:"required,min=8"`
	DisplayName string `json:"display_name" binding:"required"`

	// Security questions for password recovery
	Birthday     string `json:"birthday" binding:"required"`       // Format: YYYY-MM-DD
	FirstPetName string `json:"first_pet_name" binding:"required"` // First pet's name
	MotherMaiden string `json:"mother_maiden" binding:"required"`  // Mother's maiden name
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	Account *Account `json:"account"`
	Token   string   `json:"token"` // JWT token for authentication
}

// CreateDeskRequest represents a request to create a new desk
type CreateDeskRequest struct {
	Name string `json:"name" binding:"required"`
}

// SwitchDeskRequest represents a request to switch active desk
type SwitchDeskRequest struct {
	DeskID string `json:"desk_id" binding:"required"`
}

// RecoverPasswordRequest represents a password recovery request
type RecoverPasswordRequest struct {
	Username     string `json:"username" binding:"required"`
	Birthday     string `json:"birthday" binding:"required"`
	FirstPetName string `json:"first_pet_name" binding:"required"`
	MotherMaiden string `json:"mother_maiden" binding:"required"`
	NewPassword  string `json:"new_password" binding:"required,min=8"`
}

// UpdateDeskRequest represents a request to update desk settings
type UpdateDeskRequest struct {
	Name              *string `json:"name"`
	AutoIndent        *bool   `json:"auto_indent"`
	FontFamily        *string `json:"font_family"`
	FontSize          *string `json:"font_size"`
	DefaultSalutation *string `json:"default_salutation"`
	DefaultClosure    *string `json:"default_closure"`
}
