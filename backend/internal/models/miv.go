package models

import "time"

// MivState represents the state of a miv
type MivState string

const (
	StateIN         MivState = "IN"         // Received mivs in your inbox
	StatePENDING    MivState = "PENDING"    // Mivs I have looked at but not answered (automatically moved after opening to read)
	StateSENT       MivState = "SENT"       // Sent mivs that haven't received replies yet (combines old OUT and UNANSWERED)
	StateOUT        MivState = "OUT"        // DEPRECATED: Use SENT instead
	StateUNANSWERED MivState = "UNANSWERED" // DEPRECATED: Use SENT instead
	StateARCHIVED   MivState = "ARCHIVED"   // Conversations that have ended but can still be reviewed
	StateCC         MivState = "CC"         // CC copies of messages with limited interaction capabilities
)

// Miv represents a message in the Missiv system
type Miv struct {
	ID          string     `json:"id"`
	From        string     `json:"from"`                  // Phone-number-style sender ID
	To          string     `json:"to"`                    // Phone-number-style recipient ID
	Cc          []string   `json:"cc,omitempty"`          // CC recipient desk IDs
	Subject     string     `json:"subject"`               // Miv subject
	Body        string     `json:"body"`                  // Encrypted miv body
	State       MivState   `json:"state"`                 // Current state
	CreatedAt   time.Time  `json:"created_at"`            // When the miv was created
	SentAt      *time.Time `json:"sent_at,omitempty"`     // When the miv was sent
	ReceivedAt  *time.Time `json:"received_at,omitempty"` // When the miv was received
	IsEncrypted bool       `json:"is_encrypted"`          // Whether the body is encrypted
	FontFamily  *string    `json:"font_family,omitempty"` // Font family for message display
	FontSize    *string    `json:"font_size,omitempty"`   // Font size for message display
}

// CreateMivRequest represents a request to create a new miv
type CreateMivRequest struct {
	From       string    `json:"from,omitempty"`       // Optional sender display name
	To         string    `json:"to" binding:"required"`
	Cc         []string  `json:"cc,omitempty"`         // Optional CC recipients
	Subject    string    `json:"subject" binding:"required"`
	Body       string    `json:"body" binding:"required"`
	FontFamily *string   `json:"font_family,omitempty"` // Font family for message display
	FontSize   *string   `json:"font_size,omitempty"`   // Font size for message display
}

// UpdateStateRequest represents a request to update miv state
type UpdateStateRequest struct {
	State MivState `json:"state" binding:"required"`
}
