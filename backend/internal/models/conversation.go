package models

import "time"

// Conversation represents a threaded conversation
type Conversation struct {
	ID         string    `json:"id"`          // Unique conversation ID
	Subject    string    `json:"subject"`     // Conversation subject
	DeskID     string    `json:"desk_id"`     // Desk this conversation belongs to
	CreatedAt  time.Time `json:"created_at"`  // When the conversation was created
	UpdatedAt  time.Time `json:"updated_at"`  // When the conversation was last updated
	MivCount   int       `json:"miv_count"`   // Number of mivs in this conversation
	IsArchived bool      `json:"is_archived"` // Whether this conversation is archived
}

// MivType represents the type of miv
type MivType string

const (
	MivTypeMiv  MivType = "MIV"  // Regular message
	MivTypeCC   MivType = "CC"   // CC copy
	MivTypeVia  MivType = "VIA"  // Via routing intermediary
	MivTypeMemo MivType = "MEMO" // Memo (for future use)
)

// ConversationMiv represents a miv within a conversation thread
type ConversationMiv struct {
	ID             string     `json:"id"`
	ConversationID string     `json:"conversation_id"`       // Parent conversation ID
	Owner          string     `json:"owner"`                 // Desk ID that owns this copy of the miv
	SeqNo          int        `json:"seq_no"`                // Sequence number in conversation (1, 2, 3, ...)
	From           string     `json:"from"`                  // Sender desk ID
	To             string     `json:"to"`                    // Original recipient desk ID (for display)
	Cc             []string   `json:"cc,omitempty"`          // CC recipient desk IDs
	ArrowTo        string     `json:"arrow_to"`              // Who actually receives this piece of paper
	Type           MivType    `json:"type"`                  // Type of miv (MIV, CC, MEMO)
	Subject        string     `json:"subject"`               // Miv subject (usually conversation subject for replies)
	Body           string     `json:"body"`                  // Encrypted miv body
	State          MivState   `json:"state"`                 // Current state
	CreatedAt      time.Time  `json:"created_at"`            // When the miv was created
	SentAt         *time.Time `json:"sent_at,omitempty"`     // When the miv was sent
	ReceivedAt     *time.Time `json:"received_at,omitempty"` // When the miv was received
	ReadAt         *time.Time `json:"read_at,omitempty"`     // When the miv was read
	IsEncrypted    bool       `json:"is_encrypted"`          // Whether the body is encrypted
	IsAck          bool       `json:"is_ack"`                // Whether this is an ACK message
	IsForgotten    bool       `json:"is_forgotten"`          // Whether this miv has been forgotten (stops tracking replies)
	Deleted        bool       `json:"deleted"`               // Whether this miv has been deleted (hidden from all baskets)
	FontFamily     *string    `json:"font_family,omitempty"` // Font family for message display
	FontSize       *string    `json:"font_size,omitempty"`   // Font size for message display
	LineHeight     *string    `json:"line_height,omitempty"` // Line height for message display
	Via            []string   `json:"via,omitempty"`         // Via routing: array of intermediate desk IDs
	ViaIndex       int        `json:"via_index"`             // Current position in via routing (0-based)
	IsViaRejected  bool       `json:"is_via_rejected"`       // Whether via routing was rejected
	ViaRejectedBy  string     `json:"via_rejected_by,omitempty"` // Who rejected the via routing
	ViaRejection   string     `json:"via_rejection,omitempty"`   // Reason for via rejection
	RejectedMivID  string     `json:"rejected_miv_id,omitempty"` // ID of the original MIV if this is a rejection notice
}

// CreateConversationRequest represents a request to create a new conversation
type CreateConversationRequest struct {
	To         string    `json:"to" binding:"required"`
	Via        []string  `json:"via,omitempty"`        // Via routing: array of intermediate desk IDs
	Cc         []string  `json:"cc,omitempty"`         // Optional CC recipients
	Subject    string    `json:"subject" binding:"required"`
	Body       string    `json:"body" binding:"required"`
	FontFamily *string   `json:"font_family,omitempty"` // Font family for message display
	FontSize   *string   `json:"font_size,omitempty"`   // Font size for message display
	LineHeight *string   `json:"line_height,omitempty"` // Line height for message display
}

// ReplyToConversationRequest represents a request to reply in a conversation
type ReplyToConversationRequest struct {
	Body       string    `json:"body" binding:"required"`
	IsAck      bool      `json:"is_ack"`                // Whether this is an ACK message to end the conversation
	Cc         []string  `json:"cc,omitempty"`          // CC recipients (only for first reply in conversation)
	FontFamily *string   `json:"font_family,omitempty"` // Font family for message display
	FontSize   *string   `json:"font_size,omitempty"`   // Font size for message display
	LineHeight *string   `json:"line_height,omitempty"` // Line height for message display
}

// ListConversationsResponse represents a list of conversations with metadata
type ListConversationsResponse struct {
	Conversations []*ConversationWithLatest `json:"conversations"`
	Total         int                       `json:"total"`
}

// ConversationWithLatest includes conversation with latest miv info
type ConversationWithLatest struct {
	Conversation *Conversation    `json:"conversation"`
	LatestMiv    *ConversationMiv `json:"latest_miv,omitempty"`
	UnreadCount  int              `json:"unread_count"`
}

// ApproveViaRoutingRequest represents a request to approve via routing
type ApproveViaRoutingRequest struct {
	// No fields needed - desk_id comes from query parameter
}

// RejectViaRoutingRequest represents a request to reject via routing
type RejectViaRoutingRequest struct {
	Reason string `json:"reason" binding:"required"` // Reason for rejection
}

// GetConversationResponse represents a conversation with all its mivs
type GetConversationResponse struct {
	Conversation *Conversation      `json:"conversation"`
	Mivs         []*ConversationMiv `json:"mivs"`
}
