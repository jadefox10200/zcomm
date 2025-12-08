package models

import "time"

// NotificationType represents the type of notification
type NotificationType string

const (
	NotificationTypeReadReceipt NotificationType = "READ_RECEIPT" // Miv was read by recipient
	NotificationTypeNewMiv      NotificationType = "NEW_MIV"      // New miv received
	NotificationTypeReply       NotificationType = "REPLY"        // Reply to conversation
)

// Notification represents a notification for a desk
type Notification struct {
	ID             string           `json:"id"`                        // Unique notification ID
	DeskID         string           `json:"desk_id"`                   // Desk this notification is for
	Type           NotificationType `json:"type"`                      // Type of notification
	MivID          string           `json:"miv_id"`                    // Related miv ID
	ConversationID string           `json:"conversation_id,omitempty"` // Related conversation ID
	Message        string           `json:"message"`                   // Notification message
	Read           bool             `json:"read"`                      // Whether the notification has been read
	CreatedAt      time.Time        `json:"created_at"`                // When the notification was created
	ReadAt         *time.Time       `json:"read_at,omitempty"`         // When the notification was read
}

// CreateNotificationRequest represents a request to create a notification
type CreateNotificationRequest struct {
	DeskID         string           `json:"desk_id" binding:"required"`
	Type           NotificationType `json:"type" binding:"required"`
	MivID          string           `json:"miv_id" binding:"required"`
	ConversationID string           `json:"conversation_id"`
	Message        string           `json:"message" binding:"required"`
}

// MarkNotificationReadRequest represents a request to mark a notification as read
type MarkNotificationReadRequest struct {
	NotificationID string `json:"notification_id" binding:"required"`
}

// ListNotificationsResponse represents a list of notifications
type ListNotificationsResponse struct {
	Notifications []*Notification `json:"notifications"`
	UnreadCount   int             `json:"unread_count"`
	Total         int             `json:"total"`
}
