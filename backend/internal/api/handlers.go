package api

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
)

// Upload handler constants
const (
	maxFileSize         = 10 * 1024 * 1024 // 10MB
	maxFileExtLength    = 10               // Maximum length for file extension
	maxFilenameLength   = 100              // Maximum length for sanitized filename
)

// Compiled regex for filename sanitization (compiled once at package level)
var safeFilenameRegex = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// Account handlers

func (s *Server) registerAccount(c *gin.Context) {
	var req models.RegisterRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize username to lowercase
	req.Username = strings.ToLower(req.Username)

	// Hash the password
	passwordHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Hash security question answers
	birthdayHash, err := crypto.HashPassword(req.Birthday)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash security answers"})
		return
	}

	firstPetHash, err := crypto.HashPassword(req.FirstPetName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash security answers"})
		return
	}

	motherMaidenHash, err := crypto.HashPassword(req.MotherMaiden)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash security answers"})
		return
	}

	// Create account
	account := &models.Account{
		Username:         req.Username,
		PasswordHash:     passwordHash,
		DisplayName:      req.DisplayName,
		Desks:            []string{},
		BirthdayHash:     birthdayHash,
		FirstPetNameHash: firstPetHash,
		MotherMaidenHash: motherMaidenHash,
	}

	if err := s.storage.CreateAccount(account); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create first desk for the account
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key pair"})
		return
	}

	deskID, err := crypto.GeneratePhoneStyleID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate desk ID"})
		return
	}

	desk := &models.Desk{
		ID:                deskID,
		AccountID:         account.ID,
		PublicKey:         crypto.PublicKeyToBase64(keyPair.PublicKey),
		Name:              "Primary Desk",
		AutoIndent:        true,
		FontFamily:        "Georgia, serif",
		FontSize:          "14px",
		DefaultSalutation: "Dear [User],",
		DefaultClosure:    "Sincerely,",
	}

	if err := s.storage.CreateDesk(desk, keyPair.PrivateKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create desk"})
		return
	}

	// Update account with first desk
	account.Desks = []string{deskID}
	account.ActiveDesk = deskID
	if err := s.storage.UpdateAccount(account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update account"})
		return
	}

	// Generate token
	token, err := crypto.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusCreated, models.LoginResponse{
		Account: account,
		Token:   token,
	})
}

func (s *Server) loginAccount(c *gin.Context) {
	var req models.LoginRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize username to lowercase
	req.Username = strings.ToLower(req.Username)

	// Get account by username
	account, err := s.storage.GetAccountByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Verify password
	valid, err := crypto.VerifyPassword(req.Password, account.PasswordHash)
	if err != nil || !valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}

	// Generate token
	token, err := crypto.GenerateToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		Account: account,
		Token:   token,
	})
}

func (s *Server) recoverPassword(c *gin.Context) {
	var req models.RecoverPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Normalize username to lowercase
	req.Username = strings.ToLower(req.Username)

	// Get account by username
	account, err := s.storage.GetAccountByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or security answers"})
		return
	}

	// Verify all security answers
	validBirthday, err := crypto.VerifyPassword(req.Birthday, account.BirthdayHash)
	if err != nil || !validBirthday {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or security answers"})
		return
	}

	validPetName, err := crypto.VerifyPassword(req.FirstPetName, account.FirstPetNameHash)
	if err != nil || !validPetName {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or security answers"})
		return
	}

	validMaiden, err := crypto.VerifyPassword(req.MotherMaiden, account.MotherMaidenHash)
	if err != nil || !validMaiden {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials or security answers"})
		return
	}

	// Hash new password
	newPasswordHash, err := crypto.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash new password"})
		return
	}

	// Update password
	account.PasswordHash = newPasswordHash
	if err := s.storage.UpdateAccount(account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})
}

// Desk handlers

func (s *Server) listDesks(c *gin.Context) {
	// In a real implementation, get accountID from authenticated user
	// For now, list all desks
	accountID := c.Query("account_id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id is required"})
		return
	}

	desks, err := s.storage.ListDesksByAccount(accountID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, desks)
}

func (s *Server) createDesk(c *gin.Context) {
	var req models.CreateDeskRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// In a real implementation, get accountID from authenticated user
	accountID := c.Query("account_id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id is required"})
		return
	}

	// Generate key pair for the new desk
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key pair"})
		return
	}

	// Generate desk ID
	deskID, err := crypto.GeneratePhoneStyleID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate desk ID"})
		return
	}

	desk := &models.Desk{
		ID:                deskID,
		AccountID:         accountID,
		PublicKey:         crypto.PublicKeyToBase64(keyPair.PublicKey),
		Name:              req.Name,
		AutoIndent:        true,
		FontFamily:        "Georgia, serif",
		FontSize:          "14px",
		LineHeight:        "1.65",
		DefaultSalutation: "Dear [User],",
		DefaultClosure:    "Sincerely,",
	}

	if err := s.storage.CreateDesk(desk, keyPair.PrivateKey); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create desk"})
		return
	}

	// Update account's desk list
	account, err := s.storage.GetAccountByID(accountID)
	if err == nil {
		account.Desks = append(account.Desks, deskID)
		s.storage.UpdateAccount(account)
	}

	c.JSON(http.StatusCreated, desk)
}

func (s *Server) switchDesk(c *gin.Context) {
	var req models.SwitchDeskRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// In a real implementation, get accountID from authenticated user
	accountID := c.Query("account_id")
	if accountID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "account_id is required"})
		return
	}

	// Verify desk belongs to account
	desk, err := s.storage.GetDesk(req.DeskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}

	if desk.AccountID != accountID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Desk does not belong to account"})
		return
	}

	// Update active desk
	account, err := s.storage.GetAccountByID(accountID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Account not found"})
		return
	}

	account.ActiveDesk = req.DeskID
	if err := s.storage.UpdateAccount(account); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to switch desk"})
		return
	}

	c.JSON(http.StatusOK, account)
}

func (s *Server) updateDesk(c *gin.Context) {
	deskID := c.Param("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	var req models.UpdateDeskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing desk
	desk, err := s.storage.GetDesk(deskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}

	// TODO: Add authorization check to verify user owns this desk
	// This requires implementing proper authentication middleware

	// Update fields if provided
	if req.Name != nil {
		desk.Name = *req.Name
	}
	if req.AutoIndent != nil {
		desk.AutoIndent = *req.AutoIndent
	}
	if req.FontFamily != nil {
		desk.FontFamily = *req.FontFamily
	}
	if req.FontSize != nil {
		desk.FontSize = *req.FontSize
	}
	if req.LineHeight != nil {
		desk.LineHeight = *req.LineHeight
	}
	if req.DefaultSalutation != nil {
		desk.DefaultSalutation = *req.DefaultSalutation
	}
	if req.DefaultClosure != nil {
		desk.DefaultClosure = *req.DefaultClosure
	}

	if err := s.storage.UpdateDesk(desk); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update desk"})
		return
	}

	c.JSON(http.StatusOK, desk)
}

// Conversation handlers

func (s *Server) listConversations(c *gin.Context) {
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	conversations, err := s.storage.ListConversationsByDesk(deskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Build response with latest miv and unread count
	var response []*models.ConversationWithLatest
	for _, conv := range conversations {
		mivs, err := s.storage.GetConversationMivs(conv.ID)
		if err != nil {
			continue
		}

		var latestMiv *models.ConversationMiv
		unreadCount := 0
		if len(mivs) > 0 {
			latestMiv = mivs[len(mivs)-1]
			normalizedDeskID := crypto.NormalizeDeskID(deskID)
			for _, miv := range mivs {
				normalizedMivTo := crypto.NormalizeDeskID(miv.ArrowTo)
				isInCC := false
				for _, cc := range miv.Cc {
					if crypto.NormalizeDeskID(cc) == normalizedDeskID {
						isInCC = true
						break
					}
				}
				if (normalizedMivTo == normalizedDeskID || isInCC) && miv.ReadAt == nil {
					unreadCount++
				}
			}
		}

		response = append(response, &models.ConversationWithLatest{
			Conversation: conv,
			LatestMiv:    latestMiv,
			UnreadCount:  unreadCount,
		})
	}

	// Sort by updated_at descending
	sort.Slice(response, func(i, j int) bool {
		return response[i].Conversation.UpdatedAt.After(response[j].Conversation.UpdatedAt)
	})

	c.JSON(http.StatusOK, models.ListConversationsResponse{
		Conversations: response,
		Total:         len(response),
	})
}

func (s *Server) listArchivedConversations(c *gin.Context) {
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	conversations, err := s.storage.ListArchivedConversationsByDesk(deskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Build response with latest miv and unread count
	var response []*models.ConversationWithLatest
	for _, conv := range conversations {
		mivs, err := s.storage.GetConversationMivs(conv.ID)
		if err != nil {
			continue
		}

		var latestMiv *models.ConversationMiv
		unreadCount := 0
		if len(mivs) > 0 {
			latestMiv = mivs[len(mivs)-1]
			normalizedDeskID := crypto.NormalizeDeskID(deskID)
			for _, miv := range mivs {
				normalizedMivTo := crypto.NormalizeDeskID(miv.ArrowTo)
				isInCC := false
				for _, cc := range miv.Cc {
					if crypto.NormalizeDeskID(cc) == normalizedDeskID {
						isInCC = true
						break
					}
				}
				if (normalizedMivTo == normalizedDeskID || isInCC) && miv.ReadAt == nil {
					unreadCount++
				}
			}
		}

		response = append(response, &models.ConversationWithLatest{
			Conversation: conv,
			LatestMiv:    latestMiv,
			UnreadCount:  unreadCount,
		})
	}

	// Sort by updated_at descending
	sort.Slice(response, func(i, j int) bool {
		return response[i].Conversation.UpdatedAt.After(response[j].Conversation.UpdatedAt)
	})

	c.JSON(http.StatusOK, models.ListConversationsResponse{
		Conversations: response,
		Total:         len(response),
	})
}

func (s *Server) getConversation(c *gin.Context) {
	id := c.Param("id")
	deskID := c.Query("desk_id")

	conv, err := s.storage.GetConversation(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	mivs, err := s.storage.GetConversationMivs(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// If desk_id is provided, adjust miv states based on desk perspective
	if deskID != "" {
		normalizedDeskID := crypto.NormalizeDeskID(deskID)
		// Adjust states from the perspective of the querying desk
		for _, miv := range mivs {
			normalizedMivTo := crypto.NormalizeDeskID(miv.ArrowTo)
			if normalizedMivTo == normalizedDeskID {
				// For incoming mivs
				if miv.ReadAt == nil {
					miv.State = models.StateIN
				} else {
					// Check if we've replied to this miv
					hasReply := false
					for _, laterMiv := range mivs {
						if laterMiv.From == deskID && laterMiv.SeqNo > miv.SeqNo {
							hasReply = true
							break
						}
					}
					if !hasReply {
						miv.State = models.StatePENDING
					} else {
						// Has reply - clear the state so it doesn't appear in baskets
						miv.State = ""
					}
				}
			} else if miv.From == deskID {
				// For outgoing mivs, check if there's a reply or if it's forgotten
				hasReply := false
				for _, laterMiv := range mivs {
					if laterMiv.From != deskID && laterMiv.SeqNo > miv.SeqNo {
						hasReply = true
						break
					}
				}
				// Only show in SENT basket if not forgotten and no reply
				if !hasReply && !miv.IsForgotten {
					miv.State = models.StateSENT
				} else {
					// Has reply or is forgotten - clear the state so it doesn't appear in baskets
					miv.State = ""
				}
			}
		}

		// Note: Removed automatic marking as read when viewing conversation
		// Mivs must be explicitly marked as read using the /mivs/:id/read endpoint
	}

	c.JSON(http.StatusOK, models.GetConversationResponse{
		Conversation: conv,
		Mivs:         mivs,
	})
}

func (s *Server) createConversation(c *gin.Context) {
	// Read raw body for debugging
	bodyBytes, _ := io.ReadAll(c.Request.Body)
	log.Printf("DEBUG: Raw JSON body: %s", string(bodyBytes))
	// Restore body for binding
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	
	var req models.CreateConversationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Debug logging - log the actual values
	log.Printf("DEBUG createConversation request values:")
	if req.FontFamily != nil {
		log.Printf("  FontFamily: %s", *req.FontFamily)
	} else {
		log.Printf("  FontFamily: nil")
	}
	if req.FontSize != nil {
		log.Printf("  FontSize: %s", *req.FontSize)
	} else {
		log.Printf("  FontSize: nil")
	}
	if req.LineHeight != nil {
		log.Printf("  LineHeight: %s", *req.LineHeight)
	} else {
		log.Printf("  LineHeight: nil")
	}

	// Validate that recipient desk exists
	normalizedTo := crypto.NormalizeDeskID(req.To)
	_, err := s.storage.GetDesk(normalizedTo)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Recipient desk '%s' does not exist. Please verify the desk number and try again.", req.To)})
		return
	}

	// Validate that via recipient desks exist and are not the same as final recipient
	for _, viaRecipient := range req.Via {
		if viaRecipient != "" {
			normalizedVia := crypto.NormalizeDeskID(viaRecipient)
			_, err := s.storage.GetDesk(normalizedVia)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Via recipient desk '%s' does not exist. Please verify the desk number and try again.", viaRecipient)})
				return
			}
			// Check via recipient is not the same as final recipient
			if normalizedVia == normalizedTo {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Via recipient cannot be the same as the final recipient"})
				return
			}
		}
	}

	// Validate that CC recipient desks exist
	for _, ccRecipient := range req.Cc {
		if ccRecipient != "" {
			normalizedCc := crypto.NormalizeDeskID(ccRecipient)
			_, err := s.storage.GetDesk(normalizedCc)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("CC recipient desk '%s' does not exist. Please verify the desk number and try again.", ccRecipient)})
				return
			}
		}
	}

	// Create conversation
	conv := &models.Conversation{
		Subject: req.Subject,
		DeskID:  deskID,
	}

	if err := s.storage.CreateConversation(conv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create conversation"})
		return
	}

	// Create first miv (for primary recipient)
	// If via routing is specified, first recipient is the first via person
	actualRecipient := req.To
	if len(req.Via) > 0 {
		actualRecipient = req.Via[0] // First via recipient gets it first
	}

	miv := &models.ConversationMiv{
		ConversationID: conv.ID,
		SeqNo:          1,
		From:           deskID,
		To:             req.To, // Final recipient for display
		Cc:             req.Cc, // Include CC recipients in the miv
		ArrowTo:        actualRecipient, // Who actually receives this piece of paper NOW
		Type:           models.MivTypeMiv, // Regular message
		Subject:        req.Subject,
		Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
		State:          models.StateSENT, // Use SENT state for newly created mivs
		IsEncrypted:    false,
		FontFamily:     req.FontFamily,
		FontSize:       req.FontSize,
		LineHeight:     req.LineHeight,
		Via:            req.Via,   // Via routing array
		ViaIndex:       0,         // Start at first via recipient
		IsViaRejected:  false,
	}

	if err := s.storage.CreateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create miv"})
		return
	}

	// Create conversation for the actual current recipient so they can see the message
	normalizedRecipient := crypto.NormalizeDeskID(actualRecipient)
	recipientConv := &models.Conversation{
		Subject: req.Subject,
		DeskID:  normalizedRecipient, // Recipient owns their copy of the conversation
	}

	if err := s.storage.CreateConversation(recipientConv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create recipient conversation"})
		return
	}

	// Create the recipient's copy of the miv in their conversation
	recipientMiv := &models.ConversationMiv{
		ConversationID: recipientConv.ID, // Recipient's conversation
		SeqNo:          1,
		From:           deskID,
		To:             req.To,
		Cc:             req.Cc,
		ArrowTo:        normalizedRecipient,
		Type:           models.MivTypeMiv,
		Subject:        req.Subject,
		Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
		State:          models.StateIN, // IN state for recipient
		IsEncrypted:    false,
		FontFamily:     req.FontFamily,
		FontSize:       req.FontSize,
		LineHeight:     req.LineHeight,
		Via:            req.Via,
		ViaIndex:       0,
		IsViaRejected:  false,
	}

	if err := s.storage.CreateConversationMiv(recipientMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create recipient miv"})
		return
	}

	// Create notification for recipient (actual current recipient)
	notification := &models.Notification{
		DeskID:         normalizedRecipient, // Use normalized ID for routing
		Type:           models.NotificationTypeNewMiv,
		MivID:          recipientMiv.ID,
		ConversationID: recipientConv.ID, // Use recipient's conversation
		Message:        fmt.Sprintf("New message from %s: %s", deskID, req.Subject),
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	// Create CC copies of the miv for each CC recipient (SEPARATE conversations)
	for _, ccRecipient := range req.Cc {
		if ccRecipient != "" {
			normalizedCc := crypto.NormalizeDeskID(ccRecipient)
			
			// Create separate conversation for CC recipient
			ccConv := &models.Conversation{
				Subject: fmt.Sprintf("CC: %s", req.Subject), // Prefix subject to indicate CC
				DeskID:  ccRecipient, // CC recipient owns this conversation
			}

			if err := s.storage.CreateConversation(ccConv); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create CC conversation"})
				return
			}
			
			// Create CC copy of the miv in its own conversation
			ccMiv := &models.ConversationMiv{
				ConversationID: ccConv.ID, // Separate conversation
				SeqNo:          1, // First and only miv in this conversation
				From:           deskID,
				To:             req.To, // Original recipient for display
				Cc:             req.Cc, // Include all CC recipients for reference
				ArrowTo:        ccRecipient, // Who actually receives this piece of paper
				Type:           models.MivTypeCC, // CC copy
				Subject:        req.Subject,
				Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
				State:          models.StateCC, // CC state for limited interaction
				IsEncrypted:    false,
				FontFamily:     req.FontFamily,
				FontSize:       req.FontSize,
				LineHeight:     req.LineHeight,
				Via:            req.Via,   // Include via routing for display
				ViaIndex:       0,         // Via routing info for display only (CC doesn't participate in routing)
				IsViaRejected:  false,
			}

			if err := s.storage.CreateConversationMiv(ccMiv); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create CC miv"})
				return
			}

			// Create notification for CC recipient
			ccNotification := &models.Notification{
				DeskID:         normalizedCc,
				Type:           models.NotificationTypeNewMiv,
				MivID:          ccMiv.ID,
				ConversationID: ccConv.ID, // Separate conversation
				Message:        fmt.Sprintf("CC: New message from %s: %s", deskID, req.Subject),
				Read:           false,
			}
			s.storage.CreateNotification(ccNotification)
		}
	}

	// Return only the main conversation with the main miv
	c.JSON(http.StatusCreated, models.GetConversationResponse{
		Conversation: conv,
		Mivs:         []*models.ConversationMiv{miv},
	})
}

func (s *Server) replyToConversation(c *gin.Context) {
	conversationID := c.Param("id")

	var req models.ReplyToConversationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Get conversation
	conv, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// Get existing mivs to determine recipient
	mivs, err := s.storage.GetConversationMivs(conversationID)
	if err != nil || len(mivs) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Determine recipient (the other party in the conversation)
	var recipientID string
	var viaRecipients []string
	for _, m := range mivs {
		if m.From != deskID {
			recipientID = m.From
			// If the original message had via routing, reverse it for the reply
			if len(m.Via) > 0 {
				// Reverse the via array for reply routing
				viaRecipients = make([]string, len(m.Via))
				for i := range m.Via {
					viaRecipients[i] = m.Via[len(m.Via)-1-i]
				}
			}
			break
		}
		if m.To != deskID {
			recipientID = m.To
			// If the original message had via routing, reverse it for the reply
			if len(m.Via) > 0 {
				// Reverse the via array for reply routing
				viaRecipients = make([]string, len(m.Via))
				for i := range m.Via {
					viaRecipients[i] = m.Via[len(m.Via)-1-i]
				}
			}
			break
		}
	}

	if recipientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not determine recipient"})
		return
	}

	// Create CC copies of the reply for each CC recipient in separate conversations
	// Find CC recipients from conversation history
	var ccRecipients []string
	for _, m := range mivs {
		for _, cc := range m.Cc {
			if cc != "" && cc != recipientID && cc != deskID {
				// Check if not already in list
				found := false
				for _, existing := range ccRecipients {
					if existing == cc {
						found = true
						break
					}
				}
				if !found {
					ccRecipients = append(ccRecipients, cc)
				}
			}
		}
	}

	// Also add any new CC recipients from this reply
	for _, newCc := range req.Cc {
		if newCc != "" && newCc != recipientID && newCc != deskID {
			found := false
			for _, existing := range ccRecipients {
				if existing == newCc {
					found = true
					break
				}
			}
			if !found {
				ccRecipients = append(ccRecipients, newCc)
			}
		}
	}

	// Create reply miv with CC information and via routing
	// Determine the actual recipient based on via routing
	actualRecipient := recipientID
	if len(viaRecipients) > 0 {
		// If there's via routing, the first via recipient gets it
		actualRecipient = viaRecipients[0]
	}

	// Calculate next sequence number for sender's conversation
	nextSeqNo := len(mivs) + 1

	miv := &models.ConversationMiv{
		ConversationID: conversationID,
		SeqNo:          nextSeqNo, // Set explicit sequence number
		From:           deskID,
		To:             recipientID,
		Via:            viaRecipients, // Reversed via routing for reply
		ViaIndex:       0, // Start at beginning of via chain
		Cc:             ccRecipients, // Include all CC recipients from conversation history
		ArrowTo:        actualRecipient, // Who actually receives this reply (first via or final recipient)
		Type:           models.MivTypeMiv, // Regular message
		Subject:        conv.Subject,
		Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
		State:          models.StateSENT, // Use SENT state for replies
		IsEncrypted:    false,
		IsAck:          req.IsAck,
		FontFamily:     req.FontFamily,
		FontSize:       req.FontSize,
		LineHeight:     req.LineHeight,
	}

	if err := s.storage.CreateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create reply"})
		return
	}

	// CRITICAL: Create a copy of the reply in the recipient's conversation
	// Find the recipient's conversation with the same subject
	recipientConvs, err := s.storage.ListConversationsByDesk(recipientID)
	if err != nil {
		log.Printf("ERROR: Failed to get recipient conversations: %v", err)
	} else {
		var recipientConv *models.Conversation
		for _, rc := range recipientConvs {
			if rc.Subject == conv.Subject && rc.DeskID == recipientID {
				recipientConv = rc
				break
			}
		}

		if recipientConv != nil {
			// Get the next sequence number for recipient's conversation
			recipientMivs, err := s.storage.GetConversationMivs(recipientConv.ID)
			if err != nil {
				log.Printf("ERROR: Failed to get recipient mivs: %v", err)
			} else {
				nextSeqNo := len(recipientMivs) + 1

				// Create the reply miv in recipient's conversation
				recipientReplyMiv := &models.ConversationMiv{
					ConversationID: recipientConv.ID, // Recipient's conversation
					SeqNo:          nextSeqNo,
					From:           deskID,
					To:             recipientID,
					Via:            viaRecipients,
					ViaIndex:       0,
					Cc:             ccRecipients,
					ArrowTo:        recipientID, // Arrow points to recipient
					Type:           models.MivTypeMiv,
					Subject:        conv.Subject,
					Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
					State:          models.StateIN, // IN state for recipient
					IsEncrypted:    false,
					IsAck:          req.IsAck,
					FontFamily:     req.FontFamily,
					FontSize:       req.FontSize,
					LineHeight:     req.LineHeight,
				}

				if err := s.storage.CreateConversationMiv(recipientReplyMiv); err != nil {
					log.Printf("ERROR: Failed to create recipient reply miv: %v", err)
				} else {
					log.Printf("DEBUG: Created reply miv in recipient's conversation %s (seq %d)", recipientConv.ID, nextSeqNo)
				}
			}
		} else {
			log.Printf("ERROR: Could not find recipient conversation for %s with subject %s", recipientID, conv.Subject)
		}
	}

	// Create notification for the actual recipient (via or final)
	replyNotification := &models.Notification{
		DeskID:  actualRecipient,
		Message: fmt.Sprintf("New message in conversation: %s", conv.Subject),
		Type:    "conversation_reply",
	}
	if err := s.storage.CreateNotification(replyNotification); err != nil {
		log.Printf("Failed to create notification: %v", err)
	}

	log.Printf("DEBUG: Found %d CC recipients for reply: %v", len(ccRecipients), ccRecipients)

	// For each CC recipient, find their CC conversation and add the reply copy
	for _, ccRecipient := range ccRecipients {
		// Find the CC conversation for this recipient
		// CC conversations have subject "CC: Original Subject" and are owned by the CC recipient
		ccSubject := fmt.Sprintf("CC: %s", conv.Subject)
		
		log.Printf("DEBUG: Looking for CC conversation for recipient %s with subject %s", ccRecipient, ccSubject)
		
		// Get all conversations for this CC recipient
		ccConvs, err := s.storage.ListConversationsByDesk(ccRecipient)
		if err != nil {
			log.Printf("ERROR: Failed to get conversations for CC recipient %s: %v", ccRecipient, err)
			continue // Skip if can't get conversations
		}
		
		log.Printf("DEBUG: Found %d conversations for CC recipient %s", len(ccConvs), ccRecipient)
		
		var ccConv *models.Conversation
		for _, c := range ccConvs {
			log.Printf("DEBUG: Checking conversation %s with subject %s (owned by %s)", c.ID, c.Subject, c.DeskID)
			if c.Subject == ccSubject && c.DeskID == ccRecipient {
				ccConv = c
				log.Printf("DEBUG: Found matching CC conversation %s", c.ID)
				break
			}
		}
		
		if ccConv != nil {
			// Get existing mivs in CC conversation to determine next SeqNo
			ccMivs, err := s.storage.GetConversationMivs(ccConv.ID)
			if err != nil {
				log.Printf("ERROR: Failed to get mivs for CC conversation %s: %v", ccConv.ID, err)
				continue
			}
			
			nextSeqNo := len(ccMivs) + 1
			log.Printf("DEBUG: Creating CC reply miv #%d in conversation %s for recipient %s", nextSeqNo, ccConv.ID, ccRecipient)
			
			// Create CC copy of the reply
			ccReplyMiv := &models.ConversationMiv{
				ConversationID: ccConv.ID,
				SeqNo:          nextSeqNo,
				From:           deskID,
				To:             recipientID, // Original recipient for display
				Cc:             ccRecipients, // All CC recipients for reference
				ArrowTo:        ccRecipient, // Who receives this CC copy
				Type:           models.MivTypeCC, // CC copy
				Subject:        conv.Subject,
				Body:           base64.StdEncoding.EncodeToString([]byte(req.Body)),
				State:          models.StateCC, // CC state
				IsEncrypted:    false,
				IsAck:          req.IsAck,
				FontFamily:     req.FontFamily,
				FontSize:       req.FontSize,
				LineHeight:     req.LineHeight,
				Via:            viaRecipients, // Include via routing for display
				ViaIndex:       0,             // Via routing info for display only
				IsViaRejected:  false,
			}
			
			if err := s.storage.CreateConversationMiv(ccReplyMiv); err != nil {
				log.Printf("ERROR: Failed to create CC reply miv: %v", err)
				continue // Skip if can't create CC copy
			}
			
			log.Printf("DEBUG: Successfully created CC reply miv %s", ccReplyMiv.ID)
			
			// Create notification for CC recipient
			normalizedCc := crypto.NormalizeDeskID(ccRecipient)
			notifType := models.NotificationTypeReply
			message := fmt.Sprintf("CC Reply from %s in: %s", deskID, conv.Subject)
			if req.IsAck {
				message = fmt.Sprintf("CC ACK from %s in: %s", deskID, conv.Subject)
			}
			
			ccNotification := &models.Notification{
				DeskID:         normalizedCc,
				Type:           notifType,
				MivID:          ccReplyMiv.ID,
				ConversationID: ccConv.ID,
				Message:        message,
				Read:           false,
			}
			s.storage.CreateNotification(ccNotification)
			log.Printf("DEBUG: Created notification for CC recipient %s", normalizedCc)
		} else {
			log.Printf("ERROR: Could not find CC conversation for recipient %s with subject %s", ccRecipient, ccSubject)
		}
	}

	// If this is an ACK, archive the conversation for everyone
	if req.IsAck {
		// Archive sender's conversation
		conv.IsArchived = true
		s.storage.UpdateConversation(conv)
		
		// Archive recipient's conversation
		recipientConvs, err := s.storage.ListConversationsByDesk(recipientID)
		if err == nil {
			for _, rc := range recipientConvs {
				if rc.Subject == conv.Subject && rc.DeskID == recipientID {
					rc.IsArchived = true
					s.storage.UpdateConversation(rc)
					log.Printf("DEBUG: Archived recipient conversation %s for desk %s", rc.ID, recipientID)
					break
				}
			}
		}
		
		// Also archive CC conversations if this is an ACK
		for _, ccRecipient := range ccRecipients {
			ccSubject := fmt.Sprintf("CC: %s", conv.Subject)
			ccConvs, err := s.storage.ListConversationsByDesk(ccRecipient)
			if err != nil {
				continue
			}
			for _, c := range ccConvs {
				if c.Subject == ccSubject && c.DeskID == ccRecipient {
					c.IsArchived = true
					s.storage.UpdateConversation(c)
					break
				}
			}
		}
	} else if conv.IsArchived {
		// If conversation was archived but we got a non-ACK reply, unarchive it for everyone
		conv.IsArchived = false
		s.storage.UpdateConversation(conv)
		
		// Also unarchive CC conversations when replying from archive
		for _, ccRecipient := range ccRecipients {
			ccSubject := fmt.Sprintf("CC: %s", conv.Subject)
			ccConvs, err := s.storage.ListConversationsByDesk(ccRecipient)
			if err != nil {
				continue
			}
			for _, c := range ccConvs {
				if c.Subject == ccSubject && c.DeskID == ccRecipient {
					c.IsArchived = false
					s.storage.UpdateConversation(c)
					break
				}
			}
		}
	}

	// Create notification for recipient
	notifType := models.NotificationTypeReply
	message := fmt.Sprintf("Reply from %s in: %s", deskID, conv.Subject)
	if req.IsAck {
		message = fmt.Sprintf("ACK from %s in: %s", deskID, conv.Subject)
	}

	notification := &models.Notification{
		DeskID:         recipientID,
		Type:           notifType,
		MivID:          miv.ID,
		ConversationID: conversationID,
		Message:        message,
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	// Create notifications for all CC recipients (already handled above with CC copies)
	// The old code created notifications but not actual CC copies - now we create both

	c.JSON(http.StatusCreated, miv)
}

func (s *Server) archiveConversation(c *gin.Context) {
	conversationID := c.Param("id")

	// Get conversation
	conv, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// Archive the conversation
	conv.IsArchived = true
	if err := s.storage.UpdateConversation(conv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to archive conversation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Conversation archived successfully", "conversation": conv})
}

func (s *Server) deleteConversation(c *gin.Context) {
	conversationID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Get conversation
	conv, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// Verify the conversation belongs to the requesting desk
	if conv.DeskID != deskID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Not authorized to delete this conversation"})
		return
	}

	// Mark all mivs in this conversation as deleted for this desk
	if err := s.storage.DeleteConversationMivs(conversationID, deskID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete conversation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Conversation deleted successfully"})
}

// CC handlers

func (s *Server) answerCcMiv(c *gin.Context) {
	conversationID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Get conversation and mivs
	conv, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	mivs, err := s.storage.GetConversationMivs(conversationID)
	if err != nil || len(mivs) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Find the original sender (the one who sent the CC)
	var originalSender string
	for _, miv := range mivs {
		for _, cc := range miv.Cc {
			if cc == deskID {
				originalSender = miv.From
				break
			}
		}
		if originalSender != "" {
			break
		}
	}

	if originalSender == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No CC found for this desk"})
		return
	}

	// Create a new conversation between CC recipient and original sender
	newConv := &models.Conversation{
		Subject: fmt.Sprintf("Re: %s", conv.Subject),
		DeskID:  deskID,
	}

	if err := s.storage.CreateConversation(newConv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create conversation"})
		return
	}

	// Create first miv in the new conversation
	newMiv := &models.ConversationMiv{
		ConversationID: newConv.ID,
		SeqNo:          1,
		From:           deskID,
		To:             originalSender,
		Subject:        newConv.Subject,
		Body:           base64.StdEncoding.EncodeToString([]byte("Thank you for including me in the conversation.")), // Default response
		State:          models.StateSENT,
		IsEncrypted:    false,
	}

	if err := s.storage.CreateConversationMiv(newMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create miv"})
		return
	}

	// Create notification for the original sender
	normalizedSender := crypto.NormalizeDeskID(originalSender)
	notification := &models.Notification{
		DeskID:         normalizedSender,
		Type:           models.NotificationTypeNewMiv,
		MivID:          newMiv.ID,
		ConversationID: newConv.ID,
		Message:        fmt.Sprintf("New conversation from CC recipient %s: %s", deskID, newConv.Subject),
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	c.JSON(http.StatusCreated, models.GetConversationResponse{
		Conversation: newConv,
		Mivs:         []*models.ConversationMiv{newMiv},
	})
}

func (s *Server) deleteCcMiv(c *gin.Context) {
	conversationID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Get conversation and mivs
	conv, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	mivs, err := s.storage.GetConversationMivs(conversationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Find and mark CC mivs as forgotten for this desk
	normalizedDeskID := crypto.NormalizeDeskID(deskID)
	for _, miv := range mivs {
		for _, cc := range miv.Cc {
			if crypto.NormalizeDeskID(cc) == normalizedDeskID {
				miv.IsForgotten = true
				if err := s.storage.UpdateConversationMiv(miv); err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update miv"})
					return
				}
				break
			}
		}
	}

	// Archive the CC conversation for the recipient
	conv.IsArchived = true
	if err := s.storage.UpdateConversation(conv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to archive conversation"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "CC removed successfully"})
}

// Notification handlers

func (s *Server) listNotifications(c *gin.Context) {
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	unreadOnly := c.Query("unread_only") == "true"

	notifications, err := s.storage.ListNotificationsByDesk(deskID, unreadOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	unreadCount := 0
	for _, notif := range notifications {
		if !notif.Read {
			unreadCount++
		}
	}

	c.JSON(http.StatusOK, models.ListNotificationsResponse{
		Notifications: notifications,
		UnreadCount:   unreadCount,
		Total:         len(notifications),
	})
}

func (s *Server) markNotificationAsRead(c *gin.Context) {
	notificationID := c.Param("id")

	notif, err := s.storage.GetNotification(notificationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
		return
	}

	if err := s.storage.MarkNotificationAsRead(notificationID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notification as read"})
		return
	}

	// If it's a read receipt notification, update the miv state
	if notif.Type == models.NotificationTypeReadReceipt {
		// Get all conversation mivs
		mivs, err := s.storage.GetConversationMivs(notif.ConversationID)
		if err == nil {
			for _, miv := range mivs {
				if miv.ID == notif.MivID && miv.State == models.StateOUT {
					miv.State = models.StateUNANSWERED
					s.storage.UpdateConversationMiv(miv)
					break
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Notification marked as read"})
}

// Miv read handlers

func (s *Server) markMivAsRead(c *gin.Context) {
	mivID := c.Param("id")
	deskID := c.Query("desk_id")

	// If desk_id is not provided, try to get it from the active desk
	// For now, we require desk_id to be explicitly provided
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	if err := s.storage.MarkConversationMivAsRead(mivID, deskID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	// Get the updated miv to return
	miv, err := s.storage.GetConversationMiv(mivID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get updated miv"})
		return
	}

	c.JSON(http.StatusOK, miv)
}

// Miv forget handler

func (s *Server) forgetMiv(c *gin.Context) {
	mivID := c.Param("id")

	// Get the miv first to validate it exists
	miv, err := s.storage.GetConversationMiv(mivID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Miv not found"})
		return
	}

	// Mark the miv as forgotten
	miv.IsForgotten = true
	if err := s.storage.UpdateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to forget miv"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Miv forgotten successfully", "miv": miv})
}

// Contact handlers

func (s *Server) createContact(c *gin.Context) {
	deskID := c.Param("desk_id")

	var req models.CreateContactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify desk exists
	_, err := s.storage.GetDesk(deskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}

	contact := &models.Contact{
		DeskID:       deskID,
		Name:         req.Name,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		GreetingName: req.GreetingName,
		DeskIDRef:    req.DeskIDRef,
		Notes:        req.Notes,
	}

	if err := s.storage.CreateContact(contact); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create contact"})
		return
	}

	c.JSON(http.StatusCreated, contact)
}

func (s *Server) listContacts(c *gin.Context) {
	deskID := c.Param("desk_id")

	// Verify desk exists
	_, err := s.storage.GetDesk(deskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}

	contacts, err := s.storage.ListContactsForDesk(deskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list contacts"})
		return
	}

	response := &models.ListContactsResponse{
		Contacts: contacts,
		Total:    len(contacts),
	}

	c.JSON(http.StatusOK, response)
}

func (s *Server) getContact(c *gin.Context) {
	contactID := c.Param("contact_id")

	contact, err := s.storage.GetContact(contactID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Contact not found"})
		return
	}

	c.JSON(http.StatusOK, contact)
}

func (s *Server) updateContact(c *gin.Context) {
	contactID := c.Param("contact_id")

	var req models.UpdateContactRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get existing contact
	existing, err := s.storage.GetContact(contactID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Contact not found"})
		return
	}

	// Update fields
	if req.Name != "" {
		existing.Name = req.Name
	}
	// Always update optional fields to allow clearing
	existing.FirstName = req.FirstName
	existing.LastName = req.LastName
	existing.GreetingName = req.GreetingName
	if req.DeskIDRef != "" {
		existing.DeskIDRef = req.DeskIDRef
	}
	existing.Notes = req.Notes

	if err := s.storage.UpdateContact(existing); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update contact"})
		return
	}

	c.JSON(http.StatusOK, existing)
}

func (s *Server) deleteContact(c *gin.Context) {
	contactID := c.Param("contact_id")

	if err := s.storage.DeleteContact(contactID); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Contact not found"})
		return
	}

	c.JSON(http.StatusNoContent, nil)
}

// Upload handler - Production implementation
func (s *Server) uploadFile(c *gin.Context) {
	// Get the file from the request
	file, err := c.FormFile("upload")
	if err != nil {
		log.Printf("Upload error: No file in request - %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded"})
		return
	}

	// Validate file size (limit to 10MB)
	if file.Size > maxFileSize {
		log.Printf("Upload error: File too large - %d bytes (max: %d)", file.Size, maxFileSize)
		c.JSON(http.StatusBadRequest, gin.H{"error": "File too large. Maximum size is 10MB"})
		return
	}

	// Validate file type (only images)
	contentType := file.Header.Get("Content-Type")
	allowedTypes := map[string]string{
		"image/jpeg": ".jpg",
		"image/jpg":  ".jpg",
		"image/png":  ".png",
		"image/gif":  ".gif",
		"image/webp": ".webp",
	}

	expectedExt, validContentType := allowedTypes[contentType]
	if !validContentType {
		log.Printf("Upload error: Invalid content type - %s", contentType)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only images are allowed"})
		return
	}

	// Additional security: Validate file signature (magic bytes)
	// Note: This validates the file header but does not protect against polyglot files
	// (files with valid image headers but malicious payloads). For higher security,
	// consider re-encoding images or using a dedicated image validation library.
	// Open the file to read the first few bytes
	fileContent, err := file.Open()
	if err != nil {
		log.Printf("Upload error: Failed to open file - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file"})
		return
	}
	defer fileContent.Close()

	// Read the first 512 bytes for magic number validation
	buffer := make([]byte, 512)
	_, err = fileContent.Read(buffer)
	if err != nil {
		log.Printf("Upload error: Failed to read file header - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file header"})
		return
	}

	// Validate magic bytes for common image formats
	isValidImage := false
	detectedExt := ""
	
	// JPEG: FF D8 FF
	if len(buffer) >= 3 && buffer[0] == 0xFF && buffer[1] == 0xD8 && buffer[2] == 0xFF {
		isValidImage = true
		detectedExt = ".jpg"
	}
	// PNG: 89 50 4E 47
	if len(buffer) >= 4 && buffer[0] == 0x89 && buffer[1] == 0x50 && buffer[2] == 0x4E && buffer[3] == 0x47 {
		isValidImage = true
		detectedExt = ".png"
	}
	// GIF: 47 49 46
	if len(buffer) >= 3 && buffer[0] == 0x47 && buffer[1] == 0x49 && buffer[2] == 0x46 {
		isValidImage = true
		detectedExt = ".gif"
	}
	// WebP: 52 49 46 46 (RIFF) with "WEBP" at offset 8
	if len(buffer) >= 12 && buffer[0] == 0x52 && buffer[1] == 0x49 && buffer[2] == 0x46 && buffer[3] == 0x46 &&
		buffer[8] == 0x57 && buffer[9] == 0x45 && buffer[10] == 0x42 && buffer[11] == 0x50 {
		isValidImage = true
		detectedExt = ".webp"
	}

	if !isValidImage {
		log.Printf("Upload error: File magic bytes do not match any supported image format")
		c.JSON(http.StatusBadRequest, gin.H{"error": "File is not a valid image"})
		return
	}

	// Validate that the detected file type matches the declared content type
	if detectedExt != expectedExt {
		log.Printf("Upload error: Content-Type mismatch - declared: %s (%s), detected: %s", 
			contentType, expectedExt, detectedExt)
		c.JSON(http.StatusBadRequest, gin.H{"error": "File type mismatch. The file content does not match the declared type"})
		return
	}

	// Sanitize the original filename to prevent path traversal attacks
	// Use a whitelist approach: only allow alphanumeric, dash, underscore, and dot
	sanitizedFilename := sanitizeFilename(file.Filename)
	
	// Extract and validate the file extension
	ext := filepath.Ext(sanitizedFilename)
	if ext == "" || len(ext) > maxFileExtLength {
		// If no extension or suspicious extension, use the detected one
		ext = detectedExt
	}

	// Generate cryptographically secure unique filename
	uniqueID, err := generateUniqueID()
	if err != nil {
		log.Printf("Upload error: Failed to generate unique ID - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate unique filename"})
		return
	}

	// Construct filename: uniqueID + timestamp + extension
	filename := fmt.Sprintf("%s_%d%s", uniqueID, time.Now().Unix(), ext)

	// Define upload directory (configurable via environment variable)
	uploadDir := os.Getenv("UPLOAD_DIR")
	if uploadDir == "" {
		uploadDir = "./uploads"
	}

	// Create uploads directory if it doesn't exist
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		log.Printf("Upload error: Failed to create upload directory - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create upload directory"})
		return
	}

	// Use filepath.Join for safe path construction
	filePath := filepath.Join(uploadDir, filename)
	
	// Additional security: Ensure the final path is still within the upload directory
	absUploadDir, err := filepath.Abs(uploadDir)
	if err != nil {
		log.Printf("Upload error: Failed to get absolute path of upload directory - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		log.Printf("Upload error: Failed to get absolute path of file - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	
	if !strings.HasPrefix(absFilePath, absUploadDir) {
		log.Printf("Upload error: Path traversal attempt detected - file path outside upload directory")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid filename"})
		return
	}

	// Save the file
	if err := c.SaveUploadedFile(file, filePath); err != nil {
		log.Printf("Upload error: Failed to save file - %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}

	// Return the full URL where the file can be accessed
	// Get server URL from environment or use default
	// Note: For production deployments, SERVER_URL should be set to prevent
	// Host header injection attacks. The Host header fallback is only for development.
	serverURL := os.Getenv("SERVER_URL")
	if serverURL == "" {
		// Construct from request or use default (development only)
		// WARNING: In production, always set SERVER_URL environment variable
		// to avoid potential Host header injection vulnerabilities
		scheme := "http"
		if c.Request.TLS != nil {
			scheme = "https"
		}
		host := c.Request.Host
		if host == "" {
			host = "localhost:8080"
		}
		serverURL = fmt.Sprintf("%s://%s", scheme, host)
	}
	
	fileURL := fmt.Sprintf("%s/uploads/%s", serverURL, filename)
	
	log.Printf("File uploaded successfully: %s (size: %d bytes, type: %s)", filename, file.Size, contentType)

	c.JSON(http.StatusOK, gin.H{
		"url": fileURL,
	})
}

// sanitizeFilename removes potentially dangerous characters from filenames
// Only allows alphanumeric characters, dots, hyphens, and underscores
func sanitizeFilename(filename string) string {
	// Remove any path components
	filename = filepath.Base(filename)
	
	// Replace spaces with underscores
	filename = strings.ReplaceAll(filename, " ", "_")
	
	// Use package-level regex to keep only safe characters: alphanumeric, dot, hyphen, underscore
	filename = safeFilenameRegex.ReplaceAllString(filename, "")
	
	// Prevent filenames that start with a dot (hidden files)
	if strings.HasPrefix(filename, ".") {
		filename = "file" + filename
	}
	
	// Limit filename length using package-level constant
	if len(filename) > maxFilenameLength {
		ext := filepath.Ext(filename)
		nameWithoutExt := strings.TrimSuffix(filename, ext)
		if len(nameWithoutExt) > maxFilenameLength-len(ext) {
			nameWithoutExt = nameWithoutExt[:maxFilenameLength-len(ext)]
		}
		filename = nameWithoutExt + ext
	}
	
	return filename
}

// generateUniqueID creates a cryptographically secure random identifier
func generateUniqueID() (string, error) {
	bytes := make([]byte, 16) // 128 bits of randomness
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Via routing handlers

func (s *Server) approveViaRouting(c *gin.Context) {
	mivID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Get the miv
	miv, err := s.storage.GetConversationMiv(mivID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Miv not found"})
		return
	}

	// Verify this user is the current via recipient
	if len(miv.Via) == 0 || miv.ViaIndex >= len(miv.Via) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This miv is not in via routing"})
		return
	}

	currentViaRecipient := miv.Via[miv.ViaIndex]
	normalizedDesk := crypto.NormalizeDeskID(deskID)
	normalizedVia := crypto.NormalizeDeskID(currentViaRecipient)
	if normalizedDesk != normalizedVia {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to approve this via routing"})
		return
	}

	// Move to next recipient
	miv.ViaIndex++
	
	// Reset the state to IN for the next recipient (whether via intermediary or final recipient)
	// This ensures the MIV appears in the next person's IN basket
	miv.State = models.StateIN
	miv.ReadAt = nil  // Clear read timestamp so it shows as unread for next recipient
	
	// Determine next recipient
	if miv.ViaIndex < len(miv.Via) {
		// Forward to next via recipient
		miv.ArrowTo = miv.Via[miv.ViaIndex]
		nextRecipient := crypto.NormalizeDeskID(miv.ArrowTo)
		
		// Create notification for next via recipient
		notification := &models.Notification{
			DeskID:         nextRecipient,
			Type:           models.NotificationTypeReply,
			MivID:          miv.ID,
			ConversationID: miv.ConversationID,
			Message:        fmt.Sprintf("Via routing from %s: %s", deskID, miv.Subject),
			Read:           false,
		}
		s.storage.CreateNotification(notification)
	} else {
		// Reached the end of via chain, deliver to final recipient
		miv.ArrowTo = miv.To
		finalRecipient := crypto.NormalizeDeskID(miv.To)
		
		// Create notification for final recipient
		notification := &models.Notification{
			DeskID:         finalRecipient,
			Type:           models.NotificationTypeNewMiv,
			MivID:          miv.ID,
			ConversationID: miv.ConversationID,
			Message:        fmt.Sprintf("New message from %s: %s", miv.From, miv.Subject),
			Read:           false,
		}
		s.storage.CreateNotification(notification)
	}

	// Update the miv
	if err := s.storage.UpdateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update miv"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Via routing approved", "miv": miv})
}

func (s *Server) rejectViaRouting(c *gin.Context) {
	mivID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	var req models.RejectViaRoutingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the miv
	miv, err := s.storage.GetConversationMiv(mivID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Miv not found"})
		return
	}

	// Verify this user is the current via recipient
	if len(miv.Via) == 0 || miv.ViaIndex >= len(miv.Via) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This miv is not in via routing"})
		return
	}

	currentViaRecipient := miv.Via[miv.ViaIndex]
	normalizedDesk := crypto.NormalizeDeskID(deskID)
	normalizedVia := crypto.NormalizeDeskID(currentViaRecipient)
	if normalizedDesk != normalizedVia {
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to reject this via routing"})
		return
	}

	// Get all mivs to determine next sequence number
	mivs, err := s.storage.GetConversationMivs(miv.ConversationID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}
	nextSeqNo := len(mivs) + 1

	// Create a rejection message body
	rejectionBody := fmt.Sprintf("<p><strong>Via Routing Rejected</strong></p><p>Your message was rejected by %s during via routing.</p><p><strong>Reason:</strong> %s</p><p><strong>Original Subject:</strong> %s</p>", deskID, req.Reason, miv.Subject)

	// Create a new MIV in the conversation as a rejection notice
	// This will arrive in the sender's IN basket like a normal reply
	rejectionMiv := &models.ConversationMiv{
		ConversationID: miv.ConversationID,
		SeqNo:          nextSeqNo,
		From:           deskID,           // From the person who rejected
		To:             miv.From,         // To the original sender
		ArrowTo:        miv.From,         // Deliver to sender
		Type:           "MIV",
		Subject:        fmt.Sprintf("REJECTED: %s", miv.Subject),
		Body:           base64.StdEncoding.EncodeToString([]byte(rejectionBody)),
		State:          models.StateIN,   // Will arrive in sender's IN basket
		IsEncrypted:    false,
		IsAck:          true,             // Mark as ACK-like so it doesn't show in rejector's OUT basket
		FontFamily:     miv.FontFamily,
		FontSize:       miv.FontSize,
		LineHeight:     miv.LineHeight,
		Via:            []string{},       // No via routing on the rejection
		ViaIndex:       0,
		IsViaRejected:  false,
		RejectedMivID:  miv.ID,          // Store reference to original MIV for resubmit
	}

	if err := s.storage.CreateConversationMiv(rejectionMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rejection miv"})
		return
	}

	// Mark the original miv as forgotten so it doesn't show up in anyone's baskets anymore
	miv.IsForgotten = true
	if err := s.storage.UpdateConversationMiv(miv); err != nil {
		log.Printf("ERROR: Failed to mark original miv as forgotten: %v", err)
	}

	// Create notification for sender about rejection
	normalizedSender := crypto.NormalizeDeskID(miv.From)
	message := fmt.Sprintf("Via routing rejected by %s: %s", deskID, miv.Subject)

	notification := &models.Notification{
		DeskID:         normalizedSender,
		Type:           models.NotificationTypeReply,
		MivID:          rejectionMiv.ID,
		ConversationID: miv.ConversationID,
		Message:        message,
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	// Send rejection notices to all CC recipients
	// Each CC recipient gets a copy in their own CC conversation
	if len(miv.Cc) > 0 {
		log.Printf("DEBUG: Sending rejection notices to %d CC recipients", len(miv.Cc))
		
		for _, ccRecipient := range miv.Cc {
			if ccRecipient == "" || ccRecipient == miv.From || ccRecipient == deskID {
				continue // Skip empty, sender, and rejector
			}
			
			normalizedCc := crypto.NormalizeDeskID(ccRecipient)
			
			// Find the CC conversation for this recipient
			conv, err := s.storage.GetConversation(miv.ConversationID)
			if err != nil {
				log.Printf("ERROR: Failed to get conversation for CC rejection: %v", err)
				continue
			}
			
			ccSubject := fmt.Sprintf("CC: %s", conv.Subject)
			
			// Get all conversations for this CC recipient to find their CC conversation
			ccConvs, err := s.storage.ListConversationsByDesk(ccRecipient)
			if err != nil {
				log.Printf("ERROR: Failed to get conversations for CC recipient %s: %v", ccRecipient, err)
				continue
			}
			
			var ccConv *models.Conversation
			for _, c := range ccConvs {
				if c.Subject == ccSubject && c.DeskID == ccRecipient {
					ccConv = c
					break
				}
			}
			
			if ccConv != nil {
				// Get existing mivs in CC conversation to determine next SeqNo
				ccMivs, err := s.storage.GetConversationMivs(ccConv.ID)
				if err != nil {
					log.Printf("ERROR: Failed to get mivs for CC conversation %s: %v", ccConv.ID, err)
					continue
				}
				
				ccNextSeqNo := len(ccMivs) + 1
				
				// Create CC copy of the rejection notice
				ccRejectionMiv := &models.ConversationMiv{
					ConversationID: ccConv.ID,
					SeqNo:          ccNextSeqNo,
					From:           deskID,
					To:             miv.From,
					Cc:             miv.Cc,
					ArrowTo:        ccRecipient,
					Type:           models.MivTypeCC,
					Subject:        fmt.Sprintf("REJECTED: %s", conv.Subject),
					Body:           base64.StdEncoding.EncodeToString([]byte(rejectionBody)),
					State:          models.StateCC,
					IsEncrypted:    false,
					IsAck:          false, // CC recipients see it as a regular message
					FontFamily:     miv.FontFamily,
					FontSize:       miv.FontSize,
					LineHeight:     miv.LineHeight,
					Via:            miv.Via,
					ViaIndex:       miv.ViaIndex,
					IsViaRejected:  false,
					RejectedMivID:  miv.ID,
				}
				
				if err := s.storage.CreateConversationMiv(ccRejectionMiv); err != nil {
					log.Printf("ERROR: Failed to create CC rejection miv: %v", err)
					continue
				}
				
				log.Printf("DEBUG: Created CC rejection miv %s for recipient %s", ccRejectionMiv.ID, ccRecipient)
				
				// Create notification for CC recipient
				ccNotification := &models.Notification{
					DeskID:         normalizedCc,
					Type:           models.NotificationTypeReply,
					MivID:          ccRejectionMiv.ID,
					ConversationID: ccConv.ID,
					Message:        fmt.Sprintf("CC: Via routing rejected by %s: %s", deskID, conv.Subject),
					Read:           false,
				}
				s.storage.CreateNotification(ccNotification)
			} else {
				log.Printf("DEBUG: No CC conversation found for recipient %s with subject %s", ccRecipient, ccSubject)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Via routing rejected", "miv": rejectionMiv})
}
