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

// In-memory token store for mapping tokens to account IDs (for demo/prototype only)
var tokenStore = make(map[string]string)

// authMiddleware validates the Authorization header and extracts account ID
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid Authorization header"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		accountID, ok := tokenStore[token]
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			c.Abort()
			return
		}

		// Store account ID in context for handlers to use
		c.Set("account_id", accountID)
		c.Next()
	}
}

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
		AutoIndent:        false,
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

	// Return success message - user needs to login
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Account created successfully. Please login.",
		"username": account.Username,
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
	// Store token -> account ID
	tokenStore[token] = account.ID

	// Get encrypted private keys for all desks
	encryptedPrivKeys := make(map[string]string)
	for _, deskID := range account.Desks {
		encryptedKey, err := s.storage.GetDeskEncryptedPrivateKey(deskID, req.Password)
		if err != nil {
			log.Printf("Failed to encrypt private key for desk %s: %v", deskID, err)
			// Continue with other desks - this desk won't have encryption capability
			continue
		}
		encryptedPrivKeys[deskID] = encryptedKey
	}

	c.JSON(http.StatusOK, models.LoginResponse{
		Account:           account,
		Token:             token,
		EncryptedPrivKeys: encryptedPrivKeys,
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

	// Get account ID from middleware
	accountID, exists := c.Get("account_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get existing desk
	desk, err := s.storage.GetDesk(deskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}
	if desk.AccountID != accountID.(string) {
		c.JSON(http.StatusForbidden, gin.H{"error": "You do not own this desk"})
		return
	}

	var req models.UpdateDeskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

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

// getDeskPublicKey returns the public key for a desk (for E2E encryption)
func (s *Server) getDeskPublicKey(c *gin.Context) {
	deskID := c.Param("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Normalize desk ID for lookup
	normalizedDeskID := crypto.NormalizeDeskID(deskID)

	// Get desk
	desk, err := s.storage.GetDesk(normalizedDeskID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Desk not found"})
		return
	}

	// Return public key only (no authentication required - public keys are public)
	c.JSON(http.StatusOK, gin.H{
		"desk_id":    desk.ID,
		"public_key": desk.PublicKey,
	})
}

// getBatchDeskPublicKeys returns public keys for multiple desks (for CC encryption)
func (s *Server) getBatchDeskPublicKeys(c *gin.Context) {
	var req struct {
		DeskIDs []string `json:"desk_ids" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Limit batch size to prevent abuse
	if len(req.DeskIDs) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Maximum 50 desk IDs per request"})
		return
	}

	// Fetch public keys
	publicKeys := make(map[string]string)
	for _, deskID := range req.DeskIDs {
		normalizedDeskID := crypto.NormalizeDeskID(deskID)
		desk, err := s.storage.GetDesk(normalizedDeskID)
		if err != nil {
			// Skip desks that don't exist
			continue
		}
		publicKeys[normalizedDeskID] = desk.PublicKey
	}

	c.JSON(http.StatusOK, gin.H{
		"public_keys": publicKeys,
	})
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
		mivs, err := s.storage.GetConversationMivs(conv.ID, deskID)
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
		mivs, err := s.storage.GetConversationMivs(conv.ID, deskID)
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

	// SECURITY: Pass ownerID to filter at database level - users can ONLY see their own mivs
	var mivs []*models.ConversationMiv
	if deskID != "" {
		normalizedDeskID := crypto.NormalizeDeskID(deskID)
		mivs, err = s.storage.GetConversationMivs(id, normalizedDeskID)
	} else {
		// If no desk_id provided, return empty list for security
		mivs = []*models.ConversationMiv{}
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// If desk_id is provided, adjust miv states based on desk perspective
	if deskID != "" {
		normalizedDeskID := crypto.NormalizeDeskID(deskID)
		// Adjust states from the perspective of the querying desk
		for _, miv := range mivs {
			// Skip state recalculation for certain permanent states
			if miv.State == models.StateREMOVED {
				// Don't recalculate - this miv has been explicitly removed
				continue
			}
			
			normalizedFrom := crypto.NormalizeDeskID(miv.From)
			normalizedMivTo := crypto.NormalizeDeskID(miv.ArrowTo)
			
			// Check if this miv is FROM the querying desk first (outgoing)
			if normalizedFrom == normalizedDeskID {
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
			} else if normalizedMivTo == normalizedDeskID {
				// For incoming mivs (from someone else, to me)
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
	log.Printf("🔍 DEBUG: Raw JSON body length: %d bytes", len(bodyBytes))
	log.Printf("🔍 DEBUG: Raw JSON body: %s", string(bodyBytes))
	
	// Check if cc_bodies exists in raw JSON
	if strings.Contains(string(bodyBytes), "cc_bodies") {
		log.Printf("✅ cc_bodies found in raw JSON")
	} else {
		log.Printf("❌ cc_bodies NOT found in raw JSON")
	}
	
	// Restore body for binding
	c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	
	var req models.CreateConversationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// DEBUG: Log parsed fields
	log.Printf("🔍 DEBUG createConversation - PARSED request:")
	log.Printf("  SenderBody: %d chars", len(req.SenderBody))
	log.Printf("  RecipientBody: %d chars", len(req.RecipientBody))
	log.Printf("  Are they identical? %v", req.SenderBody == req.RecipientBody)
	log.Printf("  CC recipients: %v", req.Cc)
	log.Printf("  CcBodies map is nil: %v", req.CcBodies == nil)
	if req.CcBodies != nil {
		log.Printf("  CcBodies map size: %d", len(req.CcBodies))
		for k, v := range req.CcBodies {
			log.Printf("    CC[%s]: %d chars (prefix: %s)", k, len(v), v[:min(40, len(v))])
		}
	}

	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Prevent sending, CCing, or via-routing to self
	normalizedDeskID := crypto.NormalizeDeskID(deskID)
	normalizedTo := crypto.NormalizeDeskID(req.To)
	if normalizedTo == normalizedDeskID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot send a message to yourself."})
		return
	}
	for _, ccRecipient := range req.Cc {
		if ccRecipient != "" && crypto.NormalizeDeskID(ccRecipient) == normalizedDeskID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot CC yourself."})
			return
		}
	}
	for _, viaRecipient := range req.Via {
		if viaRecipient != "" && crypto.NormalizeDeskID(viaRecipient) == normalizedDeskID {
			c.JSON(http.StatusBadRequest, gin.H{"error": "You cannot route a message via yourself."})
			return
		}
	}

	// Debug logging - log the actual values
	log.Printf("DEBUG createConversation request values:")
	log.Printf("  IsEncrypted: %v", req.IsEncrypted)
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
	normalizedTo = crypto.NormalizeDeskID(req.To)
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

	// Determine who gets the message first (via routing or direct recipient)
	actualRecipient := req.To
	if len(req.Via) > 0 {
		actualRecipient = req.Via[0] // First via recipient gets it first
	}
	normalizedRecipient := crypto.NormalizeDeskID(actualRecipient)

	// Determine the type for the first recipient
	// If they are a via intermediary (not the final recipient), mark as VIA
	firstRecipientType := models.MivTypeMiv
	if len(req.Via) > 0 && actualRecipient != req.To {
		firstRecipientType = models.MivTypeVia
	}

	// Create SENDER's miv (state = SENT) in the shared conversation
	senderMiv := &models.ConversationMiv{
		ConversationID: conv.ID, // Shared conversation ID
		Owner:          deskID,  // Sender owns this copy
		SeqNo:          1,
		From:           deskID,
		To:             req.To, // Final recipient for display
		Cc:             req.Cc,
		ArrowTo:        deskID, // Arrow points back to sender for their SENT basket
		Type:           models.MivTypeMiv,
		Subject:        req.Subject,
		Body:           req.SenderBody, // Store sender's encrypted body directly
		State:          models.StateSENT, // Sender sees SENT
		IsEncrypted:    true,  // All messages are E2E encrypted
		FontFamily:     req.FontFamily,
		FontSize:       req.FontSize,
		LineHeight:     req.LineHeight,
		Via:            req.Via,
		ViaIndex:       0,
		IsViaRejected:  false,
	}

	if err := s.storage.CreateConversationMiv(senderMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create sender miv"})
		return
	}

	// Create RECIPIENT's miv (state = IN) in the same shared conversation
	recipientMiv := &models.ConversationMiv{
		ConversationID: conv.ID,                 // Same shared conversation ID
		Owner:          normalizedRecipient,      // Recipient owns this copy
		SeqNo:          1,                        // Same sequence number as sender's
		From:           deskID,
		To:             req.To, // Final recipient for display
		Cc:             req.Cc,
		ArrowTo:        actualRecipient,      // Arrow points to actual recipient (via or final)
		Type:           firstRecipientType,   // VIA if intermediary, MIV if final recipient
		Subject:        req.Subject,
		Body:           req.RecipientBody, // Store recipient's encrypted body directly
		State:          models.StateIN, // Recipient sees IN
		IsEncrypted:    true,  // All messages are E2E encrypted
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

	// Create notification for recipient
	notification := &models.Notification{
		DeskID:         normalizedRecipient,
		Type:           models.NotificationTypeNewMiv,
		MivID:          recipientMiv.ID,
		ConversationID: conv.ID, // Use the shared conversation
		Message:        fmt.Sprintf("New message from %s: %s", deskID, req.Subject),
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	// Create CC copies of the miv for each CC recipient in the SAME conversation
	for _, ccRecipient := range req.Cc {
		if ccRecipient != "" {
			log.Printf("🔍 Processing CC recipient: %s", ccRecipient)
			
			// Get CC-specific encrypted body from the map
			if req.CcBodies == nil {
				log.Printf("❌ ERROR: CcBodies map is nil but CC recipients exist")
				c.JSON(http.StatusBadRequest, gin.H{"error": "CC recipients specified but no CC bodies provided"})
				return
			}
			
			ccBody, ok := req.CcBodies[ccRecipient]
			if !ok || ccBody == "" {
				log.Printf("❌ ERROR: No encrypted body found for CC recipient %s", ccRecipient)
				log.Printf("   Available keys in CcBodies: %v", func() []string { keys := []string{}; for k := range req.CcBodies { keys = append(keys, k) }; return keys }())
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("No encrypted body for CC recipient %s", ccRecipient)})
				return
			}
			
			log.Printf("  ✅ Found CC-specific body: %s", ccBody[:min(40, len(ccBody))])
			
			ccMiv := &models.ConversationMiv{
				ConversationID: conv.ID, // SAME conversation as sender/recipient
				Owner:          ccRecipient, // CRITICAL: CC recipient owns their copy
				SeqNo:          1, // First miv from CC recipient's perspective
				From:           deskID,
				To:             req.To, // Original recipient for display
				Cc:             req.Cc, // Include all CC recipients for reference
				ArrowTo:        ccRecipient, // Arrow points to CC recipient
				Type:           models.MivTypeCC, // CC copy
				Subject:        req.Subject,
				Body:           ccBody, // Use CC recipient's own encrypted body
				State:          models.StateIN, // CC mivs start in IN state
				IsEncrypted:    true,  // All messages are E2E encrypted
				IsAck:          false,
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
				DeskID:         ccRecipient,
				Type:           models.NotificationTypeNewMiv,
				MivID:          ccMiv.ID,
				ConversationID: conv.ID, // SAME conversation
				Message:        fmt.Sprintf("CC: New message from %s: %s", deskID, req.Subject),
				Read:           false,
			}
			s.storage.CreateNotification(ccNotification)
		}
	}

	// Return only the main conversation with sender's miv
	c.JSON(http.StatusCreated, models.GetConversationResponse{
		Conversation: conv,
		Mivs:         []*models.ConversationMiv{senderMiv},
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

	// Get existing mivs to determine recipient - ONLY get sender's mivs for seq_no calculation
	mivs, err := s.storage.GetConversationMivs(conversationID, deskID)
	if err != nil || len(mivs) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Determine recipient from sender's own mivs (the other party in the conversation)
	var recipientID string
	var viaRecipients []string
	for _, m := range mivs {
		// If this miv is FROM me, the recipient is the TO
		if m.From == deskID {
			recipientID = m.To
			if len(m.Via) > 0 {
				// Reverse the via array for reply routing
				viaRecipients = make([]string, len(m.Via))
				for i := range m.Via {
					viaRecipients[i] = m.Via[len(m.Via)-1-i]
				}
			}
			break
		}
		// If this miv is TO me, the recipient is the FROM
		if m.To == deskID {
			recipientID = m.From
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
		Owner:          deskID, // CRITICAL: Sender owns their SENT copy
		SeqNo:          nextSeqNo, // Set explicit sequence number
		From:           deskID,
		To:             recipientID,
		Via:            viaRecipients, // Reversed via routing for reply
		ViaIndex:       0, // Start at beginning of via chain
		Cc:             ccRecipients, // Include all CC recipients from conversation history
		ArrowTo:        actualRecipient, // Who actually receives this reply (first via or final recipient)
		Type:           models.MivTypeMiv, // Regular message
		Subject:        conv.Subject,
		Body:           req.SenderBody, // Store sender's encrypted body directly
		State:          models.StateSENT, // Use SENT state for replies
		IsEncrypted:    true,  // All messages are E2E encrypted
		IsAck:          req.IsAck,
		FontFamily:     req.FontFamily,
		FontSize:       req.FontSize,
		LineHeight:     req.LineHeight,
	}

	if err := s.storage.CreateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create reply"})
		return
	}

	// CRITICAL: Create recipient's copy of the reply in the SAME conversation
	// Both sender and recipient share the same conversation ID, but own different mivs
	
	// For via routing, create miv for the FIRST via intermediary (actualRecipient)
	// NOT the final recipient
	normalizedActualRecipient := crypto.NormalizeDeskID(actualRecipient)
	
	// Determine the type for the actual recipient
	// If they are a via intermediary (not the final recipient), mark as VIA
	actualRecipientType := models.MivTypeMiv
	if len(viaRecipients) > 0 && actualRecipient != recipientID {
		actualRecipientType = models.MivTypeVia
	}
	
	// Get the next sequence number for actual recipient's mivs in this conversation
	actualRecipientMivs, err := s.storage.GetConversationMivs(conversationID, normalizedActualRecipient)
	if err != nil {
		log.Printf("ERROR: Failed to get actual recipient mivs: %v", err)
	} else {
		actualRecipientSeqNo := len(actualRecipientMivs) + 1

		// Create the reply miv for actual recipient in the SAME conversation
		recipientReplyMiv := &models.ConversationMiv{
			ConversationID: conversationID, // SAME conversation as sender
			Owner:          normalizedActualRecipient, // CRITICAL: Actual recipient (via or final) owns their IN copy
			SeqNo:          actualRecipientSeqNo,
			From:           deskID,
			To:             recipientID,
			Via:            viaRecipients,
			ViaIndex:       0,
			Cc:             ccRecipients,
			ArrowTo:        normalizedActualRecipient, // Arrow points to actual recipient
			Type:           actualRecipientType,       // VIA if intermediary, MIV if final recipient
			Subject:        conv.Subject,
			Body:           req.RecipientBody, // Store recipient's encrypted body directly
			State:          models.StateIN, // IN state for recipient
			IsEncrypted:    true,  // All messages are E2E encrypted
			IsAck:          req.IsAck,
			FontFamily:     req.FontFamily,
			FontSize:       req.FontSize,
			LineHeight:     req.LineHeight,
		}

		if err := s.storage.CreateConversationMiv(recipientReplyMiv); err != nil {
			log.Printf("ERROR: Failed to create recipient reply miv: %v", err)
		} else {
			log.Printf("DEBUG: Created reply miv for actual recipient %s in conversation %s (seq %d)", normalizedActualRecipient, conversationID, actualRecipientSeqNo)
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

	// For each CC recipient, create a CC copy in the SAME conversation
	for _, ccRecipient := range ccRecipients {
		if ccRecipient != "" && ccRecipient != deskID {
			// Get existing mivs for CC recipient to determine next SeqNo
			ccMivs, err := s.storage.GetConversationMivs(conv.ID, ccRecipient)
			if err != nil {
				log.Printf("ERROR: Failed to get mivs for CC recipient %s: %v", ccRecipient, err)
				continue
			}
			
			nextSeqNo := len(ccMivs) + 1
			log.Printf("DEBUG: Creating CC reply miv #%d in conversation %s for recipient %s", nextSeqNo, conv.ID, ccRecipient)
			
			// Get CC-specific encrypted body from the map
			if req.CcBodies == nil {
				log.Printf("❌ ERROR: CcBodies map is nil but CC recipients exist in reply")
				c.JSON(http.StatusBadRequest, gin.H{"error": "CC recipients specified but no CC bodies provided"})
				return
			}
			
			ccBody, ok := req.CcBodies[ccRecipient]
			if !ok || ccBody == "" {
				log.Printf("❌ ERROR: No encrypted body found for CC recipient %s in reply", ccRecipient)
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("No encrypted body for CC recipient %s", ccRecipient)})
				return
			}
			
			log.Printf("  ✅ Found CC-specific reply body: %s", ccBody[:min(40, len(ccBody))])
			
			// Create CC copy of the reply in the SAME conversation
			ccReplyMiv := &models.ConversationMiv{
				ConversationID: conv.ID, // SAME conversation
				Owner:          ccRecipient, // CRITICAL: CC recipient owns their copy
				SeqNo:          nextSeqNo,
				From:           deskID,
				To:             recipientID, // Original recipient for display
				Cc:             ccRecipients, // All CC recipients for reference
				ArrowTo:        ccRecipient, // Arrow points to CC recipient
				Type:           models.MivTypeCC, // CC copy
				Subject:        conv.Subject,
				Body:           ccBody, // Use CC recipient's own encrypted body
				State:          models.StateIN, // CC mivs use IN state
				IsEncrypted:    true,  // All messages are E2E encrypted
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
				ConversationID: conv.ID, // SAME conversation
				Message:        message,
				Read:           false,
			}
			s.storage.CreateNotification(ccNotification)
			log.Printf("DEBUG: Created notification for CC recipient %s", normalizedCc)
		}
	}

	// If conversation was previously archived but we got a reply, unarchive it
	// This allows continuing conversations that were archived
	if conv.IsArchived && !req.IsAck {
		conv.IsArchived = false
		s.storage.UpdateConversation(conv)
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

	// Mark all mivs in this conversation as deleted for this desk
	// No authorization check needed - DeleteConversationMivs only affects mivs owned by this desk
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

	// Verify conversation exists
	_, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// Get CC recipient's mivs to find the original sender
	ccMivs, err := s.storage.GetConversationMivs(conversationID, deskID)
	if err != nil || len(ccMivs) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Find the original sender (from the first CC miv)
	var originalSender string
	for _, miv := range ccMivs {
		if miv.Type == models.MivTypeCC {
			originalSender = miv.From
			break
		}
	}

	if originalSender == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No CC miv found for this desk"})
		return
	}

	// CC recipient wants to start a conversation with the original sender
	// This becomes a regular reply in the same conversation
	// We can redirect to the standard reply endpoint or handle inline

	// For now, just indicate that answering should be done via the normal reply flow
	// The frontend should allow CC recipients to reply to the conversation
	c.JSON(http.StatusOK, gin.H{
		"message": "To answer a CC, use the standard reply endpoint",
		"conversation_id": conversationID,
		"original_sender": originalSender,
	})
}

func (s *Server) deleteCcMiv(c *gin.Context) {
	conversationID := c.Param("id")
	deskID := c.Query("desk_id")
	if deskID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "desk_id is required"})
		return
	}

	// Verify conversation exists
	_, err := s.storage.GetConversation(conversationID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Conversation not found"})
		return
	}

	// Get CC recipient's mivs and mark them as REMOVED
	ccMivs, err := s.storage.GetConversationMivs(conversationID, deskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	normalizedDeskID := crypto.NormalizeDeskID(deskID)
	for _, miv := range ccMivs {
		// Only mark CC type mivs as REMOVED (not replies they may have sent)
		if miv.Type == models.MivTypeCC && crypto.NormalizeDeskID(miv.Owner) == normalizedDeskID {
			miv.State = models.StateREMOVED
			if err := s.storage.UpdateConversationMiv(miv); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update miv"})
				return
			}
		}
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
		// Get all conversation mivs for the notification's desk
		mivs, err := s.storage.GetConversationMivs(notif.ConversationID, notif.DeskID)
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

	var req models.ApproveViaRoutingRequest
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
		c.JSON(http.StatusForbidden, gin.H{"error": "You are not authorized to approve this via routing"})
		return
	}

	// Calculate next via index
	nextViaIndex := miv.ViaIndex + 1
	
	// Determine next recipient
	var nextRecipient string
	var nextArrowTo string
	if nextViaIndex < len(miv.Via) {
		// Forward to next via recipient
		nextRecipient = crypto.NormalizeDeskID(miv.Via[nextViaIndex])
		nextArrowTo = miv.Via[nextViaIndex]
	} else {
		// Reached the end of via chain, deliver to final recipient
		nextRecipient = crypto.NormalizeDeskID(miv.To)
		nextArrowTo = miv.To
	}

	// Get all mivs in this conversation to find Alice's miv and calculate seq_no
	allMivs, err := s.storage.GetConversationMivs(miv.ConversationID, miv.From)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}

	// Update Alice's miv (the sender) to increment via_index so she knows progress
	var aliceMiv *models.ConversationMiv
	for _, m := range allMivs {
		if m.Owner == crypto.NormalizeDeskID(miv.From) && m.SeqNo == miv.SeqNo {
			aliceMiv = m
			break
		}
	}
	if aliceMiv != nil {
		aliceMiv.ViaIndex = nextViaIndex
		if err := s.storage.UpdateConversationMiv(aliceMiv); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update sender miv"})
			return
		}
	}

	// Update Joe's miv to SENT and update arrow_to (he has forwarded it)
	// Change arrow_to to point to the next recipient so Joe no longer sees it in his basket
	miv.State = models.StateSENT
	miv.ArrowTo = nextArrowTo
	if err := s.storage.UpdateConversationMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update miv"})
		return
	}

	// Get the max seq_no for Bob in this conversation
	bobMivs, _ := s.storage.GetConversationMivs(miv.ConversationID, nextRecipient)
	maxSeqNo := 0
	for _, m := range bobMivs {
		if m.SeqNo > maxSeqNo {
			maxSeqNo = m.SeqNo
		}
	}

	// Determine the type for the new recipient
	// If they are a via intermediary (not the final recipient), mark as VIA
	newMivType := models.MivTypeMiv
	if nextViaIndex < len(miv.Via) {
		// Still in via chain, this is an intermediary
		newMivType = models.MivTypeVia
	}

	// Create a NEW miv for Bob (copy of Joe's miv with updated owner and state)
	newMiv := &models.ConversationMiv{
		ConversationID: miv.ConversationID,
		Owner:          nextRecipient,
		SeqNo:          maxSeqNo + 1,
		From:           miv.From,
		To:             miv.To,
		Cc:             miv.Cc,
		ArrowTo:        nextArrowTo,
		Type:           newMivType, // VIA if intermediary, MIV if final recipient
		Subject:        miv.Subject,
		Body:           req.NextRecipientBody, // Use re-encrypted body for next recipient
		State:          models.StateIN, // Bob sees it in his IN basket
		IsEncrypted:    miv.IsEncrypted,
		IsAck:          miv.IsAck, // CRITICAL: Preserve ACK flag when forwarding
		FontFamily:     miv.FontFamily,
		FontSize:       miv.FontSize,
		LineHeight:     miv.LineHeight,
		Via:            miv.Via,
		ViaIndex:       nextViaIndex,
		IsViaRejected:  false,
	}

	if err := s.storage.CreateConversationMiv(newMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create miv for next recipient"})
		return
	}

	// Create notification for next recipient
	var notificationType models.NotificationType
	var notificationMessage string
	if nextViaIndex < len(miv.Via) {
		notificationType = models.NotificationTypeReply
		notificationMessage = fmt.Sprintf("Via routing from %s: %s", deskID, miv.Subject)
	} else {
		notificationType = models.NotificationTypeNewMiv
		notificationMessage = fmt.Sprintf("New message from %s: %s", miv.From, miv.Subject)
	}
	
	notification := &models.Notification{
		DeskID:         nextRecipient,
		Type:           notificationType,
		MivID:          newMiv.ID,
		ConversationID: miv.ConversationID,
		Message:        notificationMessage,
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	c.JSON(http.StatusOK, gin.H{"message": "Via routing approved", "miv": newMiv})
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

	// Get all mivs for this desk to determine next sequence number
	mivs, err := s.storage.GetConversationMivs(miv.ConversationID, deskID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get conversation mivs"})
		return
	}
	nextSeqNo := len(mivs) + 1

	// Use the encrypted rejection body from the request for the recipient
	rejectionBody := req.RecipientBody

	// Get next sequence number for sender
	senderMivs, err := s.storage.GetConversationMivs(miv.ConversationID, miv.From)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get sender mivs"})
		return
	}
	senderNextSeqNo := len(senderMivs) + 1

       // Create rejector's SENT copy (like a normal reply)
       rejectorMiv := &models.ConversationMiv{
	       ConversationID: miv.ConversationID,
	       Owner:          deskID,           // Rejector owns this copy
	       SeqNo:          nextSeqNo,
	       From:           deskID,           // From the person who rejected
	       To:             miv.From,         // To the original sender
	       ArrowTo:        deskID,           // Arrow points to rejector for SENT basket
	       Type:           models.MivTypeMiv,
	       Subject:        fmt.Sprintf("REJECTED: %s", miv.Subject),
	       Body:           base64.StdEncoding.EncodeToString([]byte(rejectionBody)),
	       State:          models.StateSENT, // Rejector sees it in SENT basket
	       IsEncrypted:    true,
	       IsAck:          true,             // Set as ACK - allows deletion without reply
	       FontFamily:     miv.FontFamily,
	       FontSize:       miv.FontSize,
	       LineHeight:     miv.LineHeight,
	       Via:            []string{},       // No via routing on the rejection
	       ViaIndex:       0,
	       IsViaRejected:  false,
	       RejectedMivID:  miv.ID,          // Store reference to original MIV
       }

	if err := s.storage.CreateConversationMiv(rejectorMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rejector miv"})
		return
	}

       // Create sender's IN copy (they receive the rejection)
       senderRejectionMiv := &models.ConversationMiv{
	       ConversationID: miv.ConversationID,
	       Owner:          miv.From,         // Sender owns this copy
	       SeqNo:          senderNextSeqNo,
	       From:           deskID,           // From the person who rejected
	       To:             miv.From,         // To the original sender
	       ArrowTo:        miv.From,         // Arrow points to sender
	       Type:           models.MivTypeMiv,
	       Subject:        fmt.Sprintf("REJECTED: %s", miv.Subject),
	       Body:           req.RecipientBody,
	       State:          models.StateIN,   // Sender sees it in IN basket
	       IsEncrypted:    true,
	       IsAck:          true,             // Set as ACK - sender can delete or reply
	       FontFamily:     miv.FontFamily,
	       FontSize:       miv.FontSize,
	       LineHeight:     miv.LineHeight,
	       Via:            []string{},       // No via routing on the rejection
	       ViaIndex:       0,
	       IsViaRejected:  false,
	       RejectedMivID:  miv.ID,          // Store reference to original MIV
       }

	if err := s.storage.CreateConversationMiv(senderRejectionMiv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create sender rejection miv"})
		return
	}

	// Mark Joe's VIA miv as SENT (he has responded by rejecting)
	// Also mark Alice's original miv as forgotten so it doesn't clutter her SENT basket
	// Get all mivs in this conversation
	allMivs, _ := s.storage.GetConversationMivs(miv.ConversationID, "")
	for _, m := range allMivs {
		// Update Joe's VIA miv to SENT state
		if m.Owner == deskID && m.ID == mivID {
			m.State = models.StateSENT
			m.IsForgotten = true // Hide it since he's responded
			if err := s.storage.UpdateConversationMiv(m); err != nil {
				log.Printf("ERROR: Failed to update rejector's miv: %v", err)
			}
		}
		// Mark Alice's original SENT miv as forgotten (replaced by new exchange)
		if m.Owner == miv.From && m.SeqNo == miv.SeqNo && m.State == models.StateSENT {
			m.IsForgotten = true
			if err := s.storage.UpdateConversationMiv(m); err != nil {
				log.Printf("ERROR: Failed to mark sender's original miv as forgotten: %v", err)
			}
		}
	}

	// Create notification for sender about rejection
	normalizedSender := crypto.NormalizeDeskID(miv.From)
	message := fmt.Sprintf("Via routing rejected by %s: %s", deskID, miv.Subject)

	notification := &models.Notification{
		DeskID:         normalizedSender,
		Type:           models.NotificationTypeReply,
		MivID:          senderRejectionMiv.ID,
		ConversationID: miv.ConversationID,
		Message:        message,
		Read:           false,
	}
	s.storage.CreateNotification(notification)

	// Send rejection notices to all CC recipients in the SAME conversation
	if len(miv.Cc) > 0 {
		log.Printf("DEBUG: Sending rejection notices to %d CC recipients", len(miv.Cc))
		
		for _, ccRecipient := range miv.Cc {
			if ccRecipient == "" || ccRecipient == miv.From || ccRecipient == deskID {
				continue // Skip empty, sender, and rejector
			}
			
			normalizedCc := crypto.NormalizeDeskID(ccRecipient)
			
			// Get existing mivs for CC recipient to determine next SeqNo
			ccMivs, err := s.storage.GetConversationMivs(miv.ConversationID, ccRecipient)
			if err != nil {
				log.Printf("ERROR: Failed to get mivs for CC recipient %s: %v", ccRecipient, err)
				continue
			}
			
			ccNextSeqNo := len(ccMivs) + 1
			
			// Create CC copy of the rejection notice in the SAME conversation
			ccRejectionMiv := &models.ConversationMiv{
				ConversationID: miv.ConversationID, // SAME conversation
				Owner:          ccRecipient, // CC recipient owns their copy
				SeqNo:          ccNextSeqNo,
				From:           deskID,
				To:             miv.From,
				Cc:             miv.Cc,
				ArrowTo:        ccRecipient,
				Type:           models.MivTypeCC,
				Subject:        fmt.Sprintf("REJECTED: %s", miv.Subject),
				Body:           base64.StdEncoding.EncodeToString([]byte(rejectionBody)),
				State:          models.StateIN, // CC mivs use IN state
				IsEncrypted:    false,
				IsAck:          true, // CC recipients can delete or view
				FontFamily:     miv.FontFamily,
				FontSize:       miv.FontSize,
				LineHeight:     miv.LineHeight,
				Via:            miv.Via,
				ViaIndex:       miv.ViaIndex,
				IsViaRejected:  true, // Mark as rejected for display
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
				ConversationID: miv.ConversationID, // SAME conversation
				Message:        fmt.Sprintf("CC: Via routing rejected by %s: %s", deskID, miv.Subject),
				Read:           false,
			}
			s.storage.CreateNotification(ccNotification)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Via routing rejected", "miv": senderRejectionMiv})
}
