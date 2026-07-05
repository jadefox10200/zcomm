package api

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
	"github.com/jadefox10200/missiv/backend/internal/storage"
)

// StorageBackend is an interface for storage implementations
type StorageBackend interface {
	// Legacy Identity methods
	SetIdentity(identity *models.Identity)
	GetIdentity() (*models.Identity, error)

	// Legacy Miv methods
	CreateMiv(miv *models.Miv) error
	GetMiv(id string) (*models.Miv, error)
	ListMivs(state models.MivState) ([]*models.Miv, error)
	UpdateMivState(id string, state models.MivState) error
	DeleteMiv(id string) error

	// Account methods
	CreateAccount(account *models.Account) error
	GetAccountByID(id string) (*models.Account, error)
	GetAccountByUsername(username string) (*models.Account, error)
	ListAccounts() ([]*models.Account, error)
	UpdateAccount(account *models.Account) error

	// Desk methods
	CreateDesk(desk *models.Desk, privateKey [32]byte) error
	GetDesk(id string) (*models.Desk, error)
	GetDeskPrivateKey(id string) ([32]byte, error)
	GetDeskEncryptedPrivateKey(id string, password string) (string, error)
	ListDesksByAccount(accountID string) ([]*models.Desk, error)
	UpdateDesk(desk *models.Desk) error

	// Conversation methods
	CreateConversation(conv *models.Conversation) error
	GetConversation(id string) (*models.Conversation, error)
	ListConversationsByDesk(deskID string) ([]*models.Conversation, error)
	ListArchivedConversationsByDesk(deskID string) ([]*models.Conversation, error)
	UpdateConversation(conv *models.Conversation) error

	// ConversationMiv methods
	CreateConversationMiv(miv *models.ConversationMiv) error
	GetConversationMiv(mivID string) (*models.ConversationMiv, error)
	GetConversationMivs(conversationID string, deskID string) ([]*models.ConversationMiv, error)
	UpdateConversationMiv(miv *models.ConversationMiv) error
	MarkConversationMivAsRead(mivID string, deskID string) error
	MarkConversationMivsAsRead(conversationID string, deskID string) error
	DeleteConversationMivs(conversationID string, deskID string) error

	// Attachment methods
	CreateAttachment(attachment *models.Attachment) error
	GetAttachment(id string) (*models.Attachment, error)
	ListAttachmentsByConversation(conversationID string) ([]*models.Attachment, error)
	AssignAttachmentsToConversation(conversationID string, seqNo int, attachmentIDs []string) error
	DeleteAttachmentsByConversation(conversationID string) error
	ListOrphanAttachmentsBefore(cutoff time.Time) ([]*models.Attachment, error)
	DeleteAttachmentsByID(attachmentIDs []string) error

	// Contact methods
	CreateContact(contact *models.Contact) error
	GetContact(id string) (*models.Contact, error)
	ListContactsForDesk(deskID string) ([]*models.Contact, error)
	UpdateContact(contact *models.Contact) error
	DeleteContact(id string) error
	GetContactByDeskIDRef(deskID, deskIDRef string) (*models.Contact, error)

	// Notification methods
	CreateNotification(notif *models.Notification) error
	GetNotification(id string) (*models.Notification, error)
	ListNotificationsByDesk(deskID string, unreadOnly bool) ([]*models.Notification, error)
	MarkNotificationAsRead(id string) error
}

// Server represents the API server
type Server struct {
	storage StorageBackend
	router  *gin.Engine
	keyPair *crypto.KeyPair
}

// NewServer creates a new API server with SQLite storage
func NewServer() *Server {
	// Use SQLite storage for persistent data
	sqliteStorage, err := storage.NewSQLiteStorage("./data/zcomm.db")
	if err != nil {
		panic("Failed to initialize SQLite storage: " + err.Error())
	}

	s := &Server{
		storage: sqliteStorage,
		router:  gin.Default(),
	}

	s.setupRoutes()
	s.startAttachmentCleanupJob()

	// Load test users for development
	// if err := s.loadTestUsers(); err != nil {
	// Just log the error, don't fail server startup
	// This allows the server to continue even if test users fail to load
	// println("Warning: Failed to load test users:", err.Error())
	// }

	return s
}

// NewServerWithStorage creates a new API server with a custom storage backend (for testing)
func NewServerWithStorage(storageBackend StorageBackend) *Server {
	s := &Server{
		storage: storageBackend,
		router:  gin.Default(),
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// In production nginx handles CORS; keep backend CORS only for non-production direct access.
	if strings.ToLower(os.Getenv("API_ENV")) != "production" {
		s.router.Use(func(c *gin.Context) {
			c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}

			c.Next()
		})
	}

	api := s.router.Group("/api")
	{
		// Public endpoints (no auth required)
		api.POST("/accounts/register", s.registerAccount)
		api.POST("/accounts/login", s.loginAccount)
		api.POST("/accounts/recover-password", s.recoverPassword)
	}

	// Protected endpoints (auth required)
	protected := s.router.Group("/api")
	protected.Use(authMiddleware())
	{
		admin := protected.Group("/admin")
		admin.Use(requireAdminMiddleware(s.storage))
		{
			admin.GET("/users/count", s.adminCountUsers)
			admin.GET("/users", s.adminListUsers)
			admin.POST("/users/:account_id/lock", s.adminLockUser)
			admin.POST("/users/:account_id/unlock", s.adminUnlockUser)
			admin.POST("/users/:account_id/close", s.adminCloseUser)
			admin.POST("/users/:account_id/reopen", s.adminReopenUser)
			admin.POST("/users/:account_id/reset-password", s.adminResetUserPassword)
		}

		// Desk endpoints
		protected.GET("/desks", s.listDesks)
		protected.POST("/desks", s.createDesk)
		protected.PUT("/desks/:desk_id", s.updateDesk)
		protected.POST("/desks/switch", s.switchDesk)
		protected.GET("/desks/:desk_id/public-key", s.getDeskPublicKey) // Get public key for encryption
		protected.POST("/desks/public-keys", s.getBatchDeskPublicKeys)  // Batch get public keys

		// Conversation endpoints
		protected.GET("/conversations", s.listConversations)
		protected.GET("/conversations/archived", s.listArchivedConversations)
		protected.GET("/conversations/:id", s.getConversation)
		protected.POST("/conversations", s.createConversation)
		protected.POST("/conversations/:id/reply", s.replyToConversation)
		protected.POST("/conversations/:id/archive", s.archiveConversation)
		protected.DELETE("/conversations/:id", s.deleteConversation)
		protected.POST("/conversations/:id/cc/answer", s.answerCcMiv)
		protected.POST("/conversations/:id/cc/delete", s.deleteCcMiv)

		// Miv read endpoints
		protected.POST("/mivs/:id/read", s.markMivAsRead)
		protected.POST("/mivs/:id/forget", s.forgetMiv)

		// Via routing endpoints
		protected.POST("/mivs/:id/via/approve", s.approveViaRouting)
		protected.POST("/mivs/:id/via/reject", s.rejectViaRouting)

		// Notification endpoints
		protected.GET("/notifications", s.listNotifications)
		protected.POST("/notifications/:id/read", s.markNotificationAsRead)

		// Contact endpoints
		protected.GET("/desks/:desk_id/contacts", s.listContacts)
		protected.POST("/desks/:desk_id/contacts", s.createContact)
		protected.GET("/contacts/:contact_id", s.getContact)
		protected.PUT("/contacts/:contact_id", s.updateContact)
		protected.DELETE("/contacts/:contact_id", s.deleteContact)

		// Attachment endpoints
		protected.POST("/attachments", s.uploadAttachment)
		protected.GET("/attachments/:attachment_id", s.downloadAttachment)

		// Legacy Identity endpoints (for backward compatibility)
		protected.GET("/identity", s.getIdentity)
		api.POST("/identity", s.createIdentity)
		api.GET("/identity/publickey", s.getPublicKey)

		// Legacy Miv endpoints (for backward compatibility)
		api.GET("/mivs", s.listMivs)
		api.GET("/mivs/:id", s.getMiv)
		api.POST("/mivs", s.createMiv)
		api.PUT("/mivs/:id/state", s.updateMivState)

		// Filtered miv endpoints
		api.GET("/mivs/inbox", s.getInbox)
		api.GET("/mivs/pending", s.getPending)
		api.GET("/mivs/sent", s.getSent)             // Returns SENT state (combines old OUT and UNANSWERED)
		api.GET("/mivs/unanswered", s.getUnanswered) // DEPRECATED: Use /mivs/sent instead
		api.GET("/mivs/archived", s.getArchived)
	}

	// Health check
	s.router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

}

// Run starts the API server
// Run starts the API server (HTTP)
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
}

// RunTLS starts the API server with HTTPS
func (s *Server) RunTLS(addr, certFile, keyFile string) error {
	return s.router.RunTLS(addr, certFile, keyFile)
}

func (s *Server) startAttachmentCleanupJob() {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("ATTACHMENT_CLEANUP_DISABLED")), "true") {
		log.Printf("Attachment cleanup disabled via ATTACHMENT_CLEANUP_DISABLED")
		return
	}

	maxAge := parseDurationEnv("ATTACHMENT_ORPHAN_MAX_AGE", 24*time.Hour)
	interval := parseDurationEnv("ATTACHMENT_CLEANUP_INTERVAL", time.Hour)

	log.Printf("Attachment cleanup enabled (max age: %s, interval: %s)", maxAge, interval)

	go func() {
		s.cleanupOrphanAttachments(maxAge)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			s.cleanupOrphanAttachments(maxAge)
		}
	}()
}

func parseDurationEnv(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		log.Printf("Invalid %s=%q, using default %s", key, raw, fallback)
		return fallback
	}

	return parsed
}

func (s *Server) cleanupOrphanAttachments(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	orphans, err := s.storage.ListOrphanAttachmentsBefore(cutoff)
	if err != nil {
		log.Printf("Attachment cleanup failed to list orphan attachments: %v", err)
		return
	}

	if len(orphans) == 0 {
		return
	}

	attachmentDir := os.Getenv("ATTACHMENT_DIR")
	if attachmentDir == "" {
		attachmentDir = "./attachments"
	}

	deletableIDs := make([]string, 0, len(orphans))
	skipped := 0

	for _, orphan := range orphans {
		filePath := filepath.Join(attachmentDir, orphan.StoredFilename)
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("Attachment cleanup failed to remove file %s: %v", orphan.StoredFilename, err)
			skipped++
			continue
		}

		deletableIDs = append(deletableIDs, orphan.ID)
	}

	if len(deletableIDs) == 0 {
		if skipped > 0 {
			log.Printf("Attachment cleanup skipped %d orphan attachments due to file errors", skipped)
		}
		return
	}

	if err := s.storage.DeleteAttachmentsByID(deletableIDs); err != nil {
		log.Printf("Attachment cleanup failed to delete metadata: %v", err)
		return
	}

	log.Printf("Attachment cleanup removed %d orphan attachments (skipped %d)", len(deletableIDs), skipped)
}

// Identity handlers

func (s *Server) getIdentity(c *gin.Context) {
	identity, err := s.storage.GetIdentity()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity not found. Create one first."})
		return
	}

	c.JSON(http.StatusOK, identity)
}

func (s *Server) createIdentity(c *gin.Context) {
	var req struct {
		Name string `json:"name"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Generate new key pair
	keyPair, err := crypto.GenerateKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate key pair"})
		return
	}
	s.keyPair = keyPair

	// Generate phone-style ID
	id, err := crypto.GeneratePhoneStyleID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate ID"})
		return
	}

	identity := &models.Identity{
		ID:        id,
		PublicKey: crypto.PublicKeyToBase64(keyPair.PublicKey),
		Name:      req.Name,
	}

	s.storage.SetIdentity(identity)

	c.JSON(http.StatusCreated, identity)
}

func (s *Server) getPublicKey(c *gin.Context) {
	identity, err := s.storage.GetIdentity()
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Identity not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"public_key": identity.PublicKey,
		"id":         identity.ID,
	})
}

// Miv handlers

func (s *Server) listMivs(c *gin.Context) {
	mivs, err := s.storage.ListMivs("")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, mivs)
}

func (s *Server) getMiv(c *gin.Context) {
	id := c.Param("id")

	miv, err := s.storage.GetMiv(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Miv not found"})
		return
	}

	c.JSON(http.StatusOK, miv)
}

func (s *Server) createMiv(c *gin.Context) {
	var req models.CreateMivRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	identity, err := s.storage.GetIdentity()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Identity not set"})
		return
	}

	// For now, store as plain text. In production, encrypt the body.
	// Encryption would require recipient's public key.
	from := identity.ID
	if req.From != "" {
		from = req.From
	}
	miv := &models.Miv{
		From:        from,
		To:          req.To,
		Cc:          req.Cc,
		Subject:     req.Subject,
		Body:        base64.StdEncoding.EncodeToString([]byte(req.Body)), // Base64 encode for now
		State:       models.StatePENDING,
		CreatedAt:   time.Now(),
		IsEncrypted: false, // Set to true when implementing full encryption
		FontFamily:  req.FontFamily,
		FontSize:    req.FontSize,
	}

	if err := s.storage.CreateMiv(miv); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create miv"})
		return
	}

	c.JSON(http.StatusCreated, miv)
}

func (s *Server) updateMivState(c *gin.Context) {
	id := c.Param("id")

	var req models.UpdateStateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := s.storage.UpdateMivState(id, req.State); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}

	miv, _ := s.storage.GetMiv(id)
	c.JSON(http.StatusOK, miv)
}

// Filtered miv endpoints

func (s *Server) getInbox(c *gin.Context) {
	mivs, err := s.storage.ListMivs(models.StateIN)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, mivs)
}

func (s *Server) getPending(c *gin.Context) {
	mivs, err := s.storage.ListMivs(models.StatePENDING)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, mivs)
}

func (s *Server) getSent(c *gin.Context) {
	sentMivs, err := s.storage.ListMivs(models.StateSENT)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// For backwards compatibility, also include old OUT and UNANSWERED states
	outMivs, _ := s.storage.ListMivs(models.StateOUT)
	unansweredMivs, _ := s.storage.ListMivs(models.StateUNANSWERED)

	allMivs := append(sentMivs, outMivs...)
	allMivs = append(allMivs, unansweredMivs...)

	c.JSON(http.StatusOK, allMivs)
}

func (s *Server) getUnanswered(c *gin.Context) {
	// DEPRECATED: redirect to getSent for backwards compatibility
	s.getSent(c)
}

func (s *Server) getArchived(c *gin.Context) {
	mivs, err := s.storage.ListMivs(models.StateARCHIVED)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, mivs)
}
