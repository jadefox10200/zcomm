package api

import (
	"encoding/base64"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
	"github.com/jadefox10200/missiv/backend/internal/storage"
)

// Server represents the API server
type Server struct {
	storage *storage.MemoryStorage
	router  *gin.Engine
	keyPair *crypto.KeyPair
}

// NewServer creates a new API server
func NewServer() *Server {
	s := &Server{
		storage: storage.NewMemoryStorage(),
		router:  gin.Default(),
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Enable CORS for frontend
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

	api := s.router.Group("/api")
	{
		// Account endpoints (authentication)
		api.POST("/accounts/register", s.registerAccount)
		api.POST("/accounts/login", s.loginAccount)
		api.POST("/accounts/recover-password", s.recoverPassword)

		// Desk endpoints
		api.GET("/desks", s.listDesks)
		api.POST("/desks", s.createDesk)
		api.PUT("/desks/:desk_id", s.updateDesk)
		api.POST("/desks/switch", s.switchDesk)

		// Conversation endpoints
		api.GET("/conversations", s.listConversations)
		api.GET("/conversations/:id", s.getConversation)
		api.POST("/conversations", s.createConversation)
		api.POST("/conversations/:id/reply", s.replyToConversation)
		api.POST("/conversations/:id/archive", s.archiveConversation)
		api.POST("/conversations/:id/cc/answer", s.answerCcMiv)
		api.POST("/conversations/:id/cc/delete", s.deleteCcMiv)

		// Miv read endpoints
		api.POST("/mivs/:id/read", s.markMivAsRead)
		api.POST("/mivs/:id/forget", s.forgetMiv)

		// Notification endpoints
		api.GET("/notifications", s.listNotifications)
		api.POST("/notifications/:id/read", s.markNotificationAsRead)

		// Contact endpoints
		api.GET("/desks/:desk_id/contacts", s.listContacts)
		api.POST("/desks/:desk_id/contacts", s.createContact)
		api.GET("/contacts/:contact_id", s.getContact)
		api.PUT("/contacts/:contact_id", s.updateContact)
		api.DELETE("/contacts/:contact_id", s.deleteContact)

		// Upload endpoint
		api.POST("/upload", s.uploadFile)

		// Legacy Identity endpoints (for backward compatibility)
		api.GET("/identity", s.getIdentity)
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

	// Serve uploaded files
	s.router.Static("/uploads", "./uploads")
}

// Run starts the API server
func (s *Server) Run(addr string) error {
	return s.router.Run(addr)
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
