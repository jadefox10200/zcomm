package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
)

// MemoryStorage provides in-memory storage for mivs and identities
// This is a simple implementation for initial setup. In production, use a database.
type MemoryStorage struct {
	// Legacy single-user fields (kept for backward compatibility)
	mivs       map[string]*models.Miv
	identity   *models.Identity
	mivCounter int

	// Multi-user account fields
	accounts            map[string]*models.Account           // accountID -> Account
	accountsByUsername  map[string]*models.Account           // username -> Account
	desks               map[string]*models.Desk              // deskID -> Desk
	deskPrivateKeys     map[string][32]byte                  // deskID -> PrivateKey
	conversations       map[string]*models.Conversation      // conversationID -> Conversation
	conversationMivs    map[string][]*models.ConversationMiv // conversationID -> []Miv
	notifications       map[string]*models.Notification      // notificationID -> Notification
	notificationsByDesk map[string][]*models.Notification    // deskID -> []Notification
	contacts            map[string]*models.Contact           // contactID -> Contact
	contactsByDesk      map[string][]*models.Contact         // deskID -> []Contact

	accountCounter         int
	conversationCounter    int
	conversationMivCounter int
	notificationCounter    int
	contactCounter         int

	mu sync.RWMutex
}

// NewMemoryStorage creates a new memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		mivs:                make(map[string]*models.Miv),
		accounts:            make(map[string]*models.Account),
		accountsByUsername:  make(map[string]*models.Account),
		desks:               make(map[string]*models.Desk),
		deskPrivateKeys:     make(map[string][32]byte),
		conversations:       make(map[string]*models.Conversation),
		conversationMivs:    make(map[string][]*models.ConversationMiv),
		notifications:       make(map[string]*models.Notification),
		notificationsByDesk: make(map[string][]*models.Notification),
		contacts:            make(map[string]*models.Contact),
		contactsByDesk:      make(map[string][]*models.Contact),
	}
}

// SetIdentity sets the current user identity
func (s *MemoryStorage) SetIdentity(identity *models.Identity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identity = identity
}

// GetIdentity returns the current user identity
func (s *MemoryStorage) GetIdentity() (*models.Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.identity == nil {
		return nil, fmt.Errorf("identity not set")
	}

	return s.identity, nil
}

// CreateMiv creates a new miv
func (s *MemoryStorage) CreateMiv(miv *models.Miv) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if miv.ID == "" {
		s.mivCounter++
		miv.ID = fmt.Sprintf("miv-%d", s.mivCounter)
	}

	if miv.CreatedAt.IsZero() {
		miv.CreatedAt = time.Now()
	}

	s.mivs[miv.ID] = miv
	return nil
}

// GetMiv retrieves a miv by ID
func (s *MemoryStorage) GetMiv(id string) (*models.Miv, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	miv, exists := s.mivs[id]
	if !exists {
		return nil, fmt.Errorf("miv not found: %s", id)
	}

	return miv, nil
}

// ListMivs returns all mivs, optionally filtered by state
func (s *MemoryStorage) ListMivs(state models.MivState) ([]*models.Miv, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.Miv

	for _, miv := range s.mivs {
		if state == "" || miv.State == state {
			result = append(result, miv)
		}
	}

	return result, nil
}

// UpdateMivState updates the state of a miv
func (s *MemoryStorage) UpdateMivState(id string, state models.MivState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	miv, exists := s.mivs[id]
	if !exists {
		return fmt.Errorf("miv not found: %s", id)
	}

	miv.State = state

	// Update timestamps based on state
	now := time.Now()
	switch state {
	case models.StateOUT:
		miv.SentAt = &now
	case models.StateIN:
		if miv.ReceivedAt == nil {
			miv.ReceivedAt = &now
		}
	}

	return nil
}

// DeleteMiv deletes a miv (for cleanup, though mivs are meant to be immutable)
func (s *MemoryStorage) DeleteMiv(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.mivs[id]; !exists {
		return fmt.Errorf("miv not found: %s", id)
	}

	delete(s.mivs, id)
	return nil
}

// Account methods

// CreateAccount creates a new account
func (s *MemoryStorage) CreateAccount(account *models.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if account.ID == "" {
		s.accountCounter++
		account.ID = fmt.Sprintf("acc-%d", s.accountCounter)
	}

	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now()
	}
	account.UpdatedAt = account.CreatedAt

	// Check if username already exists
	if _, exists := s.accountsByUsername[account.Username]; exists {
		return fmt.Errorf("username already exists")
	}

	s.accounts[account.ID] = account
	s.accountsByUsername[account.Username] = account
	return nil
}

// GetAccountByID retrieves an account by ID
func (s *MemoryStorage) GetAccountByID(id string) (*models.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, exists := s.accounts[id]
	if !exists {
		return nil, fmt.Errorf("account not found: %s", id)
	}

	return account, nil
}

// GetAccountByUsername retrieves an account by username
func (s *MemoryStorage) GetAccountByUsername(username string) (*models.Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, exists := s.accountsByUsername[username]
	if !exists {
		return nil, fmt.Errorf("account not found: %s", username)
	}

	return account, nil
}

// UpdateAccount updates an account
func (s *MemoryStorage) UpdateAccount(account *models.Account) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accounts[account.ID]; !exists {
		return fmt.Errorf("account not found: %s", account.ID)
	}

	account.UpdatedAt = time.Now()
	s.accounts[account.ID] = account
	return nil
}

// Desk methods

// CreateDesk creates a new desk
func (s *MemoryStorage) CreateDesk(desk *models.Desk, privateKey [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if desk.CreatedAt.IsZero() {
		desk.CreatedAt = time.Now()
	}

	s.desks[desk.ID] = desk
	s.deskPrivateKeys[desk.ID] = privateKey
	return nil
}

// GetDesk retrieves a desk by ID
func (s *MemoryStorage) GetDesk(id string) (*models.Desk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Normalize the ID to handle formatted inputs like "555-123-4567"
	normalizedID := crypto.NormalizeDeskID(id)

	desk, exists := s.desks[normalizedID]
	if !exists {
		return nil, fmt.Errorf("desk not found: %s", id)
	}

	return desk, nil
}

// GetDeskPrivateKey retrieves a desk's private key
func (s *MemoryStorage) GetDeskPrivateKey(id string) ([32]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.deskPrivateKeys[id]
	if !exists {
		return [32]byte{}, fmt.Errorf("desk private key not found: %s", id)
	}

	return key, nil
}

// ListDesksByAccount retrieves all desks for an account
func (s *MemoryStorage) ListDesksByAccount(accountID string) ([]*models.Desk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*models.Desk
	for _, desk := range s.desks {
		if desk.AccountID == accountID {
			result = append(result, desk)
		}
	}

	return result, nil
}

// UpdateDesk updates an existing desk
func (s *MemoryStorage) UpdateDesk(desk *models.Desk) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.desks[desk.ID]; !exists {
		return fmt.Errorf("desk not found: %s", desk.ID)
	}

	s.desks[desk.ID] = desk
	return nil
}

// Conversation methods

// CreateConversation creates a new conversation
func (s *MemoryStorage) CreateConversation(conv *models.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if conv.ID == "" {
		s.conversationCounter++
		conv.ID = fmt.Sprintf("conv-%d", s.conversationCounter)
	}

	if conv.CreatedAt.IsZero() {
		conv.CreatedAt = time.Now()
	}
	conv.UpdatedAt = conv.CreatedAt

	s.conversations[conv.ID] = conv
	s.conversationMivs[conv.ID] = []*models.ConversationMiv{}
	return nil
}

// GetConversation retrieves a conversation by ID
func (s *MemoryStorage) GetConversation(id string) (*models.Conversation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	conv, exists := s.conversations[id]
	if !exists {
		return nil, fmt.Errorf("conversation not found: %s", id)
	}

	return conv, nil
}

// ListConversationsByDesk retrieves all conversations for a desk (either as creator or participant)
func (s *MemoryStorage) ListConversationsByDesk(deskID string) ([]*models.Conversation, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Use a map to track unique conversations (avoid duplicates)
	conversationMap := make(map[string]*models.Conversation)

	// First, add conversations created by this desk
	for _, conv := range s.conversations {
		if conv.DeskID == deskID {
			conversationMap[conv.ID] = conv
		}
	}

	// Then, add conversations where this desk is a participant (sent to or received from)
	for convID, mivs := range s.conversationMivs {
		// Check if this conversation contains only CC mivs
		isCCOnlyConversation := true
		for _, miv := range mivs {
			if miv.Type != models.MivTypeCC {
				isCCOnlyConversation = false
				break
			}
		}
		
		for _, miv := range mivs {
			normalizedMivTo := crypto.NormalizeDeskID(miv.ArrowTo)
			normalizedDeskID := crypto.NormalizeDeskID(deskID)
			
			// Check if deskID matches recipient or sender
			isRecipient := normalizedMivTo == normalizedDeskID
			isSender := miv.From == deskID
			
			// For CC-only conversations, only the owner should see them
			if isCCOnlyConversation && !isRecipient {
				continue
			}
			
			if isRecipient || isSender {
				if conv, exists := s.conversations[convID]; exists {
					conversationMap[convID] = conv
				}
				break // Only need to find one miv to include the conversation
			}
		}
	}

	// Convert map to slice
	var result []*models.Conversation
	for _, conv := range conversationMap {
		result = append(result, conv)
	}

	return result, nil
}

// UpdateConversation updates a conversation
func (s *MemoryStorage) UpdateConversation(conv *models.Conversation) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.conversations[conv.ID]; !exists {
		return fmt.Errorf("conversation not found: %s", conv.ID)
	}

	conv.UpdatedAt = time.Now()
	s.conversations[conv.ID] = conv
	return nil
}

// CreateConversationMiv creates a new miv in a conversation
func (s *MemoryStorage) CreateConversationMiv(miv *models.ConversationMiv) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if miv.ID == "" {
		s.conversationMivCounter++
		miv.ID = fmt.Sprintf("cmiv-%d", s.conversationMivCounter)
	}

	if miv.CreatedAt.IsZero() {
		miv.CreatedAt = time.Now()
	}

	// Get current mivs for this conversation
	mivs, exists := s.conversationMivs[miv.ConversationID]
	if !exists {
		return fmt.Errorf("conversation not found: %s", miv.ConversationID)
	}

	// Set sequence number
	if miv.SeqNo == 0 {
		miv.SeqNo = len(mivs) + 1
	}

	s.conversationMivs[miv.ConversationID] = append(mivs, miv)

	// Update conversation
	if conv, exists := s.conversations[miv.ConversationID]; exists {
		conv.MivCount = len(s.conversationMivs[miv.ConversationID])
		conv.UpdatedAt = time.Now()
	}

	return nil
}

// GetConversationMivs retrieves all mivs for a conversation
func (s *MemoryStorage) GetConversationMivs(conversationID string) ([]*models.ConversationMiv, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	mivs, exists := s.conversationMivs[conversationID]
	if !exists {
		return nil, fmt.Errorf("conversation not found: %s", conversationID)
	}

	return mivs, nil
}

// UpdateConversationMiv updates a miv in a conversation
func (s *MemoryStorage) UpdateConversationMiv(miv *models.ConversationMiv) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	mivs, exists := s.conversationMivs[miv.ConversationID]
	if !exists {
		return fmt.Errorf("conversation not found: %s", miv.ConversationID)
	}

	for i, m := range mivs {
		if m.ID == miv.ID {
			mivs[i] = miv
			return nil
		}
	}

	return fmt.Errorf("miv not found: %s", miv.ID)
}

// MarkConversationMivAsRead marks a specific miv as read
func (s *MemoryStorage) MarkConversationMivAsRead(mivID string, deskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the miv across all conversations
	for _, mivs := range s.conversationMivs {
		for i, miv := range mivs {
			if miv.ID == mivID {
				// Only mark as read if the miv is addressed to this desk
				if miv.ArrowTo != deskID {
					return fmt.Errorf("miv not found or not addressed to this desk")
				}

				// Mark as read and update state to PENDING
				now := time.Now()
				mivs[i].ReadAt = &now
				mivs[i].State = models.StatePENDING
				return nil
			}
		}
	}

	return fmt.Errorf("miv not found: %s", mivID)
}

// MarkConversationMivsAsRead marks all incoming unread mivs in a conversation as read for a specific desk
func (s *MemoryStorage) MarkConversationMivsAsRead(conversationID string, deskID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	mivs, exists := s.conversationMivs[conversationID]
	if !exists {
		return fmt.Errorf("conversation not found: %s", conversationID)
	}

	now := time.Now()
	for i, miv := range mivs {
		// Mark as read only if it's addressed to this desk and not already read
		if miv.ArrowTo == deskID && miv.ReadAt == nil {
			mivs[i].ReadAt = &now
		}
	}

	return nil
}

// GetConversationMiv retrieves a specific miv by ID
func (s *MemoryStorage) GetConversationMiv(mivID string) (*models.ConversationMiv, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find the miv across all conversations
	for _, mivs := range s.conversationMivs {
		for _, miv := range mivs {
			if miv.ID == mivID {
				return miv, nil
			}
		}
	}

	return nil, fmt.Errorf("miv not found: %s", mivID)
}

// Notification methods

// CreateNotification creates a new notification
func (s *MemoryStorage) CreateNotification(notif *models.Notification) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if notif.ID == "" {
		s.notificationCounter++
		notif.ID = fmt.Sprintf("notif-%d", s.notificationCounter)
	}

	if notif.CreatedAt.IsZero() {
		notif.CreatedAt = time.Now()
	}

	s.notifications[notif.ID] = notif
	s.notificationsByDesk[notif.DeskID] = append(s.notificationsByDesk[notif.DeskID], notif)
	return nil
}

// GetNotification retrieves a notification by ID
func (s *MemoryStorage) GetNotification(id string) (*models.Notification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	notif, exists := s.notifications[id]
	if !exists {
		return nil, fmt.Errorf("notification not found: %s", id)
	}

	return notif, nil
}

// ListNotificationsByDesk retrieves all notifications for a desk
func (s *MemoryStorage) ListNotificationsByDesk(deskID string, unreadOnly bool) ([]*models.Notification, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	notifs, exists := s.notificationsByDesk[deskID]
	if !exists {
		return []*models.Notification{}, nil
	}

	if !unreadOnly {
		return notifs, nil
	}

	var result []*models.Notification
	for _, notif := range notifs {
		if !notif.Read {
			result = append(result, notif)
		}
	}

	return result, nil
}

// MarkNotificationAsRead marks a notification as read
func (s *MemoryStorage) MarkNotificationAsRead(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	notif, exists := s.notifications[id]
	if !exists {
		return fmt.Errorf("notification not found: %s", id)
	}

	now := time.Now()
	notif.Read = true
	notif.ReadAt = &now
	return nil
}

// Contact storage methods

// CreateContact creates a new contact for a desk
func (s *MemoryStorage) CreateContact(contact *models.Contact) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if contact.ID == "" {
		s.contactCounter++
		contact.ID = fmt.Sprintf("contact-%d", s.contactCounter)
	}

	now := time.Now()
	if contact.CreatedAt.IsZero() {
		contact.CreatedAt = now
	}
	contact.UpdatedAt = now

	s.contacts[contact.ID] = contact
	s.contactsByDesk[contact.DeskID] = append(s.contactsByDesk[contact.DeskID], contact)

	return nil
}

// GetContact retrieves a contact by ID
func (s *MemoryStorage) GetContact(id string) (*models.Contact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	contact, exists := s.contacts[id]
	if !exists {
		return nil, fmt.Errorf("contact not found: %s", id)
	}

	return contact, nil
}

// ListContactsForDesk retrieves all contacts for a desk
func (s *MemoryStorage) ListContactsForDesk(deskID string) ([]*models.Contact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	contacts, exists := s.contactsByDesk[deskID]
	if !exists {
		return []*models.Contact{}, nil
	}

	return contacts, nil
}

// UpdateContact updates an existing contact
func (s *MemoryStorage) UpdateContact(contact *models.Contact) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, exists := s.contacts[contact.ID]
	if !exists {
		return fmt.Errorf("contact not found: %s", contact.ID)
	}

	// Update fields
	if contact.Name != "" {
		existing.Name = contact.Name
	}
	if contact.DeskIDRef != "" {
		existing.DeskIDRef = contact.DeskIDRef
	}
	existing.Notes = contact.Notes
	existing.UpdatedAt = time.Now()

	return nil
}

// DeleteContact deletes a contact
func (s *MemoryStorage) DeleteContact(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	contact, exists := s.contacts[id]
	if !exists {
		return fmt.Errorf("contact not found: %s", id)
	}

	// Remove from main map
	delete(s.contacts, id)

	// Remove from desk contacts
	deskContacts := s.contactsByDesk[contact.DeskID]
	for i, c := range deskContacts {
		if c.ID == id {
			s.contactsByDesk[contact.DeskID] = append(deskContacts[:i], deskContacts[i+1:]...)
			break
		}
	}

	return nil
}

// GetContactByDeskIDRef finds a contact by desk ID reference
func (s *MemoryStorage) GetContactByDeskIDRef(deskID, deskIDRef string) (*models.Contact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	contacts, exists := s.contactsByDesk[deskID]
	if !exists {
		return nil, fmt.Errorf("no contacts found for desk")
	}

	for _, contact := range contacts {
		if contact.DeskIDRef == deskIDRef {
			return contact, nil
		}
	}

	return nil, fmt.Errorf("contact not found for desk ID: %s", deskIDRef)
}
