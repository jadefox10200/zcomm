package storage

import (
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

// SQLiteStorage provides SQLite-based persistent storage
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite storage instance
func NewSQLiteStorage(dbPath string) (*SQLiteStorage, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		return nil, fmt.Errorf("failed to enable foreign keys: %w", err)
	}

	// Execute schema
	if _, err := db.Exec(schemaSQL); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	if err := ensureAccountsSchema(db); err != nil {
		return nil, fmt.Errorf("failed to migrate accounts schema: %w", err)
	}

	return &SQLiteStorage{db: db}, nil
}

func ensureAccountsSchema(db *sql.DB) error {
	alterStatements := []string{
		"ALTER TABLE accounts ADD COLUMN role TEXT NOT NULL DEFAULT 'user'",
		"ALTER TABLE accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active'",
		"ALTER TABLE accounts ADD COLUMN locked_at DATETIME",
		"ALTER TABLE accounts ADD COLUMN closed_at DATETIME",
		"ALTER TABLE accounts ADD COLUMN force_password_reset BOOLEAN NOT NULL DEFAULT 0",
		"ALTER TABLE accounts ADD COLUMN active_desk TEXT NOT NULL DEFAULT ''",
	}

	for _, stmt := range alterStatements {
		if _, err := db.Exec(stmt); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "duplicate column name") {
				continue
			}
			return err
		}
	}

	return nil
}

// Close closes the database connection
func (s *SQLiteStorage) Close() error {
	return s.db.Close()
}

// Legacy Identity methods (for backward compatibility)

func (s *SQLiteStorage) SetIdentity(identity *models.Identity) {
	_, _ = s.db.Exec(`
		INSERT OR REPLACE INTO identity (id, phone_number, public_key, private_key, created_at)
		VALUES (1, ?, ?, '', ?)
	`, identity.ID, identity.PublicKey, time.Now())
}

func (s *SQLiteStorage) GetIdentity() (*models.Identity, error) {
	var id, publicKey string

	err := s.db.QueryRow("SELECT phone_number, public_key FROM identity WHERE id = 1").
		Scan(&id, &publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("identity not set")
		}
		return nil, err
	}

	return &models.Identity{
		ID:        id,
		PublicKey: publicKey,
		Name:      "",
	}, nil
}

// Legacy Miv methods

func (s *SQLiteStorage) CreateMiv(miv *models.Miv) error {
	if miv.ID == "" {
		miv.ID = fmt.Sprintf("miv-%d", time.Now().UnixNano())
	}
	if miv.CreatedAt.IsZero() {
		miv.CreatedAt = time.Now()
	}

	_, err := s.db.Exec(`
		INSERT INTO mivs (id, from_address, to_address, subject, body, state, created_at, read_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
	`, miv.ID, miv.From, miv.To, miv.Subject, miv.Body, miv.State, miv.CreatedAt)
	return err
}

func (s *SQLiteStorage) GetMiv(id string) (*models.Miv, error) {
	miv := &models.Miv{}

	err := s.db.QueryRow("SELECT id, from_address, to_address, subject, body, state, created_at FROM mivs WHERE id = ?", id).
		Scan(&miv.ID, &miv.From, &miv.To, &miv.Subject, &miv.Body, &miv.State, &miv.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("miv not found")
		}
		return nil, err
	}

	return miv, nil
}

func (s *SQLiteStorage) ListMivs(state models.MivState) ([]*models.Miv, error) {
	query := "SELECT id, from_address, to_address, subject, body, state, created_at FROM mivs"
	var rows *sql.Rows
	var err error

	if state != "" {
		rows, err = s.db.Query(query+" WHERE state = ? ORDER BY created_at DESC", state)
	} else {
		rows, err = s.db.Query(query + " ORDER BY created_at DESC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mivs []*models.Miv
	for rows.Next() {
		miv := &models.Miv{}
		if err := rows.Scan(&miv.ID, &miv.From, &miv.To, &miv.Subject, &miv.Body, &miv.State, &miv.CreatedAt); err != nil {
			return nil, err
		}
		mivs = append(mivs, miv)
	}

	return mivs, rows.Err()
}

func (s *SQLiteStorage) UpdateMivState(id string, state models.MivState) error {
	_, err := s.db.Exec("UPDATE mivs SET state = ? WHERE id = ?", state, id)
	return err
}

func (s *SQLiteStorage) DeleteMiv(id string) error {
	_, err := s.db.Exec("DELETE FROM mivs WHERE id = ?", id)
	return err
}

// Account methods

func (s *SQLiteStorage) CreateAccount(account *models.Account) error {
	if account.ID == "" {
		account.ID = fmt.Sprintf("acct-%d", time.Now().UnixNano())
	}
	if account.CreatedAt.IsZero() {
		account.CreatedAt = time.Now()
	}
	account.UpdatedAt = time.Now()
	if account.Role == "" {
		account.Role = models.AccountRoleUser
	}
	if account.Status == "" {
		account.Status = models.AccountStatusActive
	}

	// Check if username already exists
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM accounts WHERE username = ?)", account.Username).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("username already exists")
	}

	_, err = s.db.Exec(`
		INSERT INTO accounts (id, username, password_hash, display_name, role, status, locked_at, closed_at, force_password_reset, active_desk, birthday_hash, first_pet_name_hash, mother_maiden_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, account.ID, account.Username, account.PasswordHash, account.DisplayName, account.Role, account.Status, account.LockedAt, account.ClosedAt, account.ForcePasswordReset, account.ActiveDesk, account.BirthdayHash, account.FirstPetNameHash, account.MotherMaidenHash, account.CreatedAt, account.UpdatedAt)
	return err
}

func (s *SQLiteStorage) GetAccountByID(id string) (*models.Account, error) {
	account := &models.Account{}
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, display_name, role, status, locked_at, closed_at, force_password_reset, active_desk, birthday_hash, first_pet_name_hash, mother_maiden_hash, created_at, updated_at
		FROM accounts WHERE id = ?
	`, id).Scan(&account.ID, &account.Username, &account.PasswordHash, &account.DisplayName, &account.Role, &account.Status, &account.LockedAt, &account.ClosedAt, &account.ForcePasswordReset, &account.ActiveDesk, &account.BirthdayHash, &account.FirstPetNameHash, &account.MotherMaidenHash, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}

	// Load desks
	rows, err := s.db.Query("SELECT id FROM desks WHERE account_id = ?", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	account.Desks = []string{}
	for rows.Next() {
		var deskID string
		if err := rows.Scan(&deskID); err != nil {
			return nil, err
		}
		account.Desks = append(account.Desks, deskID)
	}

	return account, rows.Err()
}

func (s *SQLiteStorage) GetAccountByUsername(username string) (*models.Account, error) {
	account := &models.Account{}
	err := s.db.QueryRow(`
		SELECT id, username, password_hash, display_name, role, status, locked_at, closed_at, force_password_reset, active_desk, birthday_hash, first_pet_name_hash, mother_maiden_hash, created_at, updated_at
		FROM accounts WHERE username = ?
	`, username).Scan(&account.ID, &account.Username, &account.PasswordHash, &account.DisplayName, &account.Role, &account.Status, &account.LockedAt, &account.ClosedAt, &account.ForcePasswordReset, &account.ActiveDesk, &account.BirthdayHash, &account.FirstPetNameHash, &account.MotherMaidenHash, &account.CreatedAt, &account.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("account not found")
		}
		return nil, err
	}

	// Load desks
	rows, err := s.db.Query("SELECT id FROM desks WHERE account_id = ?", account.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	account.Desks = []string{}
	for rows.Next() {
		var deskID string
		if err := rows.Scan(&deskID); err != nil {
			return nil, err
		}
		account.Desks = append(account.Desks, deskID)
	}

	return account, rows.Err()
}

func (s *SQLiteStorage) ListAccounts() ([]*models.Account, error) {
	rows, err := s.db.Query(`
		SELECT id, username, password_hash, display_name, role, status, locked_at, closed_at, force_password_reset, active_desk, birthday_hash, first_pet_name_hash, mother_maiden_hash, created_at, updated_at
		FROM accounts
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	accounts := make([]*models.Account, 0)
	for rows.Next() {
		account := &models.Account{}
		if err := rows.Scan(&account.ID, &account.Username, &account.PasswordHash, &account.DisplayName, &account.Role, &account.Status, &account.LockedAt, &account.ClosedAt, &account.ForcePasswordReset, &account.ActiveDesk, &account.BirthdayHash, &account.FirstPetNameHash, &account.MotherMaidenHash, &account.CreatedAt, &account.UpdatedAt); err != nil {
			return nil, err
		}

		deskRows, err := s.db.Query("SELECT id FROM desks WHERE account_id = ?", account.ID)
		if err != nil {
			return nil, err
		}

		account.Desks = []string{}
		for deskRows.Next() {
			var deskID string
			if err := deskRows.Scan(&deskID); err != nil {
				deskRows.Close()
				return nil, err
			}
			account.Desks = append(account.Desks, deskID)
		}
		if err := deskRows.Err(); err != nil {
			deskRows.Close()
			return nil, err
		}
		deskRows.Close()

		accounts = append(accounts, account)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

func (s *SQLiteStorage) UpdateAccount(account *models.Account) error {
	account.UpdatedAt = time.Now()
	_, err := s.db.Exec(`
		UPDATE accounts SET username = ?, password_hash = ?, display_name = ?, role = ?, status = ?, locked_at = ?, closed_at = ?, force_password_reset = ?, active_desk = ?, birthday_hash = ?, first_pet_name_hash = ?, mother_maiden_hash = ?, updated_at = ?
		WHERE id = ?
	`, account.Username, account.PasswordHash, account.DisplayName, account.Role, account.Status, account.LockedAt, account.ClosedAt, account.ForcePasswordReset, account.ActiveDesk, account.BirthdayHash, account.FirstPetNameHash, account.MotherMaidenHash, account.UpdatedAt, account.ID)
	return err
}

// Desk methods

func (s *SQLiteStorage) CreateDesk(desk *models.Desk, privateKey [32]byte) error {
	if desk.CreatedAt.IsZero() {
		desk.CreatedAt = time.Now()
	}

	// Private key will be stored as-is (raw bytes) for now
	// In a production system, this should be encrypted with the user's password
	// For E2E encryption, the frontend will handle encryption/decryption
	privateKeyBytes := privateKey[:]
	_, err := s.db.Exec(`
		INSERT INTO desks (id, account_id, display_name, public_key, private_key, auto_indent, 
		                   font_family, font_size, line_height, default_salutation, default_closure, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, desk.ID, desk.AccountID, desk.Name, desk.PublicKey, privateKeyBytes, desk.AutoIndent,
		desk.FontFamily, desk.FontSize, desk.LineHeight, desk.DefaultSalutation, desk.DefaultClosure, desk.CreatedAt)
	if err != nil {
		return err
	}

	// Update account's desks list
	_, err = s.db.Exec("UPDATE accounts SET updated_at = ? WHERE id = ?", time.Now(), desk.AccountID)
	return err
}

// GetDeskEncryptedPrivateKey retrieves the private key and encrypts it with the provided password
func (s *SQLiteStorage) GetDeskEncryptedPrivateKey(id string, password string) (string, error) {
	var privateKeyBytes []byte
	err := s.db.QueryRow("SELECT private_key FROM desks WHERE id = ?", id).Scan(&privateKeyBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("desk not found")
		}
		return "", err
	}

	// Encrypt the private key with the password
	encryptedKey, err := crypto.EncryptPrivateKey(privateKeyBytes, password)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt private key: %w", err)
	}

	return encryptedKey, nil
}

func (s *SQLiteStorage) GetDesk(id string) (*models.Desk, error) {
	desk := &models.Desk{}
	err := s.db.QueryRow(`
		SELECT id, account_id, display_name, public_key, auto_indent, font_family, font_size, 
		       line_height, default_salutation, default_closure, created_at
		FROM desks WHERE id = ?
	`, id).Scan(&desk.ID, &desk.AccountID, &desk.Name, &desk.PublicKey, &desk.AutoIndent,
		&desk.FontFamily, &desk.FontSize, &desk.LineHeight, &desk.DefaultSalutation, &desk.DefaultClosure, &desk.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("desk not found")
		}
		return nil, err
	}
	return desk, nil
}

func (s *SQLiteStorage) GetDeskPrivateKey(id string) ([32]byte, error) {
	var privateKeyBytes []byte
	err := s.db.QueryRow("SELECT private_key FROM desks WHERE id = ?", id).Scan(&privateKeyBytes)
	if err != nil {
		if err == sql.ErrNoRows {
			return [32]byte{}, fmt.Errorf("desk not found")
		}
		return [32]byte{}, err
	}

	var privateKey [32]byte
	copy(privateKey[:], privateKeyBytes)
	return privateKey, nil
}

func (s *SQLiteStorage) ListDesksByAccount(accountID string) ([]*models.Desk, error) {
	rows, err := s.db.Query(`
		SELECT id, account_id, display_name, public_key, created_at,
		       auto_indent, font_family, font_size, line_height, default_salutation, default_closure
		FROM desks WHERE account_id = ? ORDER BY created_at
	`, accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var desks []*models.Desk
	for rows.Next() {
		desk := &models.Desk{}
		if err := rows.Scan(
			&desk.ID, &desk.AccountID, &desk.Name, &desk.PublicKey, &desk.CreatedAt,
			&desk.AutoIndent, &desk.FontFamily, &desk.FontSize, &desk.LineHeight, &desk.DefaultSalutation, &desk.DefaultClosure,
		); err != nil {
			return nil, err
		}
		desks = append(desks, desk)
	}

	return desks, rows.Err()
}

func (s *SQLiteStorage) UpdateDesk(desk *models.Desk) error {
	_, err := s.db.Exec(`
		UPDATE desks SET display_name = ?, auto_indent = ?, font_family = ?, font_size = ?,
		                 line_height = ?, default_salutation = ?, default_closure = ? 
		WHERE id = ?
	`, desk.Name, desk.AutoIndent, desk.FontFamily, desk.FontSize,
		desk.LineHeight, desk.DefaultSalutation, desk.DefaultClosure, desk.ID)
	return err
}

// Conversation methods

func (s *SQLiteStorage) CreateConversation(conv *models.Conversation) error {
	if conv.ID == "" {
		conv.ID = fmt.Sprintf("conv-%d", time.Now().UnixNano())
	}
	if conv.CreatedAt.IsZero() {
		conv.CreatedAt = time.Now()
	}
	conv.UpdatedAt = time.Now()

	// Note: other_desk_id is not used in current model but kept in schema for compatibility
	_, err := s.db.Exec(`
		INSERT INTO conversations (id, desk_id, other_desk_id, subject, is_archived, created_at, updated_at)
		VALUES (?, ?, '', ?, ?, ?, ?)
	`, conv.ID, conv.DeskID, conv.Subject, conv.IsArchived, conv.CreatedAt, conv.UpdatedAt)
	return err
}

func (s *SQLiteStorage) GetConversation(id string) (*models.Conversation, error) {
	conv := &models.Conversation{}
	var otherDeskID string
	err := s.db.QueryRow(`
		SELECT id, desk_id, other_desk_id, subject, is_archived, created_at, updated_at
		FROM conversations WHERE id = ?
	`, id).Scan(&conv.ID, &conv.DeskID, &otherDeskID, &conv.Subject, &conv.IsArchived, &conv.CreatedAt, &conv.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("conversation not found")
		}
		return nil, err
	}
	return conv, nil
}

func (s *SQLiteStorage) ListConversationsByDesk(deskID string) ([]*models.Conversation, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT c.id, c.desk_id, c.subject, c.is_archived, c.created_at, c.updated_at
		FROM conversations c
		INNER JOIN conversation_mivs cm ON c.id = cm.conversation_id 
		WHERE cm.owner = ?
		  AND cm.deleted = 0
		  AND cm.is_forgotten = 0
		  AND (
		    c.is_archived = 0 
		    OR c.is_archived IS NULL
		  )
		ORDER BY c.updated_at DESC
	`, deskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conversations []*models.Conversation
	for rows.Next() {
		conv := &models.Conversation{}
		if err := rows.Scan(&conv.ID, &conv.DeskID, &conv.Subject, &conv.IsArchived, &conv.CreatedAt, &conv.UpdatedAt); err != nil {
			return nil, err
		}
		conversations = append(conversations, conv)
	}

	return conversations, rows.Err()
}

func (s *SQLiteStorage) ListArchivedConversationsByDesk(deskID string) ([]*models.Conversation, error) {
	rows, err := s.db.Query(`
		SELECT DISTINCT c.id, c.desk_id, c.subject, c.is_archived, c.created_at, c.updated_at
		FROM conversations c
		INNER JOIN conversation_mivs cm ON c.id = cm.conversation_id 
		WHERE cm.owner = ?
		  AND cm.is_forgotten = 0
		  AND c.is_archived = 1
		ORDER BY c.updated_at DESC
	`, deskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conversations []*models.Conversation
	for rows.Next() {
		conv := &models.Conversation{}
		if err := rows.Scan(&conv.ID, &conv.DeskID, &conv.Subject, &conv.IsArchived, &conv.CreatedAt, &conv.UpdatedAt); err != nil {
			return nil, err
		}
		conversations = append(conversations, conv)
	}

	return conversations, rows.Err()
}

func (s *SQLiteStorage) UpdateConversation(conv *models.Conversation) error {
	conv.UpdatedAt = time.Now()
	_, err := s.db.Exec(`
		UPDATE conversations SET subject = ?, is_archived = ?, updated_at = ? WHERE id = ?
	`, conv.Subject, conv.IsArchived, conv.UpdatedAt, conv.ID)
	return err
}

// ConversationMiv methods

func (s *SQLiteStorage) CreateConversationMiv(miv *models.ConversationMiv) error {
	if miv.ID == "" {
		miv.ID = fmt.Sprintf("miv-%d", time.Now().UnixNano())
	}
	if miv.CreatedAt.IsZero() {
		miv.CreatedAt = time.Now()
	}

	// Serialize Via slice to JSON
	viaJSON, err := json.Marshal(miv.Via)
	if err != nil {
		return err
	}

	// Serialize CC slice to JSON
	ccJSON, err := json.Marshal(miv.Cc)
	if err != nil {
		return err
	}

	// Handle nil font values
	fontFamily := ""
	if miv.FontFamily != nil {
		fontFamily = *miv.FontFamily
	}
	fontSize := ""
	if miv.FontSize != nil {
		fontSize = *miv.FontSize
	}
	lineHeight := "1.65"
	if miv.LineHeight != nil {
		lineHeight = *miv.LineHeight
	}

	_, err = s.db.Exec(`
		INSERT INTO conversation_mivs (id, conversation_id, owner, seq_no, from_desk_id, to_desk_id, arrow_to, subject, body, state, type, 
			font_family, font_size, line_height, is_ack, is_forgotten, deleted, read_at, cc, via, via_index, is_via_rejected, via_rejected_by, 
			via_rejection, rejected_miv_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, miv.ID, miv.ConversationID, miv.Owner, miv.SeqNo, miv.From, miv.To, miv.ArrowTo, miv.Subject, miv.Body, miv.State, miv.Type,
		fontFamily, fontSize, lineHeight, miv.IsAck, miv.IsForgotten, miv.Deleted, miv.ReadAt, string(ccJSON), string(viaJSON), miv.ViaIndex,
		miv.IsViaRejected, miv.ViaRejectedBy, miv.ViaRejection, miv.RejectedMivID, miv.CreatedAt)

	if err != nil {
		return err
	}

	// Update conversation's updated_at
	_, err = s.db.Exec("UPDATE conversations SET updated_at = ? WHERE id = ?", time.Now(), miv.ConversationID)
	return err
}

func (s *SQLiteStorage) CreateAttachment(attachment *models.Attachment) error {
	if attachment.ID == "" {
		attachment.ID = fmt.Sprintf("att-%d", time.Now().UnixNano())
	}
	if attachment.CreatedAt.IsZero() {
		attachment.CreatedAt = time.Now()
	}

	_, err := s.db.Exec(`
		INSERT INTO attachments (id, conversation_id, seq_no, uploaded_by, original_filename, stored_filename, content_type, size, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, attachment.ID, attachment.ConversationID, attachment.SeqNo, attachment.UploadedBy, attachment.OriginalFilename, attachment.StoredFilename, attachment.ContentType, attachment.Size, attachment.CreatedAt)
	return err
}

func (s *SQLiteStorage) GetAttachment(id string) (*models.Attachment, error) {
	attachment := &models.Attachment{}
	err := s.db.QueryRow(`
		SELECT id, conversation_id, seq_no, uploaded_by, original_filename, stored_filename, content_type, size, created_at
		FROM attachments WHERE id = ?
	`, id).Scan(&attachment.ID, &attachment.ConversationID, &attachment.SeqNo, &attachment.UploadedBy, &attachment.OriginalFilename, &attachment.StoredFilename, &attachment.ContentType, &attachment.Size, &attachment.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("attachment not found")
		}
		return nil, err
	}
	return attachment, nil
}

func (s *SQLiteStorage) ListAttachmentsByConversation(conversationID string) ([]*models.Attachment, error) {
	rows, err := s.db.Query(`
		SELECT id, conversation_id, seq_no, uploaded_by, original_filename, stored_filename, content_type, size, created_at
		FROM attachments WHERE conversation_id = ? ORDER BY created_at ASC
	`, conversationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attachments []*models.Attachment
	for rows.Next() {
		attachment := &models.Attachment{}
		if err := rows.Scan(&attachment.ID, &attachment.ConversationID, &attachment.SeqNo, &attachment.UploadedBy, &attachment.OriginalFilename, &attachment.StoredFilename, &attachment.ContentType, &attachment.Size, &attachment.CreatedAt); err != nil {
			return nil, err
		}
		attachments = append(attachments, attachment)
	}

	return attachments, rows.Err()
}

func (s *SQLiteStorage) AssignAttachmentsToConversation(conversationID string, seqNo int, attachmentIDs []string) error {
	if len(attachmentIDs) == 0 {
		return nil
	}

	placeholders := make([]string, len(attachmentIDs))
	args := make([]interface{}, 0, len(attachmentIDs)+2)
	args = append(args, conversationID, seqNo)
	for i, attachmentID := range attachmentIDs {
		placeholders[i] = "?"
		args = append(args, attachmentID)
	}

	query := fmt.Sprintf(`
		UPDATE attachments
		SET conversation_id = ?, seq_no = ?
		WHERE id IN (%s)
	`, strings.Join(placeholders, ","))
	_, err := s.db.Exec(query, args...)
	return err
}

func (s *SQLiteStorage) GetConversationMiv(mivID string) (*models.ConversationMiv, error) {
	miv := &models.ConversationMiv{}
	var readAt sql.NullTime
	var ccJSON, viaJSON string
	var fontFamily, fontSize, lineHeight string

	err := s.db.QueryRow(`
		SELECT id, conversation_id, owner, seq_no, from_desk_id, to_desk_id, arrow_to, subject, body, state, type, font_family, font_size, line_height,
			is_ack, is_forgotten, deleted, read_at, cc, via, via_index, is_via_rejected, via_rejected_by, via_rejection, rejected_miv_id, created_at
		FROM conversation_mivs WHERE id = ? AND deleted = 0
	`, mivID).Scan(&miv.ID, &miv.ConversationID, &miv.Owner, &miv.SeqNo, &miv.From, &miv.To, &miv.ArrowTo, &miv.Subject, &miv.Body, &miv.State,
		&miv.Type, &fontFamily, &fontSize, &lineHeight, &miv.IsAck, &miv.IsForgotten, &miv.Deleted, &readAt, &ccJSON, &viaJSON, &miv.ViaIndex,
		&miv.IsViaRejected, &miv.ViaRejectedBy, &miv.ViaRejection, &miv.RejectedMivID, &miv.CreatedAt)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("conversation miv not found")
		}
		return nil, err
	}

	if readAt.Valid {
		miv.ReadAt = &readAt.Time
	}

	// Convert font strings to pointers
	if fontFamily != "" {
		miv.FontFamily = &fontFamily
	}
	if fontSize != "" {
		miv.FontSize = &fontSize
	}
	if lineHeight != "" {
		miv.LineHeight = &lineHeight
	}

	// Deserialize CC
	if ccJSON != "" && ccJSON != "null" {
		if err := json.Unmarshal([]byte(ccJSON), &miv.Cc); err != nil {
			return nil, err
		}
	}

	// Deserialize Via
	if viaJSON != "" && viaJSON != "null" {
		if err := json.Unmarshal([]byte(viaJSON), &miv.Via); err != nil {
			return nil, err
		}
	}

	attachments, err := s.ListAttachmentsByConversation(miv.ConversationID)
	if err != nil {
		return nil, err
	}
	for _, attachment := range attachments {
		if attachment.SeqNo == miv.SeqNo {
			miv.Attachments = append(miv.Attachments, attachment)
		}
	}

	return miv, nil
}

func (s *SQLiteStorage) GetConversationMivs(conversationID string, deskID string) ([]*models.ConversationMiv, error) {
	// SECURITY: Always filter by owner (deskID) to ensure users only see their own mivs
	rows, err := s.db.Query(`
		SELECT id, conversation_id, owner, seq_no, from_desk_id, to_desk_id, arrow_to, subject, body, state, type, font_family, font_size, line_height,
			is_ack, is_forgotten, deleted, read_at, cc, via, via_index, is_via_rejected, via_rejected_by, via_rejection, rejected_miv_id, created_at
		FROM conversation_mivs WHERE conversation_id = ? AND owner = ? ORDER BY seq_no
	`, conversationID, deskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var mivs []*models.ConversationMiv
	for rows.Next() {
		miv := &models.ConversationMiv{}
		var readAt sql.NullTime
		var ccJSON, viaJSON string
		var fontFamily, fontSize, lineHeight string

		if err := rows.Scan(&miv.ID, &miv.ConversationID, &miv.Owner, &miv.SeqNo, &miv.From, &miv.To, &miv.ArrowTo, &miv.Subject, &miv.Body, &miv.State,
			&miv.Type, &fontFamily, &fontSize, &lineHeight, &miv.IsAck, &miv.IsForgotten, &miv.Deleted, &readAt, &ccJSON, &viaJSON, &miv.ViaIndex,
			&miv.IsViaRejected, &miv.ViaRejectedBy, &miv.ViaRejection, &miv.RejectedMivID, &miv.CreatedAt); err != nil {
			return nil, err
		}

		if readAt.Valid {
			miv.ReadAt = &readAt.Time
		}

		// Convert font strings to pointers
		if fontFamily != "" {
			miv.FontFamily = &fontFamily
		}
		if fontSize != "" {
			miv.FontSize = &fontSize
		}
		if lineHeight != "" {
			miv.LineHeight = &lineHeight
		}

		// Deserialize CC
		if ccJSON != "" && ccJSON != "null" {
			if err := json.Unmarshal([]byte(ccJSON), &miv.Cc); err != nil {
				return nil, err
			}
		}

		// Deserialize Via
		if viaJSON != "" && viaJSON != "null" {
			if err := json.Unmarshal([]byte(viaJSON), &miv.Via); err != nil {
				return nil, err
			}
		}

		attachments, err := s.ListAttachmentsByConversation(miv.ConversationID)
		if err != nil {
			return nil, err
		}
		for _, attachment := range attachments {
			if attachment.SeqNo == miv.SeqNo {
				miv.Attachments = append(miv.Attachments, attachment)
			}
		}

		mivs = append(mivs, miv)
	}

	return mivs, rows.Err()
}

func (s *SQLiteStorage) UpdateConversationMiv(miv *models.ConversationMiv) error {
	_, err := s.db.Exec(`
		UPDATE conversation_mivs 
		SET state = ?, is_ack = ?, is_forgotten = ?, read_at = ?, via_index = ?, is_via_rejected = ?, 
			via_rejected_by = ?, via_rejection = ?, arrow_to = ?
		WHERE id = ?
	`, miv.State, miv.IsAck, miv.IsForgotten, miv.ReadAt, miv.ViaIndex, miv.IsViaRejected,
		miv.ViaRejectedBy, miv.ViaRejection, miv.ArrowTo, miv.ID)

	if err != nil {
		return err
	}

	// Update conversation's updated_at
	_, err = s.db.Exec("UPDATE conversations SET updated_at = ? WHERE id = ?", time.Now(), miv.ConversationID)
	return err
}

func (s *SQLiteStorage) MarkConversationMivAsRead(mivID string, deskID string) error {
	now := time.Now()

	// First, get the miv being marked as read to check if it's a via intermediary or CC recipient
	var conversationID string
	var seqNo int
	var fromDesk, toDesk string
	var mivType string
	var viaJSON string
	var viaIndex int
	err := s.db.QueryRow(`
		SELECT conversation_id, seq_no, from_desk_id, to_desk_id, type, via, via_index
		FROM conversation_mivs 
		WHERE id = ? AND arrow_to = ? AND deleted = 0
	`, mivID, deskID).Scan(&conversationID, &seqNo, &fromDesk, &toDesk, &mivType, &viaJSON, &viaIndex)
	if err != nil {
		return err
	}

	// Check if this is a via intermediary by checking if deskID is in the via array
	var via []string
	if viaJSON != "" && viaJSON != "null" {
		if err := json.Unmarshal([]byte(viaJSON), &via); err != nil {
			return err
		}
	}

	// Determine if this reader is a via intermediary (not the final recipient)
	isViaIntermediary := len(via) > 0 && viaIndex < len(via) && via[viaIndex] == deskID

	// Determine if this reader is a CC recipient
	isCCRecipient := mivType == "CC"

	// Mark the recipient's miv as read
	// Via intermediaries don't change state (stay IN)
	// CC recipients and final recipients change state from IN to PENDING
	if isViaIntermediary {
		// Via intermediaries keep the message in IN state
		_, err = s.db.Exec(`
			UPDATE conversation_mivs 
			SET read_at = ? 
			WHERE id = ? AND arrow_to = ? AND deleted = 0
		`, now, mivID, deskID)
	} else {
		// Final recipients and CC recipients change state from IN to PENDING
		_, err = s.db.Exec(`
			UPDATE conversation_mivs 
			SET read_at = ?, state = CASE WHEN state = 'IN' THEN 'PENDING' ELSE state END 
			WHERE id = ? AND arrow_to = ? AND deleted = 0
		`, now, mivID, deskID)
	}
	if err != nil {
		return err
	}

	// ONLY send read receipt to sender if reader is the FINAL RECIPIENT (not a via intermediary or CC recipient)
	if !isViaIntermediary && !isCCRecipient {
		// Find and mark the sender's corresponding miv as read (their SENT copy)
		_, err = s.db.Exec(`
			UPDATE conversation_mivs 
			SET read_at = ? 
			WHERE conversation_id = ?
			AND owner = ?
			AND seq_no = ?
			AND state = 'SENT'
			AND deleted = 0
		`, now, conversationID, fromDesk, seqNo)
	}

	return err
}

func (s *SQLiteStorage) MarkConversationMivsAsRead(conversationID string, deskID string) error {
	now := time.Now()
	_, err := s.db.Exec(`
		UPDATE conversation_mivs SET read_at = ? 
		WHERE conversation_id = ? AND arrow_to = ? AND read_at IS NULL AND deleted = 0
	`, now, conversationID, deskID)
	return err
}

func (s *SQLiteStorage) DeleteConversationMivs(conversationID string, deskID string) error {
	// Mark all mivs owned by this user as deleted (soft delete)
	_, err := s.db.Exec(`
		UPDATE conversation_mivs SET deleted = 1 
		WHERE conversation_id = ? AND owner = ?
	`, conversationID, deskID)
	if err != nil {
		return err
	}

	// After marking mivs as deleted, archive the conversation
	// This way the conversation is only archived when a user deletes it (typically after ACK)
	_, err = s.db.Exec(`
		UPDATE conversations SET is_archived = 1 
		WHERE id = ?
	`, conversationID)
	return err
}

// Contact methods

func (s *SQLiteStorage) CreateContact(contact *models.Contact) error {
	if contact.ID == "" {
		contact.ID = fmt.Sprintf("contact-%d", time.Now().UnixNano())
	}
	if contact.CreatedAt.IsZero() {
		contact.CreatedAt = time.Now()
	}
	contact.UpdatedAt = time.Now()

	_, err := s.db.Exec(`
		INSERT INTO contacts (id, desk_id, desk_id_ref, display_name, first_name, last_name, greeting_name, notes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, contact.ID, contact.DeskID, contact.DeskIDRef, contact.Name, contact.FirstName, contact.LastName, contact.GreetingName, contact.Notes, contact.CreatedAt, contact.UpdatedAt)
	return err
}

func (s *SQLiteStorage) GetContact(id string) (*models.Contact, error) {
	contact := &models.Contact{}
	err := s.db.QueryRow(`
		SELECT id, desk_id, desk_id_ref, display_name, first_name, last_name, greeting_name, notes, created_at, updated_at
		FROM contacts WHERE id = ?
	`, id).Scan(&contact.ID, &contact.DeskID, &contact.DeskIDRef, &contact.Name, &contact.FirstName, &contact.LastName, &contact.GreetingName, &contact.Notes, &contact.CreatedAt, &contact.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("contact not found")
		}
		return nil, err
	}
	return contact, nil
}

func (s *SQLiteStorage) ListContactsForDesk(deskID string) ([]*models.Contact, error) {
	rows, err := s.db.Query(`
		SELECT id, desk_id, desk_id_ref, display_name, first_name, last_name, greeting_name, notes, created_at, updated_at
		FROM contacts WHERE desk_id = ? ORDER BY display_name
	`, deskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var contacts []*models.Contact
	for rows.Next() {
		contact := &models.Contact{}
		if err := rows.Scan(&contact.ID, &contact.DeskID, &contact.DeskIDRef, &contact.Name,
			&contact.FirstName, &contact.LastName, &contact.GreetingName, &contact.Notes,
			&contact.CreatedAt, &contact.UpdatedAt); err != nil {
			return nil, err
		}
		contacts = append(contacts, contact)
	}

	return contacts, rows.Err()
}

func (s *SQLiteStorage) UpdateContact(contact *models.Contact) error {
	contact.UpdatedAt = time.Now()
	_, err := s.db.Exec(`
		UPDATE contacts SET display_name = ?, first_name = ?, last_name = ?, greeting_name = ?, notes = ?, updated_at = ? WHERE id = ?
	`, contact.Name, contact.FirstName, contact.LastName, contact.GreetingName, contact.Notes, contact.UpdatedAt, contact.ID)
	return err
}

func (s *SQLiteStorage) DeleteContact(id string) error {
	_, err := s.db.Exec("DELETE FROM contacts WHERE id = ?", id)
	return err
}

func (s *SQLiteStorage) GetContactByDeskIDRef(deskID, deskIDRef string) (*models.Contact, error) {
	contact := &models.Contact{}
	err := s.db.QueryRow(`
		SELECT id, desk_id, desk_id_ref, display_name, first_name, last_name, greeting_name, notes, created_at, updated_at
		FROM contacts WHERE desk_id = ? AND desk_id_ref = ?
	`, deskID, deskIDRef).Scan(&contact.ID, &contact.DeskID, &contact.DeskIDRef, &contact.Name, &contact.FirstName, &contact.LastName, &contact.GreetingName, &contact.Notes, &contact.CreatedAt, &contact.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("contact not found")
		}
		return nil, err
	}
	return contact, nil
}

// Notification methods

func (s *SQLiteStorage) CreateNotification(notif *models.Notification) error {
	if notif.ID == "" {
		notif.ID = fmt.Sprintf("notif-%d", time.Now().UnixNano())
	}
	if notif.CreatedAt.IsZero() {
		notif.CreatedAt = time.Now()
	}

	// Map Notification model fields to schema
	// Model uses: Type, Message, Read
	// Schema has: type, title, message, link, is_read
	_, err := s.db.Exec(`
		INSERT INTO notifications (id, desk_id, type, title, message, link, is_read, created_at)
		VALUES (?, ?, ?, '', ?, '', ?, ?)
	`, notif.ID, notif.DeskID, notif.Type, notif.Message, notif.Read, notif.CreatedAt)
	return err
}

func (s *SQLiteStorage) GetNotification(id string) (*models.Notification, error) {
	notif := &models.Notification{}
	var isRead bool
	err := s.db.QueryRow(`
		SELECT id, desk_id, type, message, is_read, created_at
		FROM notifications WHERE id = ?
	`, id).Scan(&notif.ID, &notif.DeskID, &notif.Type, &notif.Message, &isRead, &notif.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("notification not found")
		}
		return nil, err
	}
	notif.Read = isRead
	return notif, nil
}

func (s *SQLiteStorage) ListNotificationsByDesk(deskID string, unreadOnly bool) ([]*models.Notification, error) {
	query := `
		SELECT id, desk_id, type, message, is_read, created_at
		FROM notifications WHERE desk_id = ?`

	if unreadOnly {
		query += " AND is_read = 0"
	}
	query += " ORDER BY created_at DESC"

	rows, err := s.db.Query(query, deskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var notifications []*models.Notification
	for rows.Next() {
		notif := &models.Notification{}
		var isRead bool
		if err := rows.Scan(&notif.ID, &notif.DeskID, &notif.Type, &notif.Message, &isRead, &notif.CreatedAt); err != nil {
			return nil, err
		}
		notif.Read = isRead
		notifications = append(notifications, notif)
	}

	return notifications, rows.Err()
}

func (s *SQLiteStorage) MarkNotificationAsRead(id string) error {
	now := time.Now()
	_, err := s.db.Exec("UPDATE notifications SET is_read = 1, read_at = ? WHERE id = ?", now, id)
	return err
}
