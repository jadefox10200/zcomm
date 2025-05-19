package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

const serverURL = "https://localhost:8443"

// App holds the application state.
type App struct {
	ctx           context.Context
	mu            sync.RWMutex
	ZID           string
	EdPriv        ed25519.PrivateKey
	ECDHPriv      [32]byte
	EncryptionKey []byte
	Storage       Storage

	// Cache for online status
	lastOnlineCheck time.Time
	isOnlineCached  bool
}

// NewApp initializes a new App instance.
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts.
func (app *App) startup(ctx context.Context) {
	app.ctx = ctx
	go app.sendAndReceive()
	go app.pollNotifications()
}

// Initialize HTTP client with custom TLS configuration.
func init() {
	http.DefaultClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // WARNING: Only for development
			},
		},
	}
}

type Account struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	ZIDs         []string `json:"zids"`
}

func (app *App) loadAccount(username string) (*Account, error) {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", username))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read account file: %w", err)
	}
	var account Account
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("unmarshal account: %w", err)
	}
	return &account, nil
}

func (app *App) saveAccount(account *Account) error {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", account.Username))
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal account: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create accounts dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

func (app *App) CreateAccount(username, password string) error {
	path := filepath.Join("data", "accounts", fmt.Sprintf("account_%s.json", username))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		return fmt.Errorf("account already exists")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	hashStr := fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=4$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))

	account := &Account{
		Username:     username,
		PasswordHash: hashStr,
		ZIDs:         []string{},
	}
	return app.saveAccount(account)
}

func (app *App) parsePasswordHash(hashStr string) ([]byte, []byte, error) {
	if hashStr == "" {
		return nil, nil, fmt.Errorf("empty hash string")
	}
	parts := strings.Split(hashStr, "$")
	if len(parts) != 6 {
		return nil, nil, fmt.Errorf("invalid hash format")
	}
	if parts[1] != "argon2id" {
		return nil, nil, fmt.Errorf("invalid algorithm")
	}
	if parts[2] != "v=19" {
		return nil, nil, fmt.Errorf("invalid version")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("decode salt: %w", err)
	}
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("decode hash: %w", err)
	}
	return salt, hash, nil
}

func (app *App) bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (app *App) Login(username, password string) ([]string, error) {
	account, err := app.loadAccount(username)
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	salt, storedHash, err := app.parsePasswordHash(account.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("parse hash: %w", err)
	}
	derivedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	if !app.bytesEqual(derivedHash, storedHash) {
		return nil, fmt.Errorf("invalid password")
	}
	fixedSalt := make([]byte, 16)
	copy(fixedSalt, []byte(username+"zcomm_salt"))
	encryptionKey := argon2.IDKey([]byte(password), fixedSalt, 3, 64*1024, 4, 32)
	if len(encryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key size")
	}
	app.EncryptionKey = encryptionKey
	return account.ZIDs, nil
}

func (app *App) SelectZID(zid string) error {
	if zid == "" {
		return fmt.Errorf("ZID cannot be empty")
	}
	storage, err := NewSQLiteStorage(zid)
	if err != nil {
		return fmt.Errorf("initialize storage: %w", err)
	}
	is, err := LoadIdentity(getIdentityPath(zid))
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if is.identity == nil {
		return fmt.Errorf("identity not found")
	}
	edPriv, ecdhPriv, err := DecryptIdentity(is.identity, app.EncryptionKey)
	if err != nil {
		return fmt.Errorf("decrypt identity: %w", err)
	}
	app.ZID = zid
	app.EdPriv = edPriv
	app.ECDHPriv = ecdhPriv
	app.Storage = storage
	return nil
}

func (app *App) CreateZID(username string) (string, error) {
	identity, err := GenerateAndStoreNewIdentity(app.EncryptionKey)
	if err != nil {
		return "", fmt.Errorf("create ZID: %w", err)
	}
	zid := identity.ID
	account, err := app.loadAccount(username)
	if err != nil {
		return "", fmt.Errorf("load account: %w", err)
	}
	for _, existingZID := range account.ZIDs {
		if existingZID == zid {
			return "", fmt.Errorf("ZID already exists")
		}
	}
	account.ZIDs = append(account.ZIDs, zid)
	if err := app.saveAccount(account); err != nil {
		return "", fmt.Errorf("save account: %w", err)
	}
	if err := app.SelectZID(zid); err != nil {
		return "", fmt.Errorf("select ZID: %w", err)
	}
	return zid, nil
}

func (app *App) ClearKeys() {
	app.mu.Lock()
	defer app.mu.Unlock()
	if app.EdPriv != nil {
		for i := range app.EdPriv {
			app.EdPriv[i] = 0
		}
		app.EdPriv = nil
	}
	for i := range app.ECDHPriv {
		app.ECDHPriv[i] = 0
	}
	for i := range app.EncryptionKey {
		app.EncryptionKey[i] = 0
	}
}

func (app *App) Logout() error {
	app.ClearKeys()
	if s, ok := app.Storage.(*SQLiteStorage); ok {
		return s.db.Close()
	}
	return nil
}

func (app *App) IsOnline() bool {
	app.mu.Lock()
	defer app.mu.Unlock()
	if time.Since(app.lastOnlineCheck) < 5*time.Second {
		return app.isOnlineCached
	}
	resp, err := http.Get(serverURL + "/ping")
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		app.lastOnlineCheck = time.Now()
		app.isOnlineCached = false
		return false
	}
	defer resp.Body.Close()
	var response map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil || response["status"] != "ok" {
		app.lastOnlineCheck = time.Now()
		app.isOnlineCached = false
		return false
	}
	app.lastOnlineCheck = time.Now()
	app.isOnlineCached = true
	return true
}

func (app *App) CreateAndSendDispatch(recipient, subject, body, conversationID string, isEnd bool) error {
	is, err := LoadIdentity(getIdentityPath(app.ZID))
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}
	if is.identity == nil {
		return fmt.Errorf("identity not found")
	}
	app.mu.RLock()
	disp, err := core.NewEncryptedDispatch(app.ZID, recipient, nil, nil, subject, body, conversationID, app.EdPriv, [32]byte{}, nil, isEnd)
	app.mu.RUnlock()
	if err != nil {
		return fmt.Errorf("create dispatch: %w", err)
	}
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(body))
	if err != nil {
		return fmt.Errorf("encrypt body: %w", err)
	}
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)
	disp.Nonce = ""
	if err := app.Storage.StoreDispatch(*disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	if err := app.Storage.StoreBasket("out", disp.UUID, ""); err != nil {
		return fmt.Errorf("store out: %w", err)
	}
	conv, err := app.Storage.LoadConversation(disp.ConversationID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("load conversation: %w", err)
	}
	seqNo := 1
	for _, entry := range conv.Dispatches {
		if entry.SeqNo >= seqNo {
			seqNo = entry.SeqNo + 1
		}
	}
	if err := app.Storage.StoreConversation(disp.ConversationID, disp.UUID, seqNo, subject, isEnd); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}
	return nil
}

func (app *App) GetBasketDispatches(basket string) ([]core.BasketDispatch, error) {
	return app.Storage.LoadBasketDispatches(basket)
}

func (app *App) GetDispatch(dispatchID string) (core.Dispatch, string, error) {
	disp, err := app.Storage.GetDispatch(dispatchID)
	if err != nil {
		return disp, "", fmt.Errorf("get dispatch: %w", err)
	}
	body, err := app.decryptLocalDispatch(&disp)
	if err != nil {
		return disp, "", fmt.Errorf("decrypt dispatch: %w", err)
	}
	return disp, body, nil
}

func (app *App) HandleDispatchAction(basket, dispatchID, action, replyBody string, isEnd bool) error {
	disp, err := app.Storage.GetDispatch(dispatchID)
	if err != nil {
		return fmt.Errorf("get dispatch: %w", err)
	}
	switch action {
	case "answer":
		err = app.CreateAndSendDispatch(disp.From, disp.Subject, replyBody, disp.ConversationID, isEnd)
		if err != nil {
			return fmt.Errorf("create and send reply: %w", err)
		}
		if err := app.Storage.RemoveMessage(basket, dispatchID); err != nil {
			return fmt.Errorf("remove original: %w", err)
		}
	case "ack":
		if !disp.IsEnd {
			err = app.CreateAndSendDispatch(disp.From, disp.Subject, "", disp.ConversationID, true)
			if err != nil {
				return fmt.Errorf("create and send ACK: %w", err)
			}
			if err := app.Storage.RemoveMessage(basket, dispatchID); err != nil {
				return fmt.Errorf("remove original: %w", err)
			}
		} else {
			if err := app.Storage.RemoveMessage(basket, dispatchID); err != nil {
				return fmt.Errorf("remove ACK: %w", err)
			}
		}
	case "pending":
		if basket != "pending" {
			if err := app.Storage.MoveMessage(basket, "pending", dispatchID, "read"); err != nil {
				return fmt.Errorf("move to pending: %w", err)
			}
		}
	case "decline":
		_ = app.handleDecline(disp, basket)
	case "pullback":
		if basket == "out" {
			if err := app.Storage.(*SQLiteStorage).pullBack(disp); err != nil {
				return fmt.Errorf("pull back dispatch: %w", err)
			}
		}
	}
	return nil
}

func (app *App) GetConversations(archived bool) ([]ConvSummary, error) {
	endedVal := 0
	if archived {
		endedVal = 1
	}
	var convList []ConvSummary
	err := app.Storage.(*SQLiteStorage).db.Select(&convList, `
		SELECT con_id, subject, ended
		FROM Conversations
		WHERE ended = ?
		ORDER BY con_id
	`, endedVal)
	if err != nil {
		return nil, fmt.Errorf("select conversations: %w", err)
	}
	return convList, nil
}

func (app *App) GetConversation(conID string) (Conversation, error) {
	return app.Storage.LoadConversation(conID)
}

func (app *App) ToggleConversationArchive(conID string, archive bool) error {
	conv, err := app.Storage.LoadConversation(conID)
	if err != nil {
		return fmt.Errorf("load conversation: %w", err)
	}
	return app.Storage.StoreConversation(conID, "", 0, conv.Subject, archive)
}

func (app *App) AddContact(alias, contactZID string) error {
	keys, err := app.fetchPublicKeys(contactZID)
	if err != nil {
		return fmt.Errorf("fetch public keys: %w", err)
	}
	return app.Storage.AddContact(alias, contactZID, keys.EdPub, keys.ECDHPub)
}

func (app *App) RemoveContact(alias string) error {
	return app.Storage.RemoveContact(alias)
}

func (app *App) ListContacts() ([]Contact, error) {
	return app.Storage.ListContacts()
}

func (app *App) ResolveAlias(input string) (string, error) {
	return app.Storage.ResolveAlias(input)
}

func (app *App) GetBasketCounts() (map[string]int, error) {
	inIds, err := app.Storage.LoadBasket("inbox")
	if err != nil {
		return nil, fmt.Errorf("load inbox: %w", err)
	}
	pendingIds, err := app.Storage.LoadBasket("pending")
	if err != nil {
		return nil, fmt.Errorf("load pending: %w", err)
	}
	outIds, err := app.Storage.LoadBasket("out")
	if err != nil {
		return nil, fmt.Errorf("load out: %w", err)
	}
	awaitingIds, err := app.Storage.LoadBasket("awaiting")
	if err != nil {
		return nil, fmt.Errorf("load awaiting: %w", err)
	}
	return map[string]int{
		"inbox":    len(inIds),
		"pending":  len(pendingIds),
		"out":      len(outIds),
		"awaiting": len(awaitingIds),
	}, nil
}

func (app *App) fetchPublicKeys(zid string) (core.PublicKeys, error) {
	resp, err := http.Get(fmt.Sprintf("%s/pubkey?id=%s", serverURL, zid))
	if err != nil {
		return core.PublicKeys{}, fmt.Errorf("fetch keys: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return core.PublicKeys{}, fmt.Errorf("fetch keys failed: %s", string(body))
	}
	var keys core.PublicKeys
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return core.PublicKeys{}, fmt.Errorf("decode keys: %w", err)
	}
	return keys, nil
}

func (app *App) fetchNotifications() ([]core.Notification, int, error) {
	app.mu.RLock()
	ts, sig, err := createReqSignature(app.ZID, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		return nil, 0, fmt.Errorf("create request signature: %w", err)
	}
	reqData := core.ReceiveRequest{ID: app.ZID, TS: ts, Sig: sig}
	data, err := json.Marshal(reqData)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", serverURL+"/notifications_request", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch notifications: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("server error: %s", string(body))
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}
	var notifs []core.Notification
	if err := json.NewDecoder(resp.Body).Decode(&notifs); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode notifications: %w", err)
	}
	return notifs, resp.StatusCode, nil
}

func (app *App) fetchDispatches() ([]core.Dispatch, int, error) {
	app.mu.RLock()
	ts, sig, err := createReqSignature(app.ZID, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		return nil, 0, fmt.Errorf("create request signature: %w", err)
	}
	reqData := core.ReceiveRequest{ID: app.ZID, TS: ts, Sig: sig}
	data, err := json.Marshal(reqData)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", serverURL+"/receive", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch dispatches: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("server error: %s", string(body))
	}
	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}
	var disps []core.Dispatch
	if err := json.NewDecoder(resp.Body).Decode(&disps); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode dispatches: %w", err)
	}
	return disps, resp.StatusCode, nil
}

func (app *App) decryptLocalDispatch(disp *core.Dispatch) (string, error) {
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)
	ciphertext, err := base64.StdEncoding.DecodeString(disp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to decode body: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(disp.LocalNonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode local nonce: %w", err)
	}
	plaintext, err := core.DecryptAESGCM(localKey[:], nonce, ciphertext)
	if err != nil {
		return "", fmt.Errorf("local decryption failed: %w", err)
	}
	return string(plaintext), nil
}

func (app *App) decryptDispatch(disp *core.Dispatch) error {
	ephemeralPub, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey)
	if err != nil {
		return fmt.Errorf("decode ephemeral key: %w", err)
	}
	var ephemeralPubKey [32]byte
	copy(ephemeralPubKey[:], ephemeralPub)
	sharedKey, err := core.DeriveSharedSecret(app.ECDHPriv, ephemeralPubKey)
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}
	body, err := disp.DecryptBody(sharedKey)
	if err != nil {
		return fmt.Errorf("decrypt dispatch: %w", err)
	}
	disp.Body = body
	return nil
}

func (app *App) storeDispatchAndUpdateConversation(disp core.Dispatch) error {
	localKey := core.DeriveLocalEncryptionKey(app.ECDHPriv)
	plaintext := disp.Body
	if disp.Nonce != "" && disp.EphemeralPubKey != "" {
		if err := app.decryptDispatch(&disp); err != nil {
			return fmt.Errorf("decrypt received dispatch: %w", err)
		}
		plaintext = disp.Body
	}
	localCiphertext, localNonce, err := core.EncryptAESGCM(localKey[:], []byte(plaintext))
	if err != nil {
		return fmt.Errorf("encrypt for local storage: %w", err)
	}
	disp.Body = base64.StdEncoding.EncodeToString(localCiphertext)
	disp.LocalNonce = base64.StdEncoding.EncodeToString(localNonce)
	tx, err := app.Storage.(*SQLiteStorage).db.Beginx()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	var exists bool
	err = tx.Get(&exists, "SELECT EXISTS(SELECT 1 FROM Dispatches WHERE uuid = ?)", disp.UUID)
	if err != nil {
		return fmt.Errorf("check dispatch exists: %w", err)
	}
	if exists {
		return fmt.Errorf("dispatch already stored")
	}
	var awaitingDispatchID string
	err = tx.Get(&awaitingDispatchID, `
		SELECT b.dispatch_id
		FROM Baskets b
		JOIN Dispatches d ON b.dispatch_id = d.uuid
		WHERE d.to_zid = ? AND b.basket_name = 'awaiting' AND d.conversation_id = ?
		LIMIT 1
	`, disp.From, disp.ConversationID)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("check awaiting basket: %w", err)
	}
	if awaitingDispatchID != "" {
		_, err = tx.Exec(`
			DELETE FROM Baskets
			WHERE basket_name = 'awaiting' AND dispatch_id = ?
		`, awaitingDispatchID)
		if err != nil {
			return fmt.Errorf("remove from awaiting basket: %w", err)
		}
	}
	_, err = tx.Exec(`
		INSERT INTO Dispatches (uuid, from_zid, to_zid, subject, body, local_nonce, nonce, ephemeral_pub_key, conversation_id, signature, timestamp, is_end)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, disp.UUID, disp.From, disp.To, disp.Subject, disp.Body, disp.LocalNonce, disp.Nonce, disp.EphemeralPubKey, disp.ConversationID, disp.Signature, disp.Timestamp, disp.IsEnd)
	if err != nil {
		return fmt.Errorf("insert dispatch: %w", err)
	}
	var maxSeqNo sql.NullInt64
	err = tx.Get(&maxSeqNo, "SELECT MAX(seq_no) FROM ConversationDispatches WHERE con_id = ?", disp.ConversationID)
	if err != nil {
		return fmt.Errorf("get max seq_no: %w", err)
	}
	seqNo := 1
	if maxSeqNo.Valid {
		seqNo = int(maxSeqNo.Int64) + 1
	}
	var convExists bool
	err = tx.Get(&convExists, "SELECT EXISTS(SELECT 1 FROM Conversations WHERE con_id = ?)", disp.ConversationID)
	if err != nil {
		return fmt.Errorf("check conversation exists: %w", err)
	}
	if !convExists {
		_, err = tx.Exec(`
			INSERT INTO Conversations (con_id, subject, ended)
			VALUES (?, ?, ?)
		`, disp.ConversationID, disp.Subject, disp.IsEnd)
		if err != nil {
			return fmt.Errorf("insert conversation: %w", err)
		}
	} else {
		_, err = tx.Exec(`
			UPDATE Conversations
			SET ended = ?
			WHERE con_id = ?
		`, disp.IsEnd, disp.ConversationID)
		if err != nil {
			return fmt.Errorf("update conversation: %w", err)
		}
	}
	_, err = tx.Exec(`
		INSERT INTO ConversationDispatches (con_id, dispatch_id, seq_no)
		VALUES (?, ?, ?)
	`, disp.ConversationID, disp.UUID, seqNo)
	if err != nil {
		return fmt.Errorf("insert conversation dispatch: %w", err)
	}
	basket := "inbox"
	_, err = tx.Exec(`
		INSERT INTO Baskets (basket_name, dispatch_id, status)
		VALUES (?, ?, ?)
	`, basket, disp.UUID, "unread")
	if err != nil {
		return fmt.Errorf("insert basket: %w", err)
	}
	return tx.Commit()
}

func handleSendDelivery(app *App, disp core.Dispatch) {
	is, err := LoadIdentity(getIdentityPath(app.ZID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load identity: %v\n", err)
		return
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", app.ZID)
		return
	}

	deliveryReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "delivery",
		Timestamp:  time.Now().Unix(),
	}

	app.mu.RLock()
	err = core.SignNotification(deliveryReceipt, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign notification: %v\n", err)
		return
	}

	data, err := json.Marshal(deliveryReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := app.Storage.StorePendingNotification(*deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			fmt.Println("Stored delivery notification for later due to network error")
		}
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := app.Storage.StorePendingNotification(*deliveryReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			// fmt.Printf("Stored delivery notification for later: server returned %d\n", resp.StatusCode)
		}
		return
	}
	// fmt.Println("Delivery notification sent successfully")
}

// handleSendRead sends a read notification for a dispatch.
func handleSendRead(app *App, disp core.Dispatch) {
	is, err := LoadIdentity(getIdentityPath(app.ZID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't load identity for read receipt: %v\n", err)
		return
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity not initialized for %s\n", app.ZID)
		return
	}

	readReceipt := &core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "read",
		Timestamp:  time.Now().Unix(),
	}

	app.mu.RLock()
	err = core.SignNotification(readReceipt, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sign read receipt: %v\n", err)
		return
	}

	if err := app.Storage.StoreReadReceipt(app, *readReceipt); err != nil {
		fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
		return
	}

	data, err := json.Marshal(readReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal read receipt: %v\n", err)
		return
	}
	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil || resp.StatusCode != http.StatusOK {
		if err := app.Storage.StorePendingNotification(*readReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Queue read receipt: %v\n", err)
		} else {
			// fmt.Printf("Read receipt queued due to %v\n", err)
		}
		if resp != nil {
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
			} else {
				fmt.Printf("Server response body: %s\n", body)
			}
			resp.Body.Close()
		}
	} else {
		// fmt.Println("Read receipt sent successfully")
		resp.Body.Close()
	}
}

// handleIncomingNotifications processes incoming notifications.
func handleIncomingNotifications(app *App, notifs []core.Notification) {
	for _, notif := range notifs {
		keys, err := app.fetchPublicKeys(notif.From)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch public keys for %s: %v\n", notif.From, err)
			continue
		}
		pubKey, err := base64.StdEncoding.DecodeString(keys.EdPub)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Decode public key for %s: %v\n", notif.From, err)
			continue
		}

		valid, err := core.VerifyNotification(notif, pubKey)
		if !valid || err != nil {
			fmt.Fprintf(os.Stderr, "Invalid signature for notification %s from %s: %v\n", notif.UUID, notif.From, err)
			continue
		}

		thisDisp, err := app.Storage.GetDispatch(notif.DispatchID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Get dispatch %s for notification %s: %v\n", notif.DispatchID, notif.UUID, err)
			continue
		}

		switch notif.Type {
		case "delivery":
			//if we are getting a notification about an ack we sent, we don't do anything as it isn't in our basket.
			if thisDisp.IsEnd {
				continue
			}
			err := app.Storage.MoveMessage("awaiting", "awaiting", notif.DispatchID, "Delivered")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update delivered: %v\n", err)
			} else {
				// fmt.Printf("Dispatch %s confirmed delivered\n", notif.DispatchID)
			}
		case "read":
			//if we are getting a notification about an ack we sent, we don't do anything as it isn't in our basket.
			if thisDisp.IsEnd {
				continue
			}
			err = app.Storage.MoveMessage("awaiting", "awaiting", notif.DispatchID, "Read")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Update read: %v\n", err)
			} else {
				err = app.Storage.StoreReadReceipt(app, notif)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
				} else {
					// fmt.Printf("Dispatch %s marked as read\n", notif.DispatchID)
				}
			}
		case "decline":
			err = app.Storage.StoreConversation(thisDisp.ConversationID, "", 0, thisDisp.Subject, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Archive conversation %s: %v\n", thisDisp.ConversationID, err)
				continue
			}

			basket := "awaiting"
			err = app.Storage.RemoveMessage(basket, thisDisp.UUID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Remove dispatch %s from %s: %v\n", thisDisp.UUID, basket, err)
			}

			// fmt.Printf("Dispatch %s declined by %s, conversation %s archived\n", notif.DispatchID, notif.From, thisDisp.ConversationID)
		}
	}
}

func updateDeliveredDispatch(app *App, dispID string, disp core.Dispatch) error {
	if disp.IsEnd {
		if err := app.Storage.RemoveMessage("out", dispID); err != nil {
			return fmt.Errorf("remove from out: %w", err)
		}
	} else {
		if err := app.Storage.MoveMessage("unanswered", "unanswered", dispID, "delivered"); err != nil {
			return fmt.Errorf("move to unanswered: %w", err)
		}
	}
	fmt.Printf("Dispatch %s confirmed delivered\n", dispID)
	return nil
}

func pollNotifications(app *App) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		if !app.IsOnline() {
			// fmt.Println("Offline: Skipping notification fetch")
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		if err := processPendingNotifications(app); err != nil {
			fmt.Fprintf(os.Stderr, "Process pending notifications: %v\n", err)
		}
		notifications, _, err := fetchNotifications(app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch notifications: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		handleIncomingNotifications(app, notifications)
		time.Sleep(5 * time.Second)
	}
}

func fetchNotifications(app *App) ([]core.Notification, int, error) {
	app.mu.RLock()
	ts, sig, err := createReqSignature(app.ZID, app.EdPriv)
	app.mu.RUnlock()
	if err != nil {
		return nil, 0, fmt.Errorf("create request signature: %w", err)
	}

	reqData := core.ReceiveRequest{ID: app.ZID, TS: ts, Sig: sig}
	data, err := json.Marshal(reqData)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", serverURL+"/notifications_request", bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch notifications: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, fmt.Errorf("server error: %s", string(body))
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, resp.StatusCode, nil
	}

	var notifs []core.Notification
	if err := json.NewDecoder(resp.Body).Decode(&notifs); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode notifications: %w", err)
	}
	return notifs, resp.StatusCode, nil
}

func processPendingNotifications(app *App) error {
	notifs, err := app.Storage.LoadPendingNotifications()
	if err != nil {
		return fmt.Errorf("load pending notifications: %w", err)
	}
	if len(notifs) == 0 {
		return nil
	}

	for _, notif := range notifs {
		data, err := json.Marshal(notif)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Send pending notification %s failed: %s\n", notif.UUID, resp.Status)
			continue
		}
		if err := app.Storage.RemovePendingNotification(notif.UUID, notif.Type); err != nil {
			fmt.Fprintf(os.Stderr, "Remove pending notification %s: %v\n", notif.UUID, err)
			continue
		}
		// fmt.Printf("Sent queued %s notification %s\n", notif.Type, notif.UUID)
	}
	return nil
}

func (app *App) pollNotifications() {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		if !app.IsOnline() {
			// fmt.Println("Offline: Skipping notification fetch")
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}
		if err := processPendingNotifications(app); err != nil {
			fmt.Fprintf(os.Stderr, "Process pending notifications: %v\n", err)
		}
		notifications, _, err := fetchNotifications(app)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch notifications: %v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		handleIncomingNotifications(app, notifications)
		time.Sleep(5 * time.Second)
	}
}

func (app *App) sendAndReceive() {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {
		// Check if online before fetching or sending
		if !app.IsOnline() {
			// fmt.Println("Offline: Skipping fetch and send operations")
			time.Sleep(backoff)
			continue
		}

		dispatches, statusCode, err := app.fetchDispatches()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fetch dispatches: %v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}

		if statusCode == http.StatusNoContent {
			// No new dispatches
			backoff = 5 * time.Second
		} else if statusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Server error: status %d\n", statusCode)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		} else {
			// Process incoming dispatches
			for _, disp := range dispatches {
				// fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
				keys, err := app.fetchPublicKeys(disp.From)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Fetch sender keys for %s: %v\n", disp.From, err)
					continue
				}

				valid, err := verifyDispatch(disp, keys)
				if !valid || err != nil {
					fmt.Fprintf(os.Stderr, "Verification failed for dispatch from %s: %v\n", disp.From, err)
					continue
				}

				if err := app.storeDispatchAndUpdateConversation(disp); err != nil {
					fmt.Fprintf(os.Stderr, "Store dispatch from %s: %v\n", disp.From, err)
					continue
				}
				// fmt.Println("Sending delivery notification")
				handleSendDelivery(app, disp)
			}
			backoff = 5 * time.Second
		}

		// Send queued dispatches from OUT
		outDispatches, err := app.Storage.LoadBasketDispatches("out")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load out basket: %v\n", err)
			time.Sleep(backoff)
			continue
		}

		for _, basketDisp := range outDispatches {
			disp, err := app.Storage.GetDispatch(basketDisp.DispatchID)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Load dispatch %s: %v\n", basketDisp.DispatchID, err)
				continue
			}
			// fmt.Printf("Got dispatch for sending with time: %s\n", dateTimeFromUnix(disp.Timestamp))
			// Decrypt body for sending
			disp.Body, err = app.decryptLocalDispatch(&disp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Decrypt dispatch %s: %v\n", disp.UUID, err)
				if err := app.Storage.MoveMessage("out", "failed", disp.UUID, ""); err != nil {
					fmt.Fprintf(os.Stderr, "Move to failed: %v\n", err)
				}
				continue
			}

			// fmt.Printf("Decrypted before being sent: %s\n", disp.Body)
			// fmt.Printf("Time before being sent: %s\n", dateTimeFromUnix(disp.Timestamp))
			// Send using stored details
			err = EncryptAndSendDispatch(app, &disp)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Send dispatch %s to %s: %v\n", disp.UUID, disp.To, err)
				if err := app.Storage.MoveMessage("out", "failed", disp.UUID, ""); err != nil {
					fmt.Fprintf(os.Stderr, "Move to failed: %v\n", err)
				}
				continue
			}

			// Update dispatch fields
			if err := app.Storage.UpdateDispatchFields(disp.UUID, disp.Nonce, disp.EphemeralPubKey, disp.Signature); err != nil {
				fmt.Fprintf(os.Stderr, "Update dispatch fields %s: %v\n", disp.UUID, err)
				continue
			}

			//if this is an ack, remove from out, else we expect an answer.
			if disp.IsEnd {
				err = app.Storage.RemoveMessage("out", disp.UUID)
				if err != nil {
					fmt.Printf("Failed to remove from out: %s\n", err.Error())
				}
			} else {

				if err := app.Storage.MoveMessage("out", "awaiting", disp.UUID, "sent"); err != nil {
					fmt.Fprintf(os.Stderr, "Move to awaiting: %v\n", err)
					continue
				}
			}
			// Move to awaiting

			// fmt.Printf("Dispatch %s sent successfully\n", disp.UUID)
		}

		time.Sleep(backoff)
	}
}

func (app *App) handleDecline(disp core.Dispatch, basket string) bool {
	notif := core.Notification{
		UUID:       uuid.New().String(),
		DispatchID: disp.UUID,
		From:       app.ZID,
		To:         disp.From,
		Type:       "decline",
		Timestamp:  time.Now().Unix(),
	}

	if err := app.Storage.RemoveMessage(basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove dispatch: %v\n", err)
		return false
	}

	app.mu.RLock()
	if err := core.SignNotification(&notif, app.EdPriv); err != nil {
		fmt.Fprintf(os.Stderr, "Sign decline notification: %v\n", err)
		app.mu.RUnlock()
		return false
	}
	app.mu.RUnlock()

	data, err := json.Marshal(notif)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal delivery receipt: %v\n", err)
		return false
	}

	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil {
		if err := app.Storage.StorePendingNotification(notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending notification: %v\n", err)
		} else {
			// fmt.Println("Stored delivery notification for later due to network error")
		}
		return false
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Read response body: %v\n", err)
	} else if resp.StatusCode != http.StatusOK {
		fmt.Printf("Server response body: %s\n", body)
	}

	if resp.StatusCode != http.StatusOK {
		if err := app.Storage.StorePendingNotification(notif); err != nil {
			fmt.Fprintf(os.Stderr, "Store pending decline notification: %v\n", err)
		} else {
			fmt.Printf("Stored decline notification for later: server returned %d\n", resp.StatusCode)
		}
		return false
	}
	fmt.Println("Delivery notification sent successfully")

	if err := app.Storage.StoreConversation(disp.ConversationID, "", 0, disp.Subject, true); err != nil {
		fmt.Fprintf(os.Stderr, "Archive conversation: %v\n", err)
		return false
	}

	fmt.Println("Dispatch declined and conversation archived")
	return true
}

// EncryptAndSendDispatch takes a cleartext body dispatch, encrypts it for the recipient and sends it.
// It populates disp.Nonce, disp.EphemeralPubKey, disp.Signature
func EncryptAndSendDispatch(app *App, disp *core.Dispatch) error {
	keys, err := app.fetchPublicKeys(disp.To)
	if err != nil {
		return fmt.Errorf("fetch recipient keys: %w", err)
	}

	ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
	if err != nil {
		return fmt.Errorf("decode ECDH key: %w", err)
	}
	var ecdhPubKey [32]byte
	copy(ecdhPubKey[:], ecdhPub)

	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		return fmt.Errorf("generate ephemeral key: %w", err)
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("generate ephemeral public key: %w", err)
	}
	disp.EphemeralPubKey = base64.StdEncoding.EncodeToString(ephemeralPub)

	shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}
	var sharedKey [32]byte
	copy(sharedKey[:], shared)

	// Use EncryptAESGCM for transmission encryption
	ciphertext, nonce, err := core.EncryptAESGCM(sharedKey[:], []byte(disp.Body))
	if err != nil {
		return fmt.Errorf("encrypt dispatch: %w", err)
	}
	disp.Nonce = base64.StdEncoding.EncodeToString(nonce)
	disp.Body = base64.StdEncoding.EncodeToString(ciphertext)

	// Sign the dispatch
	if err := core.SignDispatch(disp, app.EdPriv); err != nil {
		return fmt.Errorf("sign dispatch: %w", err)
	}

	// Send the dispatch
	data, err := json.Marshal(disp)
	if err != nil {
		return fmt.Errorf("marshal dispatch: %w", err)
	}

	resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("send dispatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("send dispatch failed: %s", string(body))
	}

	// Update dispatch fields in storage
	if err := app.Storage.UpdateDispatchFields(disp.UUID, disp.Nonce, disp.EphemeralPubKey, disp.Signature); err != nil {
		return fmt.Errorf("update dispatch fields: %w", err)
	}

	return nil
}
