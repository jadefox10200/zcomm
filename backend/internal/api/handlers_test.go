package api

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jadefox10200/missiv/backend/internal/crypto"
	"github.com/jadefox10200/missiv/backend/internal/models"
	"github.com/jadefox10200/missiv/backend/internal/storage"
)

// testPNGData represents a valid 1x1 PNG image
var testPNGData = []byte{
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
	0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, // IHDR chunk
	0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
	0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
	0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
	0x00, 0x03, 0x01, 0x01, 0x00, 0x18, 0xDD, 0x8D,
	0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
	0x44, 0xAE, 0x42, 0x60, 0x82,
}

// createAttachmentRequest creates an authenticated multipart form request with the given image data.
func createAttachmentRequest(imageData []byte, filename string, token string) (*http.Request, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	
	// Create form file with proper content type header
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", `form-data; name="upload"; filename="`+filename+`"`)
	h.Set("Content-Type", "image/png")
	part, err := writer.CreatePart(h)
	if err != nil {
		return nil, err
	}
	
	_, err = io.Copy(part, bytes.NewReader(imageData))
	if err != nil {
		return nil, err
	}
	
	err = writer.Close()
	if err != nil {
		return nil, err
	}

	req := httptest.NewRequest(http.MethodPost, "/api/attachments", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Host = "localhost:8080"
	
	return req, nil
}

func newAuthenticatedTestServer(t *testing.T) (*Server, string, string, string) {
	t.Helper()

	gin.SetMode(gin.TestMode)
	tokenStore = make(map[string]string)

	store := storage.NewMemoryStorage()
	account := &models.Account{
		Username:     "tester",
		PasswordHash: "hash",
		DisplayName:  "Tester",
		Role:         models.AccountRoleUser,
		Status:       models.AccountStatusActive,
		Desks:        []string{},
		ActiveDesk:   "",
	}
	if err := store.CreateAccount(account); err != nil {
		t.Fatalf("failed to create account: %v", err)
	}

	var privateKey [32]byte
	privateKey[0] = 1
	desk := &models.Desk{
		ID:        "5551234567",
		AccountID: account.ID,
		Name:      "Primary Desk",
		PublicKey: crypto.PublicKeyToBase64([32]byte{}),
	}
	if err := store.CreateDesk(desk, privateKey); err != nil {
		t.Fatalf("failed to create desk: %v", err)
	}
	account.ActiveDesk = desk.ID
	account.Desks = []string{desk.ID}
	if err := store.UpdateAccount(account); err != nil {
		t.Fatalf("failed to update account: %v", err)
	}

	token := "test-token"
	tokenStore[token] = account.ID

	server := NewServerWithStorage(store)
	return server, token, account.ID, desk.ID
}

func TestUploadAttachment_ReturnsAttachmentMetadata(t *testing.T) {
	// Set Gin to test mode
	server, token, _, deskID := newAuthenticatedTestServer(t)

	// Create a temporary directory for uploads
	tmpDir := t.TempDir()
	os.Setenv("ATTACHMENT_DIR", tmpDir)
	defer os.Unsetenv("ATTACHMENT_DIR")

	// Create request
	req, err := createAttachmentRequest(testPNGData, "test.png", token)
	if err != nil {
		t.Fatalf("Failed to create upload request: %v", err)
	}

	// Create response recorder
	w := httptest.NewRecorder()

	// Perform request
	server.router.ServeHTTP(w, req)

	// Check response code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, w.Code)
		t.Logf("Response body: %s", w.Body.String())
		return
	}

	// Parse response
	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// Check that attachment metadata is present
	attachmentID, ok := response["id"].(string)
	if !ok || attachmentID == "" {
		t.Fatalf("Expected 'id' field in response, got: %v", response)
	}
	if response["uploaded_by"] != deskID {
		t.Fatalf("Expected uploaded_by to match active desk, got: %v", response["uploaded_by"])
	}
	if response["original_filename"] != "test.png" {
		t.Fatalf("Expected original filename to be preserved, got: %v", response["original_filename"])
	}

	// Verify the file was actually saved
	savedPath := filepath.Join(tmpDir, response["stored_filename"].(string))
	if _, err := os.Stat(savedPath); os.IsNotExist(err) {
		t.Errorf("Expected file to be saved at %s, but it doesn't exist", savedPath)
	}
}


func TestDownloadAttachment_ReturnsFileContents(t *testing.T) {
	server, token, _, _ := newAuthenticatedTestServer(t)
	tmpDir := t.TempDir()
	os.Setenv("ATTACHMENT_DIR", tmpDir)
	defer os.Unsetenv("ATTACHMENT_DIR")

	uploadReq, err := createAttachmentRequest(testPNGData, "test.png", token)
	if err != nil {
		t.Fatalf("Failed to create upload request: %v", err)
	}

	uploadRec := httptest.NewRecorder()
	server.router.ServeHTTP(uploadRec, uploadReq)
	if uploadRec.Code != http.StatusOK {
		t.Fatalf("Expected upload to succeed, got %d: %s", uploadRec.Code, uploadRec.Body.String())
	}

	var uploadResponse map[string]interface{}
	if err := json.Unmarshal(uploadRec.Body.Bytes(), &uploadResponse); err != nil {
		t.Fatalf("Failed to parse upload response: %v", err)
	}
	attachmentID := uploadResponse["id"].(string)

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/attachments/"+attachmentID, nil)
	downloadReq.Header.Set("Authorization", "Bearer "+token)
	downloadReq.Host = "localhost:8080"
	downloadRec := httptest.NewRecorder()
	server.router.ServeHTTP(downloadRec, downloadReq)

	if downloadRec.Code != http.StatusOK {
		t.Fatalf("Expected download to succeed, got %d: %s", downloadRec.Code, downloadRec.Body.String())
	}

	if !bytes.Equal(downloadRec.Body.Bytes(), testPNGData) {
		t.Fatalf("Downloaded attachment bytes did not match uploaded bytes")
	}
}
