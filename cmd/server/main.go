//cmd/server/main.go
package main

import (
	"log"
	"net/http"
	"sync"

	"github.com/jadefox10200/zcomm/core"
)

func main() {
	// Load persistent stores
	keyStore, err := NewKeyStore("data/pubkeys.json")
	if err != nil {
		log.Fatalf("Failed to load key store: %v", err)
	}

	identityStore, err := NewIdentityStore("data/identities.json")
	if err != nil {
		log.Fatalf("Failed to load identity store: %v", err)
	}

	// Initialize inbox handler
	inbox := NewInbox(keyStore)

	// Register HTTP routes
	http.HandleFunc("/identity", HandleIdentity(identityStore, keyStore))
	http.HandleFunc("/send", inbox.HandleSend)
	http.HandleFunc("/receive", inbox.HandleReceive)
	http.HandleFunc("/notification_push", inbox.HandleConfirm)
	http.HandleFunc("/notifications_request", inbox.HandleReqNotifs)
	http.HandleFunc("/publish", HandlePublishKeys(keyStore))
	http.HandleFunc("/pubkey", HandleFetchKeys(keyStore))

	log.Println("ZComm Switchboard server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

type Inbox struct {
	mu      sync.RWMutex
	//map[zid]dispatch
	inbox   map[string][]core.Dispatch
	keyring *KeyStore
	notifications map[string][]core.Notification
}

func NewInbox(keyring *KeyStore) *Inbox {
	return &Inbox{
		//map[zid]dispatch
		inbox:   make(map[string][]core.Dispatch),
		keyring: keyring,
		notifications:    make(map[string][]core.Notification),
	}
}