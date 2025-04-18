//cmd/client/main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jadefox10200/zcomm/core"
	"golang.org/x/crypto/curve25519"
)

const serverURL = "http://localhost:8080"

var (
	conversationsMu sync.RWMutex
	conversations   = make(map[string]map[string][]string)
)

// fetchPublicKeys retrieves public keys for a given ZID from the server.
func fetchPublicKeys(zid string) (core.PublicKeys, error) {
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

// loadConversations loads conversation data from the client's storage.
func loadConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read conversations: %w", err)
	}

	var convs map[string]map[string][]string
	if err := json.Unmarshal(data, &convs); err != nil {
		return fmt.Errorf("unmarshal conversations: %w", err)
	}

	conversationsMu.Lock()
	defer conversationsMu.Unlock()
	conversations[zid] = convs[zid]
	if conversations[zid] == nil {
		conversations[zid] = make(map[string][]string)
	}
	return nil
}

// saveConversations saves conversation data to the client's storage.
func saveConversations(zid string) error {
	path := filepath.Join(zid, "conversations.json")
	conversationsMu.RLock()
	defer conversationsMu.RUnlock()

	data, err := json.MarshalIndent(map[string]map[string][]string{zid: conversations[zid]}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal conversations: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create conversations dir: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// fetchDispatches sends a POST request to retrieve notifications from the server.
func fetchNotifications(zid, ts, sig string) ([]core.Notification, int, error) {
	
	reqData := core.ReceiveRequest{ID: zid, TS: ts, Sig: sig}
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

	var notifs []core.Notification
	if err := json.NewDecoder(resp.Body).Decode(&notifs); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode dispatches: %w", err)
	}
	return notifs, resp.StatusCode, nil
}

// fetchDispatches sends a POST request to retrieve dispatches from the server.
func fetchDispatches(zid, ts, sig string) ([]core.Dispatch, int, error) {
	
	reqData := core.ReceiveRequest{ID: zid, TS: ts, Sig: sig}
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

// decryptDispatch decrypts the body of a dispatch using the shared key.
func decryptDispatch(disp *core.Dispatch, ecdhPriv [32]byte) error {
	ephemeralPub, err := base64.StdEncoding.DecodeString(disp.EphemeralPubKey)
	if err != nil {
		return fmt.Errorf("decode ephemeral key: %w", err)
	}
	var ephemeralPubKey [32]byte
	copy(ephemeralPubKey[:], ephemeralPub)

	sharedKey, err := core.DeriveSharedSecret(ecdhPriv, ephemeralPubKey)
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

//refactor this based on the concept of putting a PreviousDispatchID to indicate which dispatch is being asnwered
// clearConversationDispatches removes related dispatches for an ACK, keeping the ACK itself.
func clearConversationDispatches(zid, conversationID, excludeUUID string, dispatches []core.Dispatch) error {
	for _, basket := range []string{"inbox", "unanswered"} {
		dispIDs, err := LoadBasket(zid, basket)
		if err != nil {
			return fmt.Errorf("load %s: %w", basket, err)
		}
		for _, dispID := range dispIDs {
			for _, d := range dispatches {
				if d.UUID == dispID && d.ConversationID == conversationID && d.UUID != excludeUUID {
					if err := RemoveMessage(zid, basket, dispID); err != nil {
						return fmt.Errorf("remove from %s: %w", basket, err)
					}
				}
			}
		}
	}
	return nil
}

// storeDispatchAndUpdateConversation stores a dispatch and updates conversation state.
func storeDispatchAndUpdateConversation(zid string, disp core.Dispatch, dispatches []core.Dispatch) error {
	if err := StoreDispatch(zid, disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}

	if disp.IsEnd {
		convs, err := LoadConversations(zid)
		if err != nil {
			return fmt.Errorf("load conversations: %w", err)
		}
		for i, conv := range convs {
			if conv.ConID == disp.ConversationID {
				convs[i].Ended = true
				break
			}
		}
		path := filepath.Join(zid, "conversations.json")
		data, err := json.MarshalIndent(convs, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal conversations: %w", err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write conversations: %w", err)
		}

		if err := clearConversationDispatches(zid, disp.ConversationID, disp.UUID, dispatches); err != nil {
			return err
		}
		fmt.Printf("Conversation %s ended by %s\n", disp.ConversationID, disp.From)
	}

	if err := StoreBasket(zid, "inbox", disp.UUID); err != nil {
		return fmt.Errorf("store inbox: %w", err)
	}

	convs, err := LoadConversations(zid)
	if err != nil {
		return fmt.Errorf("load conversations: %w", err)
	}
	seqNo := 1
	for _, conv := range convs {
		if conv.ConID == disp.ConversationID {
			for _, entry := range conv.Dispatches {
				if entry.SeqNo >= seqNo {
					seqNo = entry.SeqNo + 1
				}
			}
		}
	}
	if err := StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	// Check and clear unanswered basket
	unanswered, err := LoadBasket(zid, "unanswered")
	if err != nil {
		return fmt.Errorf("load unanswered: %w", err)
	}
	for _, unansweredID := range unanswered {
		for _, unansweredDisp := range dispatches {
			if unansweredDisp.UUID == unansweredID && unansweredDisp.ConversationID == disp.ConversationID && unansweredDisp.To[0] == disp.From {
				if err := RemoveMessage(zid, "unanswered", unansweredID); err != nil {
					return fmt.Errorf("remove unanswered: %w", err)
				}
				fmt.Printf("Removed dispatch %s from unanswered\n", unansweredID)
			}
		}
	}
	return nil
}

// checkForMessages polls the server for new dispatches and processes them.
func checkForMessages(zid string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	backoff := 5 * time.Second
	maxBackoff := 60 * time.Second

	for {

		// Send any pending confirmations
		if err := processPendingNotifications(zid); err != nil {
			fmt.Fprintf(os.Stderr, "Process pending confirmations: %v\n", err)
		}

		//create signature to make receive request:
		ts, sig, err := createReqSignature(zid, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(backoff)
			continue
		}

		//request dispatches from the server:
		dispatches, statusCode, err := fetchDispatches(zid, ts, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(backoff)
			backoff = min(maxBackoff, backoff*2)
			continue
		}

		if statusCode == http.StatusNoContent {
			backoff = 5 * time.Second
			time.Sleep(backoff)
			continue
		}

		if statusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Server error: status %d\n", statusCode)
			time.Sleep(backoff)
			continue
		}

		localDispatches, err := LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
			continue
		}

		for _, disp := range dispatches {
			fmt.Printf("Received dispatch from %s at %d\n", disp.From, disp.Timestamp)
			keys, err := fetchPublicKeys(disp.From)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Fetch sender keys: %v\n", err)
				continue
			}

			if valid, err := verifyDispatch(disp, keys); !valid || err != nil {
				fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
				continue
			}

			if err := decryptDispatch(&disp, ecdhPriv); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				continue
			}

			if err := storeDispatchAndUpdateConversation(zid, disp, localDispatches); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				continue
			}
			handleSendDelivery(disp, zid, edPriv)
		}

		backoff = 5 * time.Second
		time.Sleep(backoff)
	}
}

func handleSendDelivery(disp core.Dispatch, zid string, edPriv ed25519.PrivateKey) {
    identity, err := LoadIdentity(getIdentityPath(zid))
    if err != nil {
        return
    }
    if identity.identity == nil {
        return
    }
    deliveryReceipt := core.Notification{
        UUID:       uuid.New().String(),
        DispatchID: disp.UUID,
        From:       zid,
        To:         disp.From,
        Type:       "delivery",
        Timestamp:  time.Now().Unix(),
        PubKey:     identity.identity.EdPub,
    }
    deliveryReceipt.Signature, err = signNotification(identity.identity, deliveryReceipt)
    if err != nil {
        return
    }
    data, err := json.Marshal(deliveryReceipt)
    if err != nil {
        return
    }
    resp, err := http.DefaultClient.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
    if err != nil {
        StorePendingNotification(zid, deliveryReceipt)
        return
    }
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {
        StorePendingNotification(zid, deliveryReceipt)
        return
    }
}

//this does the same thing that sendNotification should do...
//instead, the client is asking about every single dispatch in his out basket. 
// confirmSingleDispatch confirms delivery of a single dispatch with the server.
// func confirmSingleDispatch(zid, dispID string, disp core.Dispatch, edPriv ed25519.PrivateKey) error {
// 	type confirmRequest struct {
// 		ID        string `json:"id"`
// 		Timestamp int64  `json:"timestamp"`
// 		Sig       string `json:"sig"`
// 	}

// 	//create a signature for the request
// 	sig, ts, err := createReqSignature(zid, disp, edPriv)
// 	if err != nil {
// 		return fmt.Errorf("signature confirm: %w", err)
// 	}

// 	reqData := confirmRequest{
// 		ID:        zid,
// 		Timestamp: ts,
// 		Sig:       sig,
// 	}
// 	data, err := json.Marshal(reqData)
// 	if err != nil {
// 		return fmt.Errorf("marshal confirm: %w", err)
// 	}

// 	//send confirmatino that despatch was delivered:
// 	req, err := http.NewRequest("POST", serverURL+"/confirm", bytes.NewReader(data))
// 	if err != nil {
// 		return fmt.Errorf("create confirm request: %w", err)
// 	}
// 	req.Header.Set("Content-Type", "application/json")

// 	resp, err := http.DefaultClient.Do(req)
// 	if err != nil {
// 		return fmt.Errorf("send confirm: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusOK {
// 		body, _ := io.ReadAll(resp.Body)
// 		return fmt.Errorf("confirm failed: %s", string(body))
// 	}
// 	return nil
// }

// updateDispatchBasket updates the basket for a confirmed dispatch.
func updateDeliveredDispatch(zid, dispID string, disp core.Dispatch) error {
	if disp.IsEnd {
		if err := RemoveMessage(zid, "out", dispID); err != nil {
			return fmt.Errorf("remove from out: %w", err)
		}
	} else {
		if err := MoveMessage(zid, "out", "unanswered", dispID); err != nil {
			return fmt.Errorf("move to unanswered: %w", err)
		}
	}
	fmt.Printf("Dispatch %s confirmed delivered\n", dispID)
	return nil
}

//
func handleIncomingNotifications(zid string, notifs []core.Notification, disps []core.Dispatch) {
	for _, notif := range notifs{
		// Verify notification signature for security

		pubKey, err := base64.StdEncoding.DecodeString(notif.PubKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			continue //don't error just because we got one false bad notificatoin
		}

		if !verifyNotification(notif, pubKey) {
			fmt.Fprintf(os.Stderr, "Invalid signature for notification %s from %s\n", notif.UUID, notif.From)
			continue
		}

		var thisDisp core.Dispatch
		for _, disp := range disps {
			if disp.UUID == notif.DispatchID{
				thisDisp = disp
				break
			} 
		}
		switch notif.Type{
		case "delivery":	
			err := updateDeliveredDispatch(zid, notif.DispatchID, thisDisp)
			if err != nil{
				fmt.Fprintf(os.Stderr, "update delivered: %v\n", err)
			}
		case "read":
			err = StoreReadReceipt(zid, notif)
			if err != nil {
				fmt.Fprintf(os.Stderr, "incoming store read receipt : %v\n", err)
			}
			
			
		}
	}

	return
}

func pollNotifications(zid string, edPriv ed25519.PrivateKey) {
	for {
		//create signature to make receive request:
		ts, sig, err := createReqSignature(zid, edPriv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		//request notifications from the server:
		notifications, _, err := fetchNotifications(zid, ts, sig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			time.Sleep(5 * time.Second)
			continue
		}

		localDispatches, err := LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load dispatches: %v\n", err)
			continue
		}

		handleIncomingNotifications(zid, notifications, localDispatches)
		time.Sleep(5 * time.Second)
	}
}

// pollDelivery checks for delivery confirmation of outgoing dispatches.
//no longer used. just check for notifications.
// func pollDelivery(zid string, edPriv ed25519.PrivateKey) {
// 	for {
// 		dispIDs, err := LoadBasket(zid, "out")
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Load outbox: %v\n", err)
// 			time.Sleep(5 * time.Second)
// 			continue
// 		}

// 		dispatches, err := LoadDispatches(zid)
// 		if err != nil {
// 			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
// 			continue
// 		}

// 		for _, dispID := range dispIDs {
// 			var disp core.Dispatch
// 			for _, d := range dispatches {
// 				if d.UUID == dispID {
// 					disp = d
// 					break
// 				}
// 			}
// 			if err := confirmSingleDispatch(zid, dispID, disp, edPriv); err == nil {
// 				if err := updateDispatchBasket(zid, dispID, disp); err != nil {
// 					fmt.Fprintf(os.Stderr, "%v\n", err)
// 				}
// 			}
// 		}

// 		time.Sleep(5 * time.Second)
// 	}
// }

// createAndSendDispatch creates and sends a new dispatch (reply or regular).
func createAndSendDispatch(zid, recipient, subject, body, conversationID string, edPriv ed25519.PrivateKey, isEnd bool) error {
	keys, err := fetchPublicKeys(recipient)
	if err != nil {
		return fmt.Errorf("fetch recipient keys: %w", err)
	}

	ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
	if err != nil {
		return fmt.Errorf("decode ecdh key: %w", err)
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

	var sharedKey [32]byte
	shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
	if err != nil {
		return fmt.Errorf("derive shared key: %w", err)
	}
	copy(sharedKey[:], shared)

	disp, err := core.NewEncryptedDispatch(zid, []string{recipient}, nil, nil, subject, body, conversationID, edPriv, sharedKey, ephemeralPub)
	if err != nil {
		return fmt.Errorf("create dispatch: %w", err)
	}
	disp.IsEnd = isEnd

	if err := StoreDispatch(zid, *disp); err != nil {
		return fmt.Errorf("store dispatch: %w", err)
	}
	if err := StoreBasket(zid, "out", disp.UUID); err != nil {
		return fmt.Errorf("store out: %w", err)
	}

	convs, err := LoadConversations(zid)
	if err != nil {
		return fmt.Errorf("load conversations: %w", err)
	}
	seqNo := 1
	for _, conv := range convs {
		if conv.ConID == disp.ConversationID {
			for _, entry := range conv.Dispatches {
				if entry.SeqNo >= seqNo {
					seqNo = entry.SeqNo + 1
				}
			}
		}
	}
	if err := StoreConversation(zid, disp.ConversationID, disp.UUID, seqNo, disp.Subject); err != nil {
		return fmt.Errorf("store conversation: %w", err)
	}

	if isEnd {
		for i, conv := range convs {
			if conv.ConID == disp.ConversationID {
				convs[i].Ended = true
				break
			}
		}
		data, err := json.MarshalIndent(convs, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal conversations: %w", err)
		}
		path := filepath.Join(zid, "conversations.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("write conversations: %w", err)
		}
	}

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
	return nil
}

// handleAnswer processes the "Answer" option for a dispatch.
func handleAnswer(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey) bool {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Reply body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(zid, disp.From, disp.Subject, body, disp.ConversationID, edPriv, false); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return false
	}

	if err := RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
		return false
	}

	fmt.Printf("Reply sent to %s\n", disp.From)
	return true
}

// handlePending moves a dispatch to the pending basket.
func handlePending(zid, basket, dispID string) bool {
	if basket != "pending" {
		if err := MoveMessage(zid, basket, "pending", dispID); err != nil {
			fmt.Fprintf(os.Stderr, "Move to pending: %v\n", err)
			return false
		}
		fmt.Println("Dispatch moved to pending")
		return true
	}
	return false
}

// handleACK removes an ACK dispatch from the basket.
func handleACK(zid, basket, dispID string, isEnd bool) bool {
	if !isEnd {
		fmt.Println("Only ACK dispatches can be removed with this option")
		return false
	}
	if err := RemoveMessage(zid, basket, dispID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove ACK dispatch: %v\n", err)
		return false
	}
	fmt.Println("ACK dispatch removed")
	return true
}

// handleExit exits the dispatch view without action.
func handleExit() bool {
	return false
}

// handleDispatchView displays a dispatch and prompts for actions.
func handleDispatchView(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) bool {

	//display the dispatch
	fmt.Printf("From: %s\nSubject: %s", disp.From, disp.Subject)
	if disp.IsEnd { fmt.Printf(" - ACK")}
	fmt.Printf("\nBody:%s\n", disp.Body)

	//handle the read receipt:
	handleSendRead(disp, zid)

	//display the options of what they can do with this dispatch:
	fmt.Println("1. Answer")
	if disp.IsEnd {
		fmt.Println("2. Delete ACK")
		fmt.Println("3. Exit")
	} else {
		fmt.Println("2. Place in Pending")
		fmt.Println("3. End Conversation")
		fmt.Println("4. Exit")
	}
	
	fmt.Print("Choose an option: ")

	//get user input for their choise of what to do with dispatch 
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		return handleAnswer(zid, disp, basket, edPriv)
	case "2":
		if disp.IsEnd{
			return handleACK(zid, basket, disp.UUID, disp.IsEnd)
		}
		return handlePending(zid, basket, disp.UUID)
	case "3":
		if disp.IsEnd{
			return handleExit()
		}
		return handleSendACK(zid, disp, basket, edPriv)
	case "4":
		if disp.IsEnd{
			fmt.Println("Invalid option")
		}
		return false
	default:
		fmt.Println("Invalid option")
		return false
	}
}

func handleSendACK(zid string, disp core.Dispatch, basket string, edPriv ed25519.PrivateKey) bool {
	keys, err := fetchPublicKeys(disp.From)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fetch recipient keys: %v\n", err)
		return false
	}

	ecdhPub, err := base64.StdEncoding.DecodeString(keys.ECDHPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ecdh key: %v\n", err)
		return false
	}
	var ecdhPubKey [32]byte
	copy(ecdhPubKey[:], ecdhPub)

	var ephemeralPriv [32]byte
	if _, err := rand.Read(ephemeralPriv[:]); err != nil {
		fmt.Fprintf(os.Stderr, "Generate ephemeral key: %v\n", err)
		return false
	}

	ephemeralPub, err := curve25519.X25519(ephemeralPriv[:], curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Generate ephemeral public key: %v\n", err)
		return false
	}

	var sharedKey [32]byte
	shared, err := curve25519.X25519(ephemeralPriv[:], ecdhPubKey[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Derive shared key: %v\n", err)
		return false
	}
	copy(sharedKey[:], shared)

	dispEnd, err := core.NewEncryptedDispatch(zid, []string{disp.From}, nil, nil, disp.Subject, "", disp.ConversationID, edPriv, sharedKey, ephemeralPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Create end dispatch: %v\n", err)
		return false
	}
	dispEnd.IsEnd = true // Assumes new field in core.Dispatch

	if err := StoreDispatch(zid, *dispEnd); err != nil {
		fmt.Fprintf(os.Stderr, "Store end dispatch: %v\n", err)
		return false
	}
	if err := StoreBasket(zid, "out", dispEnd.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Store end out: %v\n", err)
		return false
	}

	convs, err := LoadConversations(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
		return false
	}
	seqNo := 1
	for _, conv := range convs {
		if conv.ConID == disp.ConversationID {
			for _, entry := range conv.Dispatches {
				if entry.SeqNo >= seqNo {
					seqNo = entry.SeqNo + 1
				}
			}
		}
	}
	if err := StoreConversation(zid, dispEnd.ConversationID, dispEnd.UUID, seqNo, disp.Subject); err != nil {
		fmt.Fprintf(os.Stderr, "Store end conversation: %v\n", err)
		return false
	}

	data, err := json.Marshal(dispEnd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal end dispatch: %v\n", err)
		return false
	}

	resp, err := http.Post(serverURL+"/send", "application/json", bytes.NewReader(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Send end dispatch: %v\n", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "Send end failed: %s\n", string(body))
		return false
	}

	if err := RemoveMessage(zid, basket, disp.UUID); err != nil {
		fmt.Fprintf(os.Stderr, "Remove original: %v\n", err)
		return false
	}

	fmt.Println("Conversation ended")
	return true
}

// sendNewDispatch creates and sends a new dispatch from user input.
func sendNewDispatch(zid string, edPriv ed25519.PrivateKey) error {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("To: ")
	to, _ := reader.ReadString('\n')
	to = strings.TrimSpace(to)
	fmt.Print("Subject: ")
	subject, _ := reader.ReadString('\n')
	subject = strings.TrimSpace(subject)
	fmt.Print("Body: ")
	body, _ := reader.ReadString('\n')
	body = strings.TrimSpace(body)

	if err := createAndSendDispatch(zid, to, subject, body, "", edPriv, false); err != nil {
		return err
	}
	fmt.Printf("Dispatch sent to %s\n", to)
	return nil
}

// selectDispatchFromBasket displays dispatches in a basket and returns the selected one.
func selectDispatchFromBasket(zid, basket string) (core.Dispatch, bool) {
	dispIDs, err := LoadBasket(zid, basket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load %s: %v\n", basket, err)
		return core.Dispatch{}, false
	}
	if len(dispIDs) == 0 {
		fmt.Printf("%s is empty\n", strings.Title(basket))
		return core.Dispatch{}, false
	}

	dispatches, err := LoadDispatches(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
		return core.Dispatch{}, false
	}

	for i, dispID := range dispIDs {
		for _, disp := range dispatches {
			if disp.UUID == dispID {
				if basket == "unanswered" {
					fmt.Printf("%d. To: %s, Subject: %s\n", i+1, disp.To[0], disp.Subject)
				} else {
					fmt.Printf("%d. From: %s, Subject: %s", i+1, disp.From, disp.Subject)
					if disp.IsEnd{fmt.Printf(" - ACK")}
					fmt.Printf("\n")
				}
			}
		}
	}

	fmt.Print("Select dispatch number (0 to exit): ")
	var num int
	fmt.Scanln(&num)
	if num == 0 {
		return core.Dispatch{}, false
	}
	if num < 1 || num > len(dispIDs) {
		fmt.Println("Invalid selection")
		return core.Dispatch{}, false
	}

	for _, disp := range dispatches {
		if disp.UUID == dispIDs[num-1] {
			return disp, true
		}
	}
	return core.Dispatch{}, false
}

// viewBasket displays and processes dispatches in a specified basket.
func viewBasket(zid, basket string, edPriv ed25519.PrivateKey, ecdhPriv [32]byte) {
	if basket == "unanswered" {
		dispIDs, err := LoadBasket(zid, basket)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load unanswered: %v\n", err)
			return
		}
		if len(dispIDs) == 0 {
			fmt.Println("No unanswered dispatches")
			return
		}

		dispatches, err := LoadDispatches(zid)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
			return
		}

		for i, dispID := range dispIDs {
			for _, disp := range dispatches {
				if disp.UUID == dispID {
					fmt.Printf("%d. To: %s, Subject: %s\n", i+1, disp.To[0], disp.Subject)
				}
			}
		}

		fmt.Print("Select dispatch number (0 to exit, -N to forget): ")
		var num int
		fmt.Scanln(&num)
		if num == 0 {
			return
		}
		if num < 0 {
			num = -num
			if num < 1 || num > len(dispIDs) {
				fmt.Println("Invalid selection")
				return
			}
			dispID := dispIDs[num-1]
			if err := RemoveMessage(zid, "unanswered", dispID); err != nil {
				fmt.Fprintf(os.Stderr, "Forget dispatch: %v\n", err)
				return
			}
			fmt.Printf("Dispatch %s forgotten\n", dispID)
			return
		}
		if num < 1 || num > len(dispIDs) {
			fmt.Println("Invalid selection")
			return
		}

		var selected core.Dispatch
		for _, disp := range dispatches {
			if disp.UUID == dispIDs[num-1] {
				selected = disp
				break
			}
		}

		fmt.Printf("To: %s\nSubject: %s\nBody: %s\n", selected.To[0], selected.Subject, selected.Body)
		fmt.Print("Press Enter to continue...")
		reader := bufio.NewReader(os.Stdin)
		reader.ReadString('\n')
		return
	}

	disp, ok := selectDispatchFromBasket(zid, basket)
	if !ok {
		return
	}
	if handleDispatchView(zid, disp, basket, edPriv, ecdhPriv) {
		fmt.Println("Dispatch processed")
	}
}

// viewConversations displays all active conversations.
func viewConversations(zid string) {
	convs, err := LoadConversations(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load conversations: %v\n", err)
		return
	}
	if len(convs) == 0 {
		fmt.Println("No conversations")
		return
	}

	dispatches, err := LoadDispatches(zid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load dispatches: %v\n", err)
		return
	}

	type convEntry struct {
		ConID      string
		Subject    string
		Dispatches []struct {
			DispID string
			SeqNo  int
		}
		Ended bool
	}
	convList := make([]convEntry, 0, len(convs))
	for _, conv := range convs {
		if !conv.Ended {
			convList = append(convList, convEntry{
				ConID:      conv.ConID,
				Subject:    conv.Subject,
				Dispatches: conv.Dispatches,
				Ended:      conv.Ended,
			})
		}
	}

	if len(convList) == 0 {
		fmt.Println("No active conversations")
		return
	}

	for i, conv := range convList {
		fmt.Printf("\n%d. Subject: %s (ID: %s)\n", i+1, conv.Subject, conv.ConID)
		entries := conv.Dispatches
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].SeqNo < entries[j].SeqNo
		})
		for _, entry := range entries {
			for _, disp := range dispatches {
				if disp.UUID == entry.DispID {
					fmt.Printf("    %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
				}
			}
		}
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Select conversation number (0 to exit): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" || input == "0" {
		return
	}

	num, err := strconv.Atoi(input)
	if err != nil || num < 1 || num > len(convList) {
		fmt.Println("Invalid selection")
		return
	}

	selectedConv := convList[num-1]
	fmt.Println("\nConversation Thread:")
	entries := selectedConv.Dispatches
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SeqNo < entries[j].SeqNo
	})
	for _, entry := range entries {
		for _, disp := range dispatches {
			if disp.UUID == entry.DispID {
				fmt.Printf("  %d. From: %s, Subject: %s, Time: %s\n", entry.SeqNo, disp.From, disp.Subject, time.Unix(disp.Timestamp, 0).Format(time.RFC3339))
			}
		}
	}
	fmt.Print("Press Enter to continue...")
	reader.ReadString('\n')
}

// min returns the smaller of two durations.
func min(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func main() {
	zid := flag.String("zid", "", "ZID for this client")
	flag.Parse()
	if *zid == "" {
		var err error
		*zid, err = promptNewOrLogin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get ZID: %v\n", err)
			os.Exit(1)
		}
	}

	is, err := LoadIdentity(filepath.Join("data", "identities", fmt.Sprintf("identity_%s.json", *zid)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load identity: %v\n", err)
		os.Exit(1)
	}
	if is.identity == nil {
		fmt.Fprintf(os.Stderr, "Identity for %s not found\n", *zid)
		os.Exit(1)
	}
	identity := is.identity

	edPriv, err := base64.StdEncoding.DecodeString(identity.EdPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ed private key: %v\n", err)
		os.Exit(1)
	}

	ecdhPrivBytes, err := base64.StdEncoding.DecodeString(identity.ECDHPriv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Decode ecdh private key: %v\n", err)
		os.Exit(1)
	}
	var ecdhPriv [32]byte
	copy(ecdhPriv[:], ecdhPrivBytes)

	go checkForMessages(*zid, edPriv, ecdhPriv)
	go pollNotifications(*zid, edPriv)

	reader := bufio.NewReader(os.Stdin)
	for {
		inIds, pendingIds, outIds, unansweredIds, err:= LoadBaskets(*zid)
		if err != nil{
			fmt.Fprintf(os.Stderr, "Failed to loadbaskets: %v", err)
			fmt.Println("\n1. Send Dispatch")
			fmt.Println("2. View Inbox")
			fmt.Println("3. View Pending")
			fmt.Println("4. View Out")
			fmt.Println("5. View Unanswered")
			fmt.Println("6. View Conversations")
			fmt.Println("7. Exit")
			fmt.Print("Choose an option: ")
		}
		
		fmt.Printf("\n1. Send Dispatch\n")
		fmt.Printf("2. View Inbox [%v]\n", len(inIds))
		fmt.Printf("3. View Pending [%v]\n", len(pendingIds))
		fmt.Printf("4. View Out [%v]\n", len(outIds))
		fmt.Printf("5. View Unanswered [%v]\n", len(unansweredIds))
		fmt.Printf("6. View Conversations\n")
		fmt.Printf("7. Exit\n")
		fmt.Print("Choose an option: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			if err := sendNewDispatch(*zid, edPriv); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
		case "2":
			viewBasket(*zid, "inbox", edPriv, ecdhPriv)
		case "3":
			viewBasket(*zid, "pending", edPriv, ecdhPriv)
		case "4":
			viewBasket(*zid, "out", edPriv, ecdhPriv)
		case "5":
			viewBasket(*zid, "unanswered", edPriv, ecdhPriv)
		case "6":
			viewConversations(*zid)
		case "7":
			os.Exit(0)
		default:
			fmt.Println("Invalid option")
		}
	}
}

func LoadBaskets(zid string) ([]string, []string, []string, []string, error){
	inIds, err := LoadBasket(zid, "inbox")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load in: %v", err.Error())
	}
	pendingIds, err := LoadBasket(zid, "pending")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pending in: %v", err.Error())
	}
	outIds, err := LoadBasket(zid, "out")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load out: %v", err.Error())
	}
	unansweredIds, err := LoadBasket(zid, "unanswered")
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("load unanswered: %v", err.Error())
	}

	return inIds, pendingIds, outIds, unansweredIds, nil 
}

func handleSendRead(disp core.Dispatch, zid string) {

	identity, err := LoadIdentity(getIdentityPath(zid))
    if err != nil {
        fmt.Fprintf(os.Stderr, "couldn't load identity send read: %v\n", err)
        return
    }
    if identity.identity == nil {
        fmt.Fprintf(os.Stderr, "identity not initialized for %s\n", zid)
        return
    }
    edPub, err := base64.StdEncoding.DecodeString(identity.identity.EdPub)
    if err != nil {
        fmt.Fprintf(os.Stderr, "decode ed public key: %v\n", err)
        return
    }
    readReceipt := core.Notification{
        UUID:       uuid.New().String(),
        DispatchID: disp.UUID,
        From:       zid,
        To:         disp.From,
        Type:       "read",
        Timestamp:  time.Now().Unix(),
        PubKey:     base64.StdEncoding.EncodeToString(edPub),
    }
    readReceipt.Signature, err = signNotification(identity.identity, readReceipt)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Sign read receipt: %v\n", err)
        return
    }

	// Store read receipt locally
	if err := StoreReadReceipt(zid, readReceipt); err != nil {
		fmt.Fprintf(os.Stderr, "Store read receipt: %v\n", err)
		return
	}

	// Attempt to send read receipt
	data, err := json.Marshal(readReceipt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Marshal read receipt: %v\n", err)
		return
	}
	resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
	if err != nil || resp.StatusCode != http.StatusOK {
		// Queue if offline or server error
		if err := StorePendingNotification(zid, readReceipt); err != nil {
			fmt.Fprintf(os.Stderr, "Queue read receipt: %v\n", err)
			return
		}
		fmt.Printf("Offline or server error, read receipt queued\n")
		if resp != nil {
			resp.Body.Close()
		}
	} else {
		resp.Body.Close()
	}
}

// processPendingConfirmations sends queued confirmations when online
func processPendingNotifications(myID string) error {
	notifs, err := LoadPendingNotifications(myID)
	if err != nil {
		return fmt.Errorf("load pending confirmations: %w", err)
	}
	if len(notifs) == 0 {
		return nil
	}

	for _, notif := range notifs {
		data, err := json.Marshal(notif)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Marshal pending confirmation %s: %v\n", notif.DispatchID, err)
			continue
		}
		resp, err := http.Post(serverURL+"/notification_push", "application/json", bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Send pending confirmation %s: %v\n", notif.DispatchID, err)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintf(os.Stderr, "Send pending confirmation %s failed: %s\n", notif.DispatchID, resp.Status)
			continue
		}

		// Remove from queue
		if err := RemovePendingNotification(myID, notif.DispatchID, notif.Type); err != nil {
			fmt.Fprintf(os.Stderr, "Remove pending confirmation %s: %v\n", notif.DispatchID, err)
			continue
		}
		fmt.Printf("Sent queued %s confirmation for %s\n", notif.Type, notif.DispatchID)
	}
	return nil
}