import React, { useState, useEffect, useRef, useCallback } from "react";
import { Capacitor } from "@capacitor/core";
import { LocalNotifications } from "@capacitor/local-notifications";
import Auth from "./components/Auth";
import DeskSwitcher from "./components/DeskSwitcher";
import ConversationList from "./components/ConversationList";
import BasketView from "./components/BasketView";
import MivDetailWithContext from "./components/MivDetailWithContext";
import NotificationPanel from "./components/NotificationPanel";
import ComposeMiv from "./components/ComposeMiv";
import ContactManager from "./components/ContactManager";
import Settings from "./components/Settings";
import Toast from "./components/Toast";
import AdminPanel from "./components/AdminPanel";
import {
  Account,
  Desk,
  ConversationWithLatest,
  ConversationMiv,
  GetConversationResponse,
  Notification,
  RegisterRequest,
  CreateMivRequest,
  MivState,
  Contact,
} from "./types";
import * as api from "./api/client";
import "./App.css";
import UnlockKeysModal from "./components/UnlockKeysModal";

type View =
  | "baskets"
  | "conversations"
  | "compose"
  | "notifications"
  | "contacts"
  | "settings"
  | "admin";

function App() {
  const isNativePlatform = Capacitor.isNativePlatform();

  // Authentication state
  const [account, setAccount] = useState<Account | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Mobile navigation state
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Desk state
  const [desks, setDesks] = useState<Desk[]>([]);
  const [activeDesk, setActiveDesk] = useState<Desk | null>(null);

  // Basket view state (primary interface)
  const [selectedBasket, setSelectedBasket] = useState<MivState>("IN");
  const [selectedMiv, setSelectedMiv] = useState<ConversationMiv | null>(null);
  const [basketRefreshKey, setBasketRefreshKey] = useState<number>(0);

  // Basket counts
  const [basketCounts, setBasketCounts] = useState<{
    inbox: number;
    pending: number;
    sent: number;
    archived: number;
  }>({ inbox: 0, pending: 0, sent: 0, archived: 0 });

  // Conversation view state (supplementary)
  const [conversations, setConversations] = useState<ConversationWithLatest[]>(
    []
  );
  const [selectedConversation, setSelectedConversation] =
    useState<GetConversationResponse | null>(null);
  const [currentView, setCurrentView] = useState<View>("baskets");

  // Notification state
  const [notifications, setNotifications] = useState<Notification[]>([]);
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const [unreadCount, setUnreadCount] = useState(0);

  // Toast state
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);

  // Resubmit state - for pre-populating ComposeMiv with rejected via routing message
  const [resubmitMiv, setResubmitMiv] = useState<ConversationMiv | null>(null);

  // Native notifications state
  const localNotificationsReadyRef = useRef(false);
  const notificationsSnapshotInitializedRef = useRef(false);
  const knownInboxMivIdsRef = useRef<Set<string>>(new Set());

  const initializeLocalNotifications = useCallback(async () => {
    if (!isNativePlatform) return;

    try {
      const permissionStatus = await LocalNotifications.checkPermissions();
      let displayPermission = permissionStatus.display;

      if (displayPermission !== "granted") {
        const requested = await LocalNotifications.requestPermissions();
        displayPermission = requested.display;
      }

      if (displayPermission !== "granted") {
        console.warn("Local notifications permission was not granted");
        return;
      }

      // Android notification channel (ignored on iOS/web)
      await LocalNotifications.createChannel({
        id: "inbox-mivs",
        name: "Inbox Messages",
        description: "Notifications for new inbox MIVs",
        importance: 5,
        visibility: 1,
      });

      localNotificationsReadyRef.current = true;
    } catch (error) {
      console.error("Failed to initialize local notifications:", error);
    }
  }, [isNativePlatform]);

  // Add listeners for notification events (tap/receive)
  useEffect(() => {
    if (!isNativePlatform) return;

    let actionHandle: any = null;
    let receiveHandle: any = null;

    LocalNotifications.addListener(
      "localNotificationActionPerformed",
      async (notification) => {
        try {
          const payload = (notification as any).notification?.extra;
          if (payload?.conversationId && activeDesk) {
            const resp = await api.getConversation(payload.conversationId, activeDesk.id);
            setSelectedConversation(resp);
            setCurrentView("conversations");
          }
        } catch (err) {
          console.error("Failed handling notification action:", err);
        }
      }
    )
      .then((h) => {
        actionHandle = h;
      })
      .catch((e) => console.warn("addListener failed:", e));

    LocalNotifications.addListener(
      "localNotificationReceived",
      (notification) => {
        const title = (notification as any).notification?.title;
        const body = (notification as any).notification?.body;
        setToastMessage(`${title}: ${body}`);
      }
    )
      .then((h) => {
        receiveHandle = h;
      })
      .catch((e) => console.warn("addListener failed:", e));

    return () => {
      try {
        actionHandle?.remove?.();
        receiveHandle?.remove?.();
      } catch (e) {
        // ignore
      }
    };
  }, [isNativePlatform, activeDesk]);

  const notifyForNewInboxMivs = useCallback(async (
    latestConversations: ConversationWithLatest[] | undefined,
    deskId: string
  ) => {
    if (!latestConversations || !Array.isArray(latestConversations)) return;

    const latestInboxMivs = latestConversations
      .map((conversation) => conversation.latest_miv)
      .filter((miv): miv is ConversationMiv => Boolean(miv))
      .filter((miv) => {
        if (miv.deleted || miv.is_forgotten) return false;
        if (miv.from === deskId) return false;
        return miv.state === "IN" || miv.state === "CC";
      });

    const currentInboxMivIds = new Set(latestInboxMivs.map((miv) => miv.id));

    // Prime initial snapshot so we don't fire on existing unread messages at startup
    if (!notificationsSnapshotInitializedRef.current) {
      knownInboxMivIdsRef.current = currentInboxMivIds;
      notificationsSnapshotInitializedRef.current = true;
      return;
    }

    const newUnreadMivs = latestInboxMivs.filter(
      (miv) => !knownInboxMivIdsRef.current.has(miv.id)
    );

    knownInboxMivIdsRef.current = currentInboxMivIds;

    if (newUnreadMivs.length === 0) return;

    // If native local notifications are available, show system notifications.
    // Otherwise, fall back to toast in web runtime.
    if (isNativePlatform && localNotificationsReadyRef.current) {
      const now = Date.now();
      const notificationsToSchedule = newUnreadMivs.slice(0, 5).map((item, index) => ({
        id: Number(String(now + index).slice(-9)),
        title: "New Inbox Message",
        body: item.subject || `New message from ${item.from}`,
        schedule: { at: new Date(now + 300 + index * 120) },
        channelId: "inbox-mivs",
        extra: {
          mivId: item.id,
          conversationId: item.conversation_id,
          type: item.type,
        },
      }));

      try {
        await LocalNotifications.schedule({ notifications: notificationsToSchedule });
      } catch (error) {
        console.error("Failed to schedule local notifications:", error);
      }
    } else {
      const latest = newUnreadMivs[newUnreadMivs.length - 1];
      setToastMessage(`New inbox message: ${latest.subject}`);
    }
  }, [isNativePlatform]);

  // Load saved session on mount
  useEffect(() => {
    const savedAccount = localStorage.getItem("account");
    const savedToken = localStorage.getItem("token");

    if (savedAccount && savedToken) {
      try {
        const acc = JSON.parse(savedAccount);
        setAccount(acc);
        setToken(savedToken);
      } catch (e) {
        localStorage.removeItem("account");
        localStorage.removeItem("token");
      }
    }
    setLoading(false);
  }, []);

  // Initialize native local notifications once
  useEffect(() => {
    initializeLocalNotifications();
  }, [initializeLocalNotifications]);

  // Load desks when account is set
  useEffect(() => {
    const loadDesks = async () => {
      if (!account) return;

      try {
        const deskList = await api.listDesks(account.id);
        setDesks(deskList);

        if (deskList.length > 0 && !activeDesk) {
          const activeDeskId = account.active_desk || deskList[0].id;
          const desk =
            deskList.find((d) => d.id === activeDeskId) || deskList[0];
          setActiveDesk(desk);
        }
      } catch (err: any) {
        console.error("Failed to load desks:", err);
        // If there's an authentication error, clear the session
        if (
          err.message &&
          (err.message.includes("401") ||
            err.message.includes("Unauthorized") ||
            err.message.includes("not found"))
        ) {
          alert("Your session is no longer valid. Please sign in again.");
          handleLogout();
        }
      }
    };

    if (account) {
      loadDesks();
    }
  }, [account, activeDesk]);

  // If desks exist but sessionStorage lacks private keys, attempt to restore from persisted encrypted keys
  useEffect(() => {
    const tryRestoreKeys = async () => {
      if (!desks || desks.length === 0) return;
      // Check if any desk already has a private key in sessionStorage
      const { getPrivateKey } = await import("./utils/crypto");

      let missing = false;
      for (const d of desks) {
        if (!getPrivateKey(d.id)) {
          missing = true;
          break;
        }
      }

      if (!missing) return;

      const enc = localStorage.getItem("encrypted_priv_keys");
      if (!enc) return;

      let parsed: Record<string, string>;
      try {
        parsed = JSON.parse(enc);
      } catch (e) {
        console.warn("Failed to parse encrypted_priv_keys from localStorage", e);
        return;
      }

      // Instead of using prompt (which may be unsupported in native/webview), open modal
      setEncryptedKeysPayload(parsed);
      setShowUnlockModal(true);
    };

    tryRestoreKeys();
  }, [desks]);

  const [showUnlockModal, setShowUnlockModal] = React.useState(false);
  const [encryptedKeysPayload, setEncryptedKeysPayload] = React.useState<
    Record<string, string> | null
  >(null);

  const handleUnlockWithPassword = async (password: string) => {
    if (!encryptedKeysPayload) return false;
    try {
      const { decryptPrivateKey, storePrivateKey } = await import(
        "./utils/crypto"
      );
      for (const [deskId, encryptedKey] of Object.entries(encryptedKeysPayload)) {
        const decryptedKey = decryptPrivateKey(encryptedKey, password);
        storePrivateKey(deskId, decryptedKey);
      }
      setShowUnlockModal(false);
      setEncryptedKeysPayload(null);
      setToastMessage("Encryption keys unlocked");
      return true;
    } catch (err) {
      console.error("Failed to decrypt persisted keys:", err);
      return false;
    }
  };

  // Load conversations and notifications when active desk changes
  useEffect(() => {
    const loadData = async () => {
      if (!activeDesk) return;

      try {
        const [convResponse, notifResponse, contactsResponse] =
          await Promise.all([
            api.listConversations(activeDesk.id),
            api.listNotifications(activeDesk.id, false),
            api.listContacts(activeDesk.id),
          ]);
        setConversations(convResponse.conversations || []);
        setNotifications(notifResponse.notifications || []);
        setUnreadCount(notifResponse.unread_count);
        setContacts(contactsResponse.contacts || []);

        await notifyForNewInboxMivs(convResponse.conversations, activeDesk.id);

        // Calculate basket counts
        await calculateBasketCounts(convResponse.conversations, activeDesk.id);
      } catch (err: any) {
        console.error("Failed to load data:", err);
        // If there's an authentication error, clear the session
        if (
          err.message &&
          (err.message.includes("401") || err.message.includes("Unauthorized"))
        ) {
          alert("Your session is no longer valid. Please sign in again.");
          handleLogout();
        }
      }

                setBasketRefreshKey((prev) => prev + 1);
    };

    if (activeDesk) {
      loadData();

      // Poll for updates every 10 seconds
      const interval = setInterval(() => {
        loadData();
      }, 10000);

      return () => clearInterval(interval);
    }
  }, [activeDesk, notifyForNewInboxMivs]);

  const calculateBasketCounts = async (
    convs: ConversationWithLatest[],
    deskId: string
  ) => {
    let inboxCount = 0;
    let pendingCount = 0;
    let sentCount = 0;
    let archivedCount = 0;

    // Handle case where convs might be null or undefined
    if (!convs || !Array.isArray(convs)) {
      setBasketCounts({
        inbox: 0,
        pending: 0,
        sent: 0,
        archived: 0,
      });
      return;
    }

    for (const conv of convs) {
      try {
        // Pass deskId to get miv states from user's perspective
        const fullConv = await api.getConversation(
          conv.conversation.id,
          deskId
        );

        for (const miv of fullConv.mivs) {
          // Skip forgotten mivs
          if (miv.is_forgotten) continue;

          // Skip deleted mivs (only affects ACKs)
          if (miv.deleted) continue;

          // For archived conversations, count messages in IN and PENDING baskets
          if (conv.conversation.is_archived) {
            // Count any messages in IN or PENDING basket even if conversation is archived
            if (miv.state === "IN") {
              inboxCount++;
            } else if (miv.state === "PENDING") {
              pendingCount++;
            }
            // Count all mivs for archived total
            archivedCount++;
          } else {
            // Count based on miv state from backend for active conversations
            if (miv.state === "IN" || miv.state === "CC") {
              inboxCount++;
            } else if (miv.state === "PENDING") {
              pendingCount++;
            } else if (
              miv.state === "SENT" &&
              !miv.is_ack &&
              miv.type !== "VIA"
            ) {
              // Exclude ACK mivs and VIA mivs from SENT basket count (they don't expect replies)
              sentCount++;
            }
          }
        }
      } catch (err) {
        console.error("Failed to load conversation for counting:", err);
      }
    }

    setBasketCounts({
      inbox: inboxCount,
      pending: pendingCount,
      sent: sentCount,
      archived: archivedCount,
    });
  };

  const refreshConversations = async () => {
    if (!activeDesk) return;
    try {
      const response = await api.listConversations(activeDesk.id);
      setConversations(response.conversations || []);
    } catch (err) {
      console.error("Failed to refresh conversations:", err);
    }
  };

  const refreshNotifications = async () => {
    if (!activeDesk) return;
    try {
      const response = await api.listNotifications(activeDesk.id, false);
      setNotifications(response.notifications || []);
      setUnreadCount(response.unread_count);
    } catch (err) {
      console.error("Failed to refresh notifications:", err);
    }
  };

  const handleLogin = async (username: string, password: string) => {
    const response = await api.login({ username, password });
    setAccount(response.account);
    setToken(response.token);
    localStorage.setItem("account", JSON.stringify(response.account));
    localStorage.setItem("token", response.token);

    // Decrypt and store private keys in sessionStorage for E2E encryption
    if (response.encrypted_priv_keys) {
      const { decryptPrivateKey, storePrivateKey } = await import(
        "./utils/crypto"
      );

      // ...removed debug log...

      for (const [deskId, encryptedKey] of Object.entries(
        response.encrypted_priv_keys
      )) {
        try {
          const decryptedKey = decryptPrivateKey(encryptedKey, password);
          storePrivateKey(deskId, decryptedKey);
          // ...removed debug log...
        } catch (err) {
          console.error(
            `❌ Failed to decrypt private key for desk ${deskId}:`,
            err
          );
        }
      }
      // Persist encrypted keys so session can be restored across browser restarts
      try {
        localStorage.setItem(
          "encrypted_priv_keys",
          JSON.stringify(response.encrypted_priv_keys)
        );
      } catch (e) {
        console.warn("Failed to persist encrypted_priv_keys to localStorage", e);
      }
    } else {
      console.warn("⚠️ No encrypted_priv_keys in login response");
    }
  };

  const handleRegister = async (request: RegisterRequest) => {
    const response = await api.register(request);
    // Registration successful - show success message
    // User needs to login manually now
    alert(response.message || "Registration successful! Please login.");
    // Don't set account/token - user must login
  };

  const handleLogout = () => {
    // Clear authentication state
    setAccount(null);
    setToken(null);

    // Clear ALL encryption keys from sessionStorage
    const keysToRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith("privateKey_")) {
        keysToRemove.push(key);
      }
    }
    keysToRemove.forEach((key) => sessionStorage.removeItem(key));
    // ...removed debug log...

    // Clear desk state
    setDesks([]);
    setActiveDesk(null);

    // Clear basket view state
    setSelectedBasket("IN");
    setSelectedMiv(null);
    setBasketRefreshKey(0);

    // Clear basket counts
    // Remove persisted encrypted private keys
    localStorage.removeItem("encrypted_priv_keys");
    setBasketCounts({ inbox: 0, pending: 0, sent: 0, archived: 0 });

    // Clear conversation view state
    setConversations([]);
    setSelectedConversation(null);
    setCurrentView("baskets");

    // Clear notification state
    setNotifications([]);
    setUnreadCount(0);

    // Clear other state
    setToastMessage(null);
    setContacts([]);
    setResubmitMiv(null);
    setMobileMenuOpen(false);

    notificationsSnapshotInitializedRef.current = false;
    knownInboxMivIdsRef.current = new Set();

    // Clear local storage
    localStorage.removeItem("account");
    localStorage.removeItem("token");

    // Clear private keys from sessionStorage (E2E encryption)
    import("./utils/crypto").then(({ clearAllPrivateKeys }) => {
      clearAllPrivateKeys();
    });
  };

  const handleCreateDesk = async (name: string) => {
    if (!account) return;

    try {
      const newDesk = await api.createDesk(account.id, { name });
      setDesks([...desks, newDesk]);
    } catch (err) {
      console.error("Failed to create desk:", err);
    }
  };

  const handleSwitchDesk = async (deskId: string) => {
    if (!account) return;

    try {
      const updatedAccount = await api.switchDesk(account.id, {
        desk_id: deskId,
      });
      setAccount(updatedAccount);
      localStorage.setItem("account", JSON.stringify(updatedAccount));

      const desk = desks.find((d) => d.id === deskId);
      if (desk) {
        setActiveDesk(desk);
        setSelectedConversation(null);
      }
    } catch (err) {
      console.error("Failed to switch desk:", err);
    }
  };

  const handleMivClick = async (miv: ConversationMiv) => {
    // Check if we're switching from one inbox miv to another
    const isPreviousMivInInbox =
      selectedMiv &&
      selectedMiv.state === "IN" &&
      selectedMiv.arrow_to === activeDesk?.id &&
      !selectedMiv.read_at;
    const isClickingDifferentMiv = selectedMiv && selectedMiv.id !== miv.id;

    // If switching from one inbox miv to another, mark previous as read
    if (isPreviousMivInInbox && isClickingDifferentMiv && activeDesk) {
      try {
        await api.markMivAsRead(selectedMiv.id, activeDesk.id);

        // Get sender name for toast
        const getSenderName = (deskId: string): string => {
          const contact = contacts.find((c) => c.desk_id_ref === deskId);
          if (contact) return contact.name;
          // Format as phone number
          if (deskId.length === 10) {
            return `${deskId.slice(0, 4)}-${deskId.slice(4, 6)}-${deskId.slice(
              6
            )}`;
          }
          return deskId;
        };

        const senderName = getSenderName(selectedMiv.from);
        setToastMessage(`Moved Miv from ${senderName} to Pending`);

        // Refresh basket counts and list after a short delay to ensure backend is updated
        setTimeout(async () => {
          setBasketRefreshKey((prev) => prev + 1);
          const response = await api.listConversations(activeDesk.id);
          await calculateBasketCounts(response.conversations, activeDesk.id);
        }, 100);
      } catch (err) {
        console.error("Failed to mark previous miv as read:", err);
      }
    }

    // Set the newly selected miv
    setSelectedMiv(miv);

    // When clicking a miv in a basket, automatically mark it as read if it's incoming and unread
    if (miv.state === "IN" && miv.arrow_to === activeDesk?.id && !miv.read_at) {
      try {
        await api.markMivAsRead(miv.id, activeDesk.id);
        // Update the selected miv with read status
        const updatedMiv = {
          ...miv,
          read_at: new Date().toISOString(),
          state: "PENDING" as MivState,
        };
        setSelectedMiv(updatedMiv);

        // Show toast notification
        const getSenderName = (deskId: string): string => {
          const contact = contacts.find((c) => c.desk_id_ref === deskId);
          if (contact) return contact.name;
          // Format as phone number
          if (deskId.length === 10) {
            return `${deskId.slice(0, 4)}-${deskId.slice(4, 6)}-${deskId.slice(
              6
            )}`;
          }
          return deskId;
        };

        const senderName = getSenderName(miv.from);
        setToastMessage(`Moved Miv from ${senderName} to Pending`);

        // Refresh basket counts and list after a short delay to ensure backend is updated
        setTimeout(async () => {
          setBasketRefreshKey((prev) => prev + 1);
          const response = await api.listConversations(activeDesk.id);
          await calculateBasketCounts(response.conversations, activeDesk.id);
        }, 100);
      } catch (err) {
        console.error("Failed to mark miv as read:", err);
      }
    }
  };

  const handleMivReply = async (body: string, isAck: boolean = false) => {
    if (!activeDesk || !selectedMiv) return;

    try {
      // Get sender's private key for encryption
      const { getPrivateKey, encryptMessage } = await import("./utils/crypto");
      const senderPrivateKey = getPrivateKey(activeDesk.id);

      if (!senderPrivateKey) {
        throw new Error("Private key not found. Please log in again.");
      }

      // Determine recipient (the person we're replying to)
      // For via routing: reply to the person who forwarded to you
      // For direct messages: reply to the sender
      let recipientId: string;
      if (selectedMiv.via && selectedMiv.via.length > 0) {
        // This message went through via routing
        // Find current user's position in the chain
        const myPosition = selectedMiv.via.indexOf(activeDesk.id);
        if (myPosition > 0) {
          // Current user is not the first via recipient
          // Reply to the previous via recipient who forwarded to me
          recipientId = selectedMiv.via[myPosition - 1];
        } else if (myPosition === -1 && activeDesk.id === selectedMiv.to) {
          // Current user is the final recipient (not in via chain)
          // Reply to the last via recipient who forwarded to me
          recipientId = selectedMiv.via[selectedMiv.via.length - 1];
        } else {
          // Current user is the first via recipient
          // Reply to the original sender
          recipientId =
            selectedMiv.from === activeDesk.id
              ? selectedMiv.to
              : selectedMiv.from;
        }
      } else {
        // Direct message, no via routing
        recipientId =
          selectedMiv.from === activeDesk.id
            ? selectedMiv.to
            : selectedMiv.from;
      }

      // Fetch sender's public key (for encrypting their own copy)
      const senderPublicKeyResponse = await api.getDeskPublicKey(activeDesk.id);
      const senderPublicKey = senderPublicKeyResponse.public_key;

      // Fetch recipient's public key
      const recipientPublicKeyResponse = await api.getDeskPublicKey(
        recipientId
      );
      const recipientPublicKey = recipientPublicKeyResponse.public_key;

      // Encrypt TWO copies:
      // 1. Sender's copy: encrypted with sender's keys
      const senderEncryptedBody = encryptMessage(
        body,
        senderPublicKey,
        senderPrivateKey
      );

      // 2. Recipient's copy: encrypted with recipient's public key
      const recipientEncryptedBody = encryptMessage(
        body,
        recipientPublicKey,
        senderPrivateKey
      );

      // Handle CCs: encrypt for each CC recipient if present
      let ccBodies: { [deskId: string]: string } | undefined = undefined;
      if (selectedMiv.cc && selectedMiv.cc.length > 0) {
        ccBodies = {};
        // Fetch all CC public keys in parallel
        const ccPublicKeys = await Promise.all(
          selectedMiv.cc.map(async (ccId) => {
            const res = await api.getDeskPublicKey(ccId);
            return { ccId, publicKey: res.public_key };
          })
        );
        for (const { ccId, publicKey } of ccPublicKeys) {
          // Encrypt the reply/ACK for each CC recipient
          ccBodies[ccId] = encryptMessage(body, publicKey, senderPrivateKey);
        }
      }

      await api.replyToConversation(
        selectedMiv.conversation_id,
        activeDesk.id,
        {
          sender_body: senderEncryptedBody, // Sender's encrypted copy
          recipient_body: recipientEncryptedBody, // Recipient's encrypted copy
          is_ack: isAck,
          font_family: activeDesk.font_family,
          font_size: activeDesk.font_size,
          cc_bodies: ccBodies,
        }
      );

      // Clear the selected miv immediately to remove it from view
      setSelectedMiv(null);

      // Refresh conversations to update basket counts and lists
      await refreshConversations();

      // Recalculate basket counts
      const response = await api.listConversations(activeDesk.id);
      await calculateBasketCounts(response.conversations, activeDesk.id);

      // Force basket view to refresh
      setBasketRefreshKey((prev) => prev + 1);
    } catch (err) {
      console.error("Failed to reply:", err);
    }
  };

  const handleMivForget = async () => {
    if (!activeDesk) return;

    try {
      // Clear the selected miv immediately to remove it from view
      setSelectedMiv(null);

      // Refresh conversations to update basket counts and lists
      await refreshConversations();

      // Recalculate basket counts
      const response = await api.listConversations(activeDesk.id);
      await calculateBasketCounts(response.conversations, activeDesk.id);

      // Force basket view to refresh
      setBasketRefreshKey((prev) => prev + 1);
    } catch (err) {
      console.error("Failed to forget miv:", err);
    }
  };

  const handleBackToBasket = async () => {
    // Clear the selected miv to return to basket view
    setSelectedMiv(null);

    // Refresh the basket to reflect any state changes (e.g., IN -> PENDING)
    if (activeDesk) {
      setBasketRefreshKey((prev) => prev + 1);
      const response = await api.listConversations(activeDesk.id);
      await calculateBasketCounts(response.conversations, activeDesk.id);
    }
  };

  const handleConversationClick = async (conv: ConversationWithLatest) => {
    try {
      // Pass desk_id to automatically mark messages as read
      const response = await api.getConversation(
        conv.conversation.id,
        activeDesk?.id
      );
      setSelectedConversation(response);
      setCurrentView("conversations");
    } catch (err) {
      console.error("Failed to load conversation:", err);
    }
  };

  const handleSendConversation = async (request: CreateMivRequest) => {
    if (!activeDesk) return;

    try {
      // Convert CreateMivRequest to CreateConversationRequest
      const conversationRequest = {
        to: request.to,
        cc: request.cc,
        via: request.via,
        subject: request.subject,
        sender_body: request.sender_body,
        recipient_body: request.recipient_body,
        cc_bodies: request.cc_bodies, // Include CC-specific encrypted bodies
        attachment_ids: request.attachment_ids,
        font_family: request.font_family,
        font_size: request.font_size,
        line_height: request.line_height,
      };

      await api.createConversation(activeDesk.id, conversationRequest);

      // Clear resubmit state after successful send
      setResubmitMiv(null);

      // Redirect to inbox instead of conversations screen
      setSelectedBasket("IN");
      setCurrentView("baskets");
      setSelectedMiv(null);

      // Refresh conversations and basket counts
      await refreshConversations();
      const convResponse = await api.listConversations(activeDesk.id);
      await calculateBasketCounts(convResponse.conversations, activeDesk.id);

      // Force basket view to refresh
      setBasketRefreshKey((prev) => prev + 1);
    } catch (err) {
      console.error("Failed to create conversation:", err);
      throw err;
    }
  };

  const handleDeleteCc = async (conversationId: string) => {
    if (!activeDesk) return;

    try {
      await api.deleteCcMiv(conversationId, activeDesk.id);

      // Refresh the conversation list to hide this CC
      await refreshConversations();
      setSelectedMiv(null);
      setCurrentView("baskets");

      alert("CC removed from your view.");
    } catch (err) {
      console.error("Failed to delete CC:", err);
      alert("Failed to remove CC. Please try again.");
    }
  };

  const handleResubmit = (miv: ConversationMiv) => {
    // Store the MIV for resubmission
    setResubmitMiv(miv);
    // Switch to compose view
    setCurrentView("compose");
    // Navigate back to see the compose view
    setSelectedMiv(null);
  };

  const handleNotificationClick = async (notification: Notification) => {
    if (notification.conversation_id) {
      try {
        // Pass desk_id to automatically mark messages as read
        const response = await api.getConversation(
          notification.conversation_id,
          activeDesk?.id
        );
        setSelectedConversation(response);
        setCurrentView("conversations");

        if (!notification.read) {
          await api.markNotificationAsRead(notification.id);
          await refreshNotifications();
        }
      } catch (err) {
        console.error("Failed to load conversation from notification:", err);
      }
    }
  };

  const handleMarkNotificationAsRead = async (notificationId: string) => {
    try {
      await api.markNotificationAsRead(notificationId);
      await refreshNotifications();
    } catch (err) {
      console.error("Failed to mark notification as read:", err);
    }
  };

  const handleDeskUpdated = (updatedDesk: Desk) => {
    // Update active desk with new settings
    setActiveDesk(updatedDesk);

    // Update desks list
    setDesks(desks.map((d) => (d.id === updatedDesk.id ? updatedDesk : d)));
  };

  if (loading) {
    return (
      <div className="app loading">
        <div>Loading...</div>
      </div>
    );
  }

  if (!account || !token) {
    return <Auth onLogin={handleLogin} onRegister={handleRegister} />;
  }

  if (!activeDesk) {
    return (
      <div className="app loading">
        <div>Loading desk...</div>
      </div>
    );
  }

  const normalizeRole = (role?: string | null) => (role || "").trim().toLowerCase();

  let storedRole = "";
  try {
    const stored = localStorage.getItem("account");
    if (stored) {
      const parsed = JSON.parse(stored) as { role?: string };
      storedRole = normalizeRole(parsed.role);
    }
  } catch {
    storedRole = "";
  }

  const effectiveRole = normalizeRole(account.role) || storedRole;
  const isAdmin = effectiveRole === "admin";

  return (
    <div className="app">
      <div className="sidebar">
        <div className="sidebar-header">
          <button
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            <span aria-hidden="true">☰</span>
            <span className="mobile-btn-label">Menu</span>
          </button>
          <h1>Zcomm</h1>
          <div className="mobile-header-actions">
            {selectedMiv && (
              <button
                className="mobile-back-btn"
                onClick={() => setSelectedMiv(null)}
                aria-label="Back to basket"
              >
                <span aria-hidden="true">←</span>
                <span className="mobile-btn-label">Back</span>
              </button>
            )}
            {currentView !== "compose" && (
              <button
                className="mobile-compose-btn"
                onClick={() => {
                  setResubmitMiv(null);
                  setCurrentView("compose");
                }}
                aria-label="Compose new message"
              >
                <span aria-hidden="true">✏️</span>
                <span className="mobile-btn-label">Compose</span>
              </button>
            )}
          </div>
          <div className="user-info">
            <div className="user-name">{account.display_name}</div>
            <div className="user-username">@{account.username}</div>
            <div className="user-role">Role: {effectiveRole || "unknown"}</div>
          </div>
        </div>

        {/* Desk switching moved into the mobile/side menu to simplify top header */}

        <button
          onClick={() => {
            setResubmitMiv(null);
            setCurrentView("compose");
            setSelectedMiv(null);
          }}
          className="compose-btn"
        >
          + New Conversation
        </button>

        <nav className={`nav-menu ${mobileMenuOpen ? "open" : ""}`}>
          <div className="nav-section">
            <h4>Desks</h4>
            <DeskSwitcher
              desks={desks}
              activeDeskId={activeDesk.id}
              onSwitchDesk={(id) => {
                handleSwitchDesk(id);
                setMobileMenuOpen(false);
              }}
              onCreateDesk={(name) => {
                handleCreateDesk(name);
                setMobileMenuOpen(false);
              }}
            />
          </div>
          <div className="nav-section">
            <h4>Baskets</h4>
            <button
              className={
                currentView === "baskets" && selectedBasket === "IN"
                  ? "active"
                  : ""
              }
              onClick={() => {
                setCurrentView("baskets");
                setSelectedBasket("IN");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              📥 Inbox
              <span className="count-badge">{basketCounts.inbox}</span>
            </button>
            <button
              className={
                currentView === "baskets" && selectedBasket === "PENDING"
                  ? "active"
                  : ""
              }
              onClick={() => {
                setCurrentView("baskets");
                setSelectedBasket("PENDING");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              ⏳ Pending
              <span className="count-badge">{basketCounts.pending}</span>
            </button>
            <button
              className={
                currentView === "baskets" && selectedBasket === "SENT"
                  ? "active"
                  : ""
              }
              onClick={() => {
                setCurrentView("baskets");
                setSelectedBasket("SENT");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              📤 Sent
              <span className="count-badge">{basketCounts.sent}</span>
            </button>
          </div>

          <div className="nav-section">
            <h4>Other</h4>
            <button
              className={currentView === "conversations" ? "active" : ""}
              onClick={() => {
                setCurrentView("conversations");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              💬 Conversations
            </button>
            <button
              className={
                currentView === "baskets" && selectedBasket === "ARCHIVED"
                  ? "active"
                  : ""
              }
              onClick={() => {
                setCurrentView("baskets");
                setSelectedBasket("ARCHIVED");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              📁 Archived
            </button>
            <button
              className={currentView === "contacts" ? "active" : ""}
              onClick={() => {
                setCurrentView("contacts");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              👥 Contacts
            </button>
            {/* Notifications sidebar button is temporarily hidden until the feature is fixed
            <button
              className={currentView === "notifications" ? "active" : ""}
              onClick={() => {
                setCurrentView("notifications");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              🔔 Notifications
              {unreadCount > 0 && <span className="badge">{unreadCount}</span>}
            </button>
            */}
          </div>

          <div className="nav-section">
            <h4>Account</h4>
            {isAdmin && (
              <button
                className={currentView === "admin" ? "active" : ""}
                onClick={() => {
                  setCurrentView("admin");
                  setSelectedMiv(null);
                  setMobileMenuOpen(false);
                }}
              >
                🛠️ Admin
              </button>
            )}
            <button
              className={currentView === "settings" ? "active" : ""}
              onClick={() => {
                setCurrentView("settings");
                setSelectedMiv(null);
                setMobileMenuOpen(false);
              }}
            >
              ⚙️ Settings
            </button>
            <button
              onClick={() => {
                handleLogout();
                setMobileMenuOpen(false);
              }}
            >
              🚪 Sign Out
            </button>
          </div>
        </nav>

        <div className="sidebar-footer">
          <button
            onClick={() => {
              setCurrentView("settings");
              setSelectedMiv(null);
            }}
            className="btn-settings"
            title="Settings"
          >
            ⚙️ Settings
          </button>
          <button onClick={handleLogout} className="btn-logout">
            Sign Out
          </button>
        </div>
      </div>

      {/* Mobile overlay */}
      <div
        className={`mobile-overlay ${mobileMenuOpen ? "open" : ""}`}
        onClick={() => setMobileMenuOpen(false)}
      ></div>

      <div className="main-content">
        {currentView === "admin" && isAdmin ? (
          <AdminPanel currentAccountId={account.id} />
        ) : currentView === "settings" ? (
          <Settings
            desk={activeDesk}
            onClose={() => setCurrentView("baskets")}
            onDeskUpdated={handleDeskUpdated}
          />
        ) : currentView === "compose" ? (
          <ComposeMiv
            onSend={handleSendConversation}
            onCancel={() => {
              setResubmitMiv(null);
              setCurrentView("baskets");
            }}
            deskId={activeDesk.id}
            desk={activeDesk}
            resubmitMiv={resubmitMiv}
          />
        ) : currentView === "notifications" ? (
          <div className="notifications-view">
            <NotificationPanel
              notifications={notifications}
              onNotificationClick={handleNotificationClick}
              onMarkAsRead={handleMarkNotificationAsRead}
            />
          </div>
        ) : currentView === "contacts" ? (
          <ContactManager deskId={activeDesk.id} />
        ) : currentView === "baskets" ? (
          <>
            <div
              className={`basket-list-container ${
                selectedMiv ? "mobile-hidden" : ""
              }`}
            >
              <BasketView
                deskId={activeDesk.id}
                selectedBasket={selectedBasket}
                onMivClick={handleMivClick}
                selectedMivId={selectedMiv?.id}
                onBasketChange={setSelectedBasket}
                onNavigateToConversations={() => setCurrentView("conversations")}
                refreshToken={basketRefreshKey}
              />
            </div>
            {selectedMiv ? (
              <div className="basket-detail-container mobile-fullscreen">
                <MivDetailWithContext
                  miv={selectedMiv}
                  currentDeskId={activeDesk.id}
                  currentDesk={activeDesk}
                  onReply={handleMivReply}
                  onForget={handleMivForget}
                  onDeleteCc={handleDeleteCc}
                  onBack={handleBackToBasket}
                  onResubmit={handleResubmit}
                  isArchived={selectedBasket === "ARCHIVED"}
                />
              </div>
            ) : null}
          </>
        ) : (
          <>
            <div
              className={`basket-list-container ${
                selectedMiv || selectedConversation ? "mobile-hidden" : ""
              }`}
            >
              <ConversationList
                conversations={conversations.filter(
                  (conv) => !conv.conversation.is_archived
                )}
                selectedConversationId={selectedConversation?.conversation.id}
                onConversationClick={handleConversationClick}
                currentDeskId={activeDesk.id}
                onMivClick={handleMivClick}
                selectedMivId={selectedMiv?.id}
              />
            </div>

            {/* Only render the detail panel when a conversation or miv is selected so
                the conversation list can fill the available space when nothing is open */}
            {(selectedMiv || selectedConversation) && (
              <div className={`basket-detail-container mobile-fullscreen`}>
                {selectedMiv ? (
                  <MivDetailWithContext
                    miv={selectedMiv}
                    currentDeskId={activeDesk.id}
                    currentDesk={activeDesk}
                    onReply={handleMivReply}
                    onForget={handleMivForget}
                    onDeleteCc={handleDeleteCc}
                    onBack={handleBackToBasket}
                    onResubmit={handleResubmit}
                    isArchived={false}
                  />
                ) : selectedConversation ? (
                  // When a conversation thread is selected, show its latest miv in the detail
                  (() => {
                    const latest =
                      selectedConversation.mivs &&
                      selectedConversation.mivs.length > 0
                        ? selectedConversation.mivs[
                            selectedConversation.mivs.length - 1
                          ]
                        : null;
                    return latest ? (
                      <MivDetailWithContext
                        miv={latest}
                        currentDeskId={activeDesk.id}
                        currentDesk={activeDesk}
                        onReply={handleMivReply}
                        onForget={handleMivForget}
                        onDeleteCc={handleDeleteCc}
                        onBack={() => {
                          setSelectedConversation(null);
                          setCurrentView("conversations");
                        }}
                        onResubmit={handleResubmit}
                        isArchived={false}
                      />
                    ) : (
                      <div className="empty-selection">
                        <p>Select a message to view</p>
                      </div>
                    );
                  })()
                ) : null}
              </div>
            )}
          </>
        )}
      </div>
      {toastMessage && (
        <Toast message={toastMessage} onClose={() => setToastMessage(null)} />
      )}
      {showUnlockModal && encryptedKeysPayload && (
        <UnlockKeysModal
          encryptedKeys={encryptedKeysPayload}
          accountLabel={
            account
              ? `${account.display_name || account.username} (@${account.username})`
              : undefined
          }
          onUnlock={handleUnlockWithPassword}
          onCancel={() => {
            setShowUnlockModal(false);
            setEncryptedKeysPayload(null);
          }}
        />
      )}
    </div>
  );
}

export default App;
