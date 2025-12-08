import React, { useState, useEffect } from "react";
import Auth from "./components/Auth";
import DeskSwitcher from "./components/DeskSwitcher";
import ConversationList from "./components/ConversationList";
import ConversationThread from "./components/ConversationThread";
import BasketView from "./components/BasketView";
import MivDetailWithContext from "./components/MivDetailWithContext";
import NotificationPanel from "./components/NotificationPanel";
import ComposeMiv from "./components/ComposeMiv";
import ContactManager from "./components/ContactManager";
import Settings from "./components/Settings";
import Toast from "./components/Toast";
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

type View =
  | "baskets"
  | "conversations"
  | "compose"
  | "notifications"
  | "contacts"
  | "settings";

function App() {
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
  const [unreadCount, setUnreadCount] = useState(0);

  // Toast state
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [contacts, setContacts] = useState<Contact[]>([]);

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
    };

    if (activeDesk) {
      loadData();

      // Poll for updates every 10 seconds
      const interval = setInterval(() => {
        loadData();
      }, 10000);

      return () => clearInterval(interval);
    }
  }, [activeDesk]);

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
          
          // Count based on miv state from backend
          if (!conv.conversation.is_archived) {
            if (miv.state === "IN" || miv.state === "CC") {
              inboxCount++;
            } else if (miv.state === "PENDING") {
              pendingCount++;
            } else if (miv.state === "SENT" && !miv.is_ack) {
              // Exclude ACK mivs from SENT basket count (they don't expect replies)
              sentCount++;
            }
          }

          // Archived: all messages in archived conversations
          if (conv.conversation.is_archived) {
            archivedCount++;
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
  };

  const handleRegister = async (request: RegisterRequest) => {
    const response = await api.register(request);
    setAccount(response.account);
    setToken(response.token);
    localStorage.setItem("account", JSON.stringify(response.account));
    localStorage.setItem("token", response.token);
  };

  const handleLogout = () => {
    setAccount(null);
    setToken(null);
    setDesks([]);
    setActiveDesk(null);
    setConversations([]);
    setNotifications([]);
    localStorage.removeItem("account");
    localStorage.removeItem("token");
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
      selectedMiv.to === activeDesk?.id &&
      !selectedMiv.read_at &&
      selectedBasket === "IN";
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
    if (miv.to === activeDesk?.id && !miv.read_at) {
      try {
        await api.markMivAsRead(miv.id, activeDesk.id);
        // Update the selected miv with read status
        const updatedMiv = { ...miv, read_at: new Date().toISOString() };
        setSelectedMiv(updatedMiv);
      } catch (err) {
        console.error("Failed to mark miv as read:", err);
      }
    }
  };

  const handleMivReply = async (body: string, isAck: boolean = false) => {
    if (!activeDesk || !selectedMiv) return;

    try {
      await api.replyToConversation(
        selectedMiv.conversation_id,
        activeDesk.id,
        {
          body,
          is_ack: isAck,
          font_family: activeDesk.font_family,
          font_size: activeDesk.font_size,
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
      // Convert CreateMivRequest to CreateConversationRequest (they have the same fields now)
      const conversationRequest = {
        to: request.to,
        cc: request.cc,
        subject: request.subject,
        body: request.body,
        font_family: request.font_family,
        font_size: request.font_size,
      };

      await api.createConversation(activeDesk.id, conversationRequest);

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

  const handleReply = async (body: string, isAck: boolean = false) => {
    if (!activeDesk || !selectedConversation) return;

    try {
      await api.replyToConversation(
        selectedConversation.conversation.id,
        activeDesk.id,
        {
          body,
          is_ack: isAck,
        }
      );

      // Reload conversation
      const response = await api.getConversation(
        selectedConversation.conversation.id,
        activeDesk.id
      );
      setSelectedConversation(response);
      await refreshConversations();
    } catch (err) {
      console.error("Failed to reply:", err);
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

  return (
    <div className="app">
      <div className="sidebar">
        <div className="sidebar-header">
          <button
            className="mobile-menu-btn"
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle menu"
          >
            ☰
          </button>
          <h1>Zcomm</h1>
          <div className="mobile-header-actions">
            {selectedMiv && (
              <button
                className="mobile-back-btn"
                onClick={() => setSelectedMiv(null)}
                aria-label="Back to basket"
              >
                ←
              </button>
            )}
            {currentView !== "compose" && (
              <button
                className="mobile-compose-btn"
                onClick={() => setCurrentView("compose")}
                aria-label="Compose new message"
              >
                ✏️ Compose
              </button>
            )}
          </div>
          <div className="user-info">
            <div className="user-name">{account.display_name}</div>
            <div className="user-username">@{account.username}</div>
          </div>
        </div>

        <DeskSwitcher
          desks={desks}
          activeDeskId={activeDesk.id}
          onSwitchDesk={handleSwitchDesk}
          onCreateDesk={handleCreateDesk}
        />

        <button
          onClick={() => setCurrentView("compose")}
          className="compose-btn"
        >
          + New Conversation
        </button>

        <nav className={`nav-menu ${mobileMenuOpen ? "open" : ""}`}>
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
                setMobileMenuOpen(false);
              }}
            >
              👥 Contacts
            </button>
            <button
              className={currentView === "notifications" ? "active" : ""}
              onClick={() => {
                setCurrentView("notifications");
                setMobileMenuOpen(false);
              }}
            >
              🔔 Notifications
              {unreadCount > 0 && <span className="badge">{unreadCount}</span>}
            </button>
          </div>

          <div className="nav-section">
            <h4>Account</h4>
            <button
              className={currentView === "settings" ? "active" : ""}
              onClick={() => {
                setCurrentView("settings");
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
            onClick={() => setCurrentView("settings")}
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
        {currentView === "settings" ? (
          <Settings
            desk={activeDesk}
            onClose={() => setCurrentView("baskets")}
            onDeskUpdated={handleDeskUpdated}
          />
        ) : currentView === "compose" ? (
          <ComposeMiv
            onSend={handleSendConversation}
            onCancel={() => setCurrentView("baskets")}
            deskId={activeDesk.id}
            desk={activeDesk}
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
                key={basketRefreshKey}
                deskId={activeDesk.id}
                selectedBasket={selectedBasket}
                onMivClick={handleMivClick}
                selectedMivId={selectedMiv?.id}
                onBasketChange={setSelectedBasket}
              />
            </div>
            <div
              className={`basket-detail-container ${
                selectedMiv ? "mobile-fullscreen" : ""
              }`}
            >
              {selectedMiv ? (
                <MivDetailWithContext
                  miv={selectedMiv}
                  currentDeskId={activeDesk.id}
                  currentDesk={activeDesk}
                  onReply={handleMivReply}
                  onForget={handleMivForget}
                  onDeleteCc={handleDeleteCc}
                />
              ) : (
                <div className="empty-selection">
                  <p>Select a message to view</p>
                </div>
              )}
            </div>
          </>
        ) : (
          <>
            <div className="conversation-list-container">
              <ConversationList
                conversations={conversations.filter(
                  (conv) => !conv.conversation.is_archived
                )}
                selectedConversationId={selectedConversation?.conversation.id}
                onConversationClick={handleConversationClick}
                currentDeskId={activeDesk.id}
              />
            </div>
            <div className="conversation-thread-container">
              {selectedConversation ? (
                <ConversationThread
                  conversation={selectedConversation}
                  currentDeskId={activeDesk.id}
                  desk={activeDesk}
                  account={account || undefined}
                  onReply={handleReply}
                />
              ) : (
                <div className="empty-conversation">
                  <p>Select a conversation to view</p>
                </div>
              )}
            </div>
          </>
        )}
      </div>
      {toastMessage && (
        <Toast message={toastMessage} onClose={() => setToastMessage(null)} />
      )}
    </div>
  );
}

export default App;
