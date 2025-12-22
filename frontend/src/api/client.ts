import {
  Miv,
  Identity,
  CreateMivRequest,
  UpdateStateRequest,
  Account,
  Desk,
  RegisterRequest,
  RegisterResponse,
  LoginRequest,
  LoginResponse,
  CreateDeskRequest,
  SwitchDeskRequest,
  UpdateDeskRequest,
  ListConversationsResponse,
  GetConversationResponse,
  ConversationMiv,
  CreateConversationRequest,
  ReplyToConversationRequest,
  ListNotificationsResponse,
  Contact,
  CreateContactRequest,
  UpdateContactRequest,
  ListContactsResponse,
} from "../types";

// Use environment variable or default to localhost backend for development
const API_BASE_URL =
  process.env.REACT_APP_API_URL || "http://localhost:8080/api";

// Helper to get auth headers
const getAuthHeaders = (): HeadersInit => {
  const token = localStorage.getItem("token");
  const headers: HeadersInit = {
    "Content-Type": "application/json",
  };
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
};

// Helper to handle auth errors
const handleAuthError = (response: Response) => {
  if (response.status === 401) {
    localStorage.removeItem("token");
    localStorage.removeItem("account");
    window.location.href = "/";
    throw new Error("Session expired. Please login again.");
  }
};

// Identity API
export const getIdentity = async (): Promise<Identity> => {
  const response = await fetch(`${API_BASE_URL}/identity`);
  if (!response.ok) {
    throw new Error("Failed to fetch identity");
  }
  return response.json();
};

export const createIdentity = async (name: string): Promise<Identity> => {
  const response = await fetch(`${API_BASE_URL}/identity`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name }),
  });
  if (!response.ok) {
    throw new Error("Failed to create identity");
  }
  return response.json();
};

// Miv API
export const listMivs = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs`);
  if (!response.ok) {
    throw new Error("Failed to fetch mivs");
  }
  return response.json();
};

export const getMiv = async (id: string): Promise<Miv> => {
  const response = await fetch(`${API_BASE_URL}/mivs/${id}`);
  if (!response.ok) {
    throw new Error("Failed to fetch miv");
  }
  return response.json();
};

export const createMiv = async (request: CreateMivRequest): Promise<Miv> => {
  const response = await fetch(`${API_BASE_URL}/mivs`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    throw new Error("Failed to create miv");
  }
  return response.json();
};

export const updateMivState = async (
  id: string,
  request: UpdateStateRequest
): Promise<Miv> => {
  const response = await fetch(`${API_BASE_URL}/mivs/${id}/state`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    throw new Error("Failed to update miv state");
  }
  return response.json();
};

// Filtered miv endpoints
export const getInbox = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs/inbox`);
  if (!response.ok) {
    throw new Error("Failed to fetch inbox");
  }
  return response.json();
};

export const getPending = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs/pending`);
  if (!response.ok) {
    throw new Error("Failed to fetch pending mivs");
  }
  return response.json();
};

export const getSent = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs/sent`);
  if (!response.ok) {
    throw new Error("Failed to fetch sent mivs");
  }
  return response.json();
};

export const getUnanswered = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs/unanswered`);
  if (!response.ok) {
    throw new Error("Failed to fetch unanswered mivs");
  }
  return response.json();
};

export const getArchived = async (): Promise<Miv[]> => {
  const response = await fetch(`${API_BASE_URL}/mivs/archived`);
  if (!response.ok) {
    throw new Error("Failed to fetch archived mivs");
  }
  return response.json();
};

// Account API

export const register = async (
  request: RegisterRequest
): Promise<RegisterResponse> => {
  const response = await fetch(`${API_BASE_URL}/accounts/register`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to register");
  }
  return response.json();
};

export const login = async (request: LoginRequest): Promise<LoginResponse> => {
  const response = await fetch(`${API_BASE_URL}/accounts/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to login");
  }
  return response.json();
};

// Desk API

export const listDesks = async (accountId: string): Promise<Desk[]> => {
  const response = await fetch(`${API_BASE_URL}/desks?account_id=${accountId}`);
  if (!response.ok) {
    throw new Error("Failed to fetch desks");
  }
  return response.json();
};

export const createDesk = async (
  accountId: string,
  request: CreateDeskRequest
): Promise<Desk> => {
  const response = await fetch(
    `${API_BASE_URL}/desks?account_id=${accountId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    throw new Error("Failed to create desk");
  }
  return response.json();
};

export const switchDesk = async (
  accountId: string,
  request: SwitchDeskRequest
): Promise<Account> => {
  const response = await fetch(
    `${API_BASE_URL}/desks/switch?account_id=${accountId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    throw new Error("Failed to switch desk");
  }
  return response.json();
};

export const updateDesk = async (
  deskId: string,
  request: UpdateDeskRequest
): Promise<Desk> => {
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}`, {
    method: "PUT",
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to update desk");
  }
  return response.json();
};

// Public key API (for E2E encryption)

export const getDeskPublicKey = async (
  deskId: string
): Promise<{ desk_id: string; public_key: string }> => {
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}/public-key`);
  if (!response.ok) {
    throw new Error("Failed to fetch public key");
  }
  return response.json();
};

export const getBatchDeskPublicKeys = async (
  deskIds: string[]
): Promise<{ public_keys: Record<string, string> }> => {
  const response = await fetch(`${API_BASE_URL}/desks/public-keys`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ desk_ids: deskIds }),
  });
  if (!response.ok) {
    throw new Error("Failed to fetch public keys");
  }
  return response.json();
};

// Conversation API

export const listConversations = async (
  deskId: string
): Promise<ListConversationsResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations?desk_id=${deskId}`
  );
  if (!response.ok) {
    throw new Error("Failed to fetch conversations");
  }
  return response.json();
};

export const listArchivedConversations = async (
  deskId: string
): Promise<ListConversationsResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/archived?desk_id=${deskId}`
  );
  if (!response.ok) {
    throw new Error("Failed to fetch archived conversations");
  }
  return response.json();
};

export const getConversation = async (
  id: string,
  deskId?: string
): Promise<GetConversationResponse> => {
  const url = deskId
    ? `${API_BASE_URL}/conversations/${id}?desk_id=${deskId}`
    : `${API_BASE_URL}/conversations/${id}`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Failed to fetch conversation");
  }
  return response.json();
};

export const createConversation = async (
  deskId: string,
  request: CreateConversationRequest
): Promise<GetConversationResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    // Try to parse error message from response
    const errorData = await response
      .json()
      .catch(() => ({ error: "Failed to create conversation" }));
    throw new Error(errorData.error || "Failed to create conversation");
  }
  return response.json();
};

export const replyToConversation = async (
  conversationId: string,
  deskId: string,
  request: ReplyToConversationRequest
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/${conversationId}/reply?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    throw new Error("Failed to reply to conversation");
  }
};

// Archive conversation
export const archiveConversation = async (
  conversationId: string
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/${conversationId}/archive`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error("Failed to archive conversation");
  }
};

export const deleteConversation = async (
  conversationId: string,
  deskId: string
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/${conversationId}?desk_id=${deskId}`,
    {
      method: "DELETE",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error("Failed to delete conversation");
  }
};

// CC functions
export const answerCcMiv = async (
  conversationId: string,
  deskId: string
): Promise<GetConversationResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/${conversationId}/cc/answer?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error("Failed to answer CC");
  }
  return response.json();
};

export const deleteCcMiv = async (
  conversationId: string,
  deskId: string
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/${conversationId}/cc/delete?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error("Failed to delete CC");
  }
};

// Mark miv as read
export const markMivAsRead = async (
  mivId: string,
  deskId?: string
): Promise<ConversationMiv> => {
  const url = deskId
    ? `${API_BASE_URL}/mivs/${mivId}/read?desk_id=${deskId}`
    : `${API_BASE_URL}/mivs/${mivId}/read`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error("Failed to mark miv as read");
  }
  return response.json();
};

// Forget miv (remove from SENT basket, stop tracking replies)
export const forgetMiv = async (mivId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/mivs/${mivId}/forget`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
  });
  if (!response.ok) {
    throw new Error("Failed to forget miv");
  }
};

// Via routing functions
export const approveViaRouting = async (
  mivId: string,
  deskId: string,
  nextRecipientBody: string
): Promise<ConversationMiv> => {
  const response = await fetch(
    `${API_BASE_URL}/mivs/${mivId}/via/approve?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        next_recipient_body: nextRecipientBody,
      }),
    }
  );
  if (!response.ok) {
    throw new Error("Failed to approve via routing");
  }
  return response.json();
};

export const rejectViaRouting = async (
  mivId: string,
  deskId: string,
  reason: string,
  recipientBody: string
): Promise<ConversationMiv> => {
  const response = await fetch(
    `${API_BASE_URL}/mivs/${mivId}/via/reject?desk_id=${deskId}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ reason, recipient_body: recipientBody }),
    }
  );
  if (!response.ok) {
    throw new Error("Failed to reject via routing");
  }
  return response.json();
};

// Notification API

export const listNotifications = async (
  deskId: string,
  unreadOnly: boolean = false
): Promise<ListNotificationsResponse> => {
  const url = `${API_BASE_URL}/notifications?desk_id=${deskId}${
    unreadOnly ? "&unread_only=true" : ""
  }`;
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Failed to fetch notifications");
  }
  return response.json();
};

export const markNotificationAsRead = async (
  notificationId: string
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/notifications/${notificationId}/read`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
  if (!response.ok) {
    throw new Error("Failed to mark notification as read");
  }
};

// Contact API

export const listContacts = async (
  deskId: string
): Promise<ListContactsResponse> => {
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}/contacts`);
  if (!response.ok) {
    throw new Error("Failed to fetch contacts");
  }
  return response.json();
};

export const createContact = async (
  deskId: string,
  request: CreateContactRequest
): Promise<Contact> => {
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}/contacts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to create contact");
  }
  return response.json();
};

export const getContact = async (contactId: string): Promise<Contact> => {
  const response = await fetch(`${API_BASE_URL}/contacts/${contactId}`);
  if (!response.ok) {
    throw new Error("Failed to fetch contact");
  }
  return response.json();
};

export const updateContact = async (
  contactId: string,
  request: UpdateContactRequest
): Promise<Contact> => {
  const response = await fetch(`${API_BASE_URL}/contacts/${contactId}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to update contact");
  }
  return response.json();
};

export const deleteContact = async (contactId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/contacts/${contactId}`, {
    method: "DELETE",
  });
  if (!response.ok) {
    throw new Error("Failed to delete contact");
  }
};
