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
  AdminUserCounts,
  AdminUsersResponse,
  Contact,
  CreateContactRequest,
  UpdateContactRequest,
  ListContactsResponse,
  UploadFileResponse,
} from "../types";
import { Capacitor } from "@capacitor/core";

const normalizeBaseUrl = (url: string): string => url.replace(/\/+$/, "");

const isAbsoluteHttpUrl = (url: string): boolean => /^https?:\/\//i.test(url);

const resolveApiBaseUrl = (): string => {
  const envUrl = process.env.REACT_APP_API_URL?.trim();
  const isNativeRuntime = Capacitor.isNativePlatform();
  const host = typeof window !== "undefined" ? window.location.hostname : "";
  const isProductionHost = /(^|\.)zcommapp\.com$/i.test(host);

  if (envUrl) {
    if (isAbsoluteHttpUrl(envUrl)) {
      return normalizeBaseUrl(envUrl);
    }

    if (isNativeRuntime && envUrl.startsWith("/")) {
      return normalizeBaseUrl(`https://zcommapp.com${envUrl}`);
    }

    if (!isNativeRuntime && !envUrl.startsWith("/")) {
      return normalizeBaseUrl(envUrl);
    }

    if (!isNativeRuntime && envUrl.startsWith("/") && isProductionHost) {
      return normalizeBaseUrl(envUrl);
    }
  }

  if (!isNativeRuntime) {
    // Only production web host should use same-origin API proxy.
    if (isProductionHost) {
      return "/api";
    }

    // Local/LAN static serving (serve -s build) has no API proxy.
    return "https://zcommapp.com/api";
  }

  // Native apps need an absolute host.
  return "https://zcommapp.com/api";
};

const API_BASE_URL = resolveApiBaseUrl();

let authRedirectInProgress = false;

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

const getUploadAuthHeaders = (): HeadersInit => {
  const token = localStorage.getItem("token");
  const headers: HeadersInit = {};
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
};

// Helper to handle auth errors
const handleAuthError = (response: Response) => {
  if (response.status !== 401) {
    return;
  }

  localStorage.removeItem("token");
  localStorage.removeItem("account");
  localStorage.removeItem("encrypted_priv_keys");
  sessionStorage.clear();

  if (typeof window !== "undefined" && !authRedirectInProgress) {
    authRedirectInProgress = true;

    const message = "Your session expired. Please sign in again.";
    try {
      window.alert(message);
    } catch {
      // Ignore alert issues and continue with redirect.
    }

    const loginUrl = "/?session=expired";
    window.location.replace(loginUrl);
  }

  throw new Error("Session expired. Please sign in again.");
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
  const requestUrl = `${API_BASE_URL}/accounts/register`;
  const response = await fetch(requestUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  const responseBody = await response.text();

  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    if (!responseBody.trim()) {
      throw new Error(`Failed to register: HTTP ${response.status} with empty response body`);
    }
    if (contentType.includes("application/json")) {
      try {
        const error = JSON.parse(responseBody);
        throw new Error(error.error || error.message || `Failed to register: HTTP ${response.status}`);
      } catch {
      }
    }
    if (responseBody.trim().startsWith("<")) {
      const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
      console.error("Register API diagnostic:", diagnostic);
      throw new Error(`Failed to register: backend returned HTML instead of JSON. ${diagnostic}`);
    }
    const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
    console.error("Register API diagnostic:", diagnostic);
    throw new Error(`Failed to register: ${diagnostic}`);
  }

  if (!responseBody.trim()) {
    throw new Error("Failed to register: backend returned empty body");
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(responseBody) as RegisterResponse;
    } catch {
      throw new Error(`Failed to register: malformed JSON response (HTTP ${response.status})`);
    }
  }

  if (responseBody.trim().startsWith("<")) {
    const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
    console.error("Register API diagnostic:", diagnostic);
    throw new Error(`Failed to register: received HTML page instead of API JSON. ${diagnostic}`);
  }

  const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
  console.error("Register API diagnostic:", diagnostic);
  throw new Error(`Failed to register: expected JSON. ${diagnostic}`);
};

export const login = async (request: LoginRequest): Promise<LoginResponse> => {
  const requestUrl = `${API_BASE_URL}/accounts/login`;
  const response = await fetch(requestUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  const responseBody = await response.text();

  const contentType = response.headers.get("content-type") || "";

  if (!response.ok) {
    if (!responseBody.trim()) {
      throw new Error(`Failed to login: HTTP ${response.status} with empty response body`);
    }
    if (contentType.includes("application/json")) {
      try {
        const error = JSON.parse(responseBody);
        throw new Error(error.error || error.message || `Failed to login: HTTP ${response.status}`);
      } catch {
      }
    }
    if (responseBody.trim().startsWith("<")) {
      const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
      console.error("Login API diagnostic:", diagnostic);
      throw new Error(`Failed to login: backend returned HTML instead of JSON. ${diagnostic}`);
    }
    const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
    console.error("Login API diagnostic:", diagnostic);
    throw new Error(`Failed to login: ${diagnostic}`);
  }

  if (!responseBody.trim()) {
    throw new Error("Failed to login: backend returned empty body");
  }

  if (contentType.includes("application/json")) {
    try {
      return JSON.parse(responseBody) as LoginResponse;
    } catch {
      throw new Error(`Failed to login: malformed JSON response (HTTP ${response.status})`);
    }
  }

  if (responseBody.trim().startsWith("<")) {
    const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
    console.error("Login API diagnostic:", diagnostic);
    throw new Error(`Failed to login: received HTML page instead of API JSON. ${diagnostic}`);
  }

  const diagnostic = `URL=${requestUrl} status=${response.status} content-type='${contentType || "unknown"}' body='${responseBody.slice(0, 120)}'`;
  console.error("Login API diagnostic:", diagnostic);
  throw new Error(`Failed to login: expected JSON. ${diagnostic}`);
};

// Desk API

export const listDesks = async (accountId: string): Promise<Desk[]> => {
  const response = await fetch(`${API_BASE_URL}/desks?account_id=${accountId}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}/public-key`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to fetch public key");
  }
  return response.json();
};

export const getBatchDeskPublicKeys = async (
  deskIds: string[]
): Promise<{ public_keys: Record<string, string> }> => {
  const response = await fetch(`${API_BASE_URL}/desks/public-keys`, {
    method: "POST",
    headers: getAuthHeaders(),
    body: JSON.stringify({ desk_ids: deskIds }),
  });
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to fetch public keys");
  }
  return response.json();
};

// Conversation API

export const listConversations = async (
  deskId: string
): Promise<ListConversationsResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations?desk_id=${deskId}`,
    { headers: getAuthHeaders() }
  );
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to fetch conversations");
  }
  return response.json();
};

export const listArchivedConversations = async (
  deskId: string
): Promise<ListConversationsResponse> => {
  const response = await fetch(
    `${API_BASE_URL}/conversations/archived?desk_id=${deskId}`,
    { headers: getAuthHeaders() }
  );
  if (!response.ok) {
    handleAuthError(response);
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
  const response = await fetch(url, { headers: getAuthHeaders() });
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify(request),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to mark miv as read");
  }
  return response.json();
};

// Forget miv (remove from SENT basket, stop tracking replies)
export const forgetMiv = async (mivId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/mivs/${mivId}/forget`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify({
        next_recipient_body: nextRecipientBody,
      }),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
      body: JSON.stringify({ reason, recipient_body: recipientBody }),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
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
  const response = await fetch(url, { headers: getAuthHeaders() });
  if (!response.ok) {
    handleAuthError(response);
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
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to mark notification as read");
  }
};

// Contact API

export const listContacts = async (
  deskId: string
): Promise<ListContactsResponse> => {
  const response = await fetch(`${API_BASE_URL}/desks/${deskId}/contacts`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
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
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json();
    throw new Error(error.error || "Failed to create contact");
  }
  return response.json();
};

export const MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024;
export const ATTACHMENT_UPLOAD_TIMEOUT_MS = 90_000;

export const uploadAttachment = async (
  file: File,
  deskId: string
): Promise<UploadFileResponse> => {
  if (file.size > MAX_ATTACHMENT_SIZE_BYTES) {
    throw new Error("File too large. Maximum size is 25MB");
  }

  const formData = new FormData();
  formData.append("upload", file);
  formData.append("desk_id", deskId);

  const controller = new AbortController();
  const timeoutId = window.setTimeout(
    () => controller.abort(),
    ATTACHMENT_UPLOAD_TIMEOUT_MS
  );

  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/attachments`, {
      method: "POST",
      headers: getUploadAuthHeaders(),
      body: formData,
      signal: controller.signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new Error(
        "Upload timed out after 90 seconds. Please try again."
      );
    }
    throw error;
  } finally {
    window.clearTimeout(timeoutId);
  }

  if (!response.ok) {
    handleAuthError(response);

    if (response.status === 413) {
      throw new Error(
        "Upload rejected by server (413 Request Entity Too Large). The active server/proxy limit appears lower than 25MB."
      );
    }

    const errorData = await response
      .json()
      .catch(() => ({ error: "Failed to upload attachment" }));
    throw new Error(
      errorData.error ||
        (response.status === 401 || response.status === 403
          ? "Your session could not upload attachments. Please sign in again."
          : "Failed to upload attachment")
    );
  }

  return response.json();
};

export const downloadAttachment = async (
  attachmentId: string,
  deskId: string
): Promise<Blob> => {
  const query = `?desk_id=${encodeURIComponent(deskId)}`;
  const response = await fetch(
    `${API_BASE_URL}/attachments/${attachmentId}${query}`,
    {
      headers: getAuthHeaders(),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
    const errorData = await response
      .json()
      .catch(() => ({ error: "Failed to download attachment" }));
    throw new Error(
      errorData.error ||
        (response.status === 401 || response.status === 403
          ? "Your session could not access this attachment. Please sign in again."
          : "Failed to download attachment")
    );
  }
  return response.blob();
};

export const getContact = async (contactId: string): Promise<Contact> => {
  const response = await fetch(`${API_BASE_URL}/contacts/${contactId}`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
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
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json();
    throw new Error(error.error || "Failed to update contact");
  }
  return response.json();
};

export const deleteContact = async (contactId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/contacts/${contactId}`, {
    method: "DELETE",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    throw new Error("Failed to delete contact");
  }
};

// Admin API

export const getAdminUserCounts = async (): Promise<AdminUserCounts> => {
  const response = await fetch(`${API_BASE_URL}/admin/users/count`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to fetch user counts");
  }
  return response.json();
};

export const listAdminUsers = async (): Promise<AdminUsersResponse> => {
  const response = await fetch(`${API_BASE_URL}/admin/users`, {
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to fetch users");
  }
  return response.json();
};

export const lockAdminUser = async (accountId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/admin/users/${accountId}/lock`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to lock user");
  }
};

export const unlockAdminUser = async (accountId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/admin/users/${accountId}/unlock`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to unlock user");
  }
};

export const closeAdminUser = async (accountId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/admin/users/${accountId}/close`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to close user");
  }
};

export const reopenAdminUser = async (accountId: string): Promise<void> => {
  const response = await fetch(`${API_BASE_URL}/admin/users/${accountId}/reopen`, {
    method: "POST",
    headers: getAuthHeaders(),
  });
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to reopen user");
  }
};

export const resetAdminUserPassword = async (
  accountId: string,
  newPassword: string
): Promise<void> => {
  const response = await fetch(
    `${API_BASE_URL}/admin/users/${accountId}/reset-password`,
    {
      method: "POST",
      headers: getAuthHeaders(),
      body: JSON.stringify({ new_password: newPassword }),
    }
  );
  if (!response.ok) {
    handleAuthError(response);
    const error = await response.json().catch(() => ({}));
    throw new Error(error.error || "Failed to reset password");
  }
};
