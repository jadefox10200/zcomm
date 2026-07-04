export type MivState =
  | "IN"
  | "PENDING"
  | "SENT"
  | "OUT"
  | "UNANSWERED"
  | "ARCHIVED"
  | "CC"
  | "REMOVED";

export type NotificationType = "READ_RECEIPT" | "NEW_MIV" | "REPLY";

export interface Miv {
  id: string;
  from: string;
  to: string;
  cc?: string[];
  subject: string;
  body: string;
  state: MivState;
  created_at: string;
  sent_at?: string;
  received_at?: string;
  is_encrypted: boolean;
  font_family?: string;
  font_size?: string;
}

export interface Identity {
  id: string;
  public_key: string;
  name: string;
}

export interface CreateMivRequest {
  to: string;
  cc?: string[];
  via?: string[];
  subject: string;
  sender_body: string;
  recipient_body: string;
  cc_bodies?: { [deskId: string]: string }; // Map of CC deskId to encrypted body
  attachment_ids?: string[];
  font_family?: string;
  font_size?: string;
  line_height?: string;
}

export interface UpdateStateRequest {
  state: MivState;
}

// Account and Authentication types

export interface Account {
  id: string;
  username: string;
  display_name: string;
  role?: string;
  status?: string;
  locked_at?: string;
  closed_at?: string;
  force_password_reset?: boolean;
  created_at: string;
  updated_at: string;
  desks: string[];
  active_desk: string;
}

export interface AdminUserCounts {
  total: number;
  active: number;
  locked: number;
  closed: number;
  admins: number;
}

export interface AdminUsersResponse {
  users: Account[];
}

export interface Desk {
  id: string;
  account_id: string;
  public_key: string;
  name: string;
  created_at: string;
  auto_indent: boolean;
  font_family: string;
  font_size: string;
  line_height: string;
  default_salutation: string;
  default_closure: string;
}

export interface RegisterRequest {
  username: string;
  password: string;
  display_name: string;
  birthday: string;
  first_pet_name: string;
  mother_maiden: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  account: Account;
  token: string;
  encrypted_priv_keys?: Record<string, string>; // Desk ID -> Encrypted private key (base64)
}

export interface RegisterResponse {
  message: string;
  username: string;
}

export interface CreateDeskRequest {
  name: string;
}

export interface SwitchDeskRequest {
  desk_id: string;
}

export interface UpdateDeskRequest {
  name?: string;
  auto_indent?: boolean;
  font_family?: string;
  font_size?: string;
  line_height?: string;
  default_salutation?: string;
  default_closure?: string;
}

export interface RecoverPasswordRequest {
  username: string;
  birthday: string;
  first_pet_name: string;
  mother_maiden: string;
  new_password: string;
}

// Conversation types

export interface Conversation {
  id: string;
  subject: string;
  desk_id: string;
  created_at: string;
  updated_at: string;
  miv_count: number;
  is_archived: boolean;
}

export interface ConversationMiv {
  id: string;
  conversation_id: string;
  owner: string;
  seq_no: number;
  from: string;
  to: string;
  cc?: string[];
  arrow_to: string;
  type: "MIV" | "CC" | "VIA" | "MEMO";
  subject: string;
  body: string;
  state: MivState;
  created_at: string;
  sent_at?: string;
  received_at?: string;
  read_at?: string;
  is_encrypted: boolean;
  is_ack: boolean;
  is_forgotten: boolean;
  deleted: boolean;
  font_family?: string;
  font_size?: string;
  line_height?: string;
  via?: string[];
  via_index: number;
  is_via_rejected: boolean;
  via_rejected_by?: string;
  via_rejection?: string;
  rejected_miv_id?: string;
  attachments?: Attachment[];
}

export interface Attachment {
  id: string;
  conversation_id?: string;
  seq_no: number;
  uploaded_by: string;
  original_filename: string;
  stored_filename: string;
  content_type: string;
  size: number;
  created_at: string;
}

export interface CreateConversationRequest {
  to: string;
  via?: string[];
  cc?: string[];
  subject: string;
  sender_body: string; // Encrypted body for sender (encrypted with sender's keys)
  recipient_body: string; // Encrypted body for recipient (encrypted with recipient's public key)
  cc_bodies?: { [deskId: string]: string }; // Encrypted bodies for each CC recipient (map of deskId -> encrypted body)
  attachment_ids?: string[]; // Uploaded attachment IDs
  font_family?: string;
  font_size?: string;
  line_height?: string;
}

export interface ReplyToConversationRequest {
  sender_body: string; // Encrypted body for sender
  recipient_body: string; // Encrypted body for recipient
  cc_bodies?: { [deskId: string]: string }; // Encrypted bodies for each CC recipient
  is_ack?: boolean;
  cc?: string[];
  attachment_ids?: string[];
  font_family?: string;
  font_size?: string;
  line_height?: string;
}

export interface ConversationWithLatest {
  conversation: Conversation;
  latest_miv?: ConversationMiv;
  unread_count: number;
}

export interface ListConversationsResponse {
  conversations: ConversationWithLatest[];
  total: number;
}

export interface GetConversationResponse {
  conversation: Conversation;
  mivs: ConversationMiv[];
}

// Notification types

export interface Notification {
  id: string;
  desk_id: string;
  type: NotificationType;
  miv_id: string;
  conversation_id?: string;
  message: string;
  read: boolean;
  created_at: string;
  read_at?: string;
}

export interface ListNotificationsResponse {
  notifications: Notification[];
  unread_count: number;
  total: number;
}

// Contact types

export interface Contact {
  id: string;
  desk_id: string;
  name: string;
  first_name?: string;
  last_name?: string;
  greeting_name?: string;
  desk_id_ref: string;
  notes: string;
  created_at: string;
  updated_at: string;
}

export interface CreateContactRequest {
  name: string;
  first_name?: string;
  last_name?: string;
  greeting_name?: string;
  desk_id_ref: string;
  notes?: string;
}

export interface UpdateContactRequest {
  name?: string;
  first_name?: string;
  last_name?: string;
  greeting_name?: string;
  desk_id_ref?: string;
  notes?: string;
}

export interface UploadFileResponse {
  id: string;
  conversation_id?: string;
  seq_no: number;
  uploaded_by: string;
  original_filename: string;
  stored_filename: string;
  content_type: string;
  size: number;
  created_at: string;
}

export interface ListContactsResponse {
  contacts: Contact[];
  total: number;
}
