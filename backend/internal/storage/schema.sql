-- SQLite Schema for Zcomm Application

-- Accounts table
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    status TEXT NOT NULL DEFAULT 'active',
    locked_at DATETIME,
    closed_at DATETIME,
    force_password_reset BOOLEAN NOT NULL DEFAULT 0,
    active_desk TEXT NOT NULL DEFAULT '',
    birthday_hash TEXT NOT NULL,
    first_pet_name_hash TEXT NOT NULL,
    mother_maiden_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);

-- Desks table (each account can have multiple desks)
CREATE TABLE IF NOT EXISTS desks (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key BLOB NOT NULL,
    auto_indent BOOLEAN NOT NULL DEFAULT 1,
    font_family TEXT NOT NULL DEFAULT 'Georgia, serif',
    font_size TEXT NOT NULL DEFAULT '14px',
    line_height TEXT NOT NULL DEFAULT '1.65',
    default_salutation TEXT NOT NULL DEFAULT '',
    default_closure TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_desks_account_id ON desks(account_id);

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
    id TEXT PRIMARY KEY,
    desk_id TEXT NOT NULL,
    other_desk_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    is_archived BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (desk_id) REFERENCES desks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conversations_desk_id ON conversations(desk_id);
CREATE INDEX IF NOT EXISTS idx_conversations_updated_at ON conversations(updated_at DESC);

-- Conversation MIVs table
CREATE TABLE IF NOT EXISTS conversation_mivs (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    seq_no INTEGER NOT NULL DEFAULT 1,
    from_desk_id TEXT NOT NULL,
    to_desk_id TEXT NOT NULL,
    arrow_to TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    state TEXT NOT NULL,
    type TEXT NOT NULL,
    font_family TEXT NOT NULL,
    font_size TEXT NOT NULL,
    line_height TEXT NOT NULL DEFAULT '1.65',
    is_encrypted BOOLEAN NOT NULL DEFAULT 0,
    is_ack BOOLEAN NOT NULL DEFAULT 0,
    is_forgotten BOOLEAN NOT NULL DEFAULT 0,
    deleted BOOLEAN NOT NULL DEFAULT 0,
    read_at DATETIME,
    cc TEXT,
    via TEXT,
    via_index INTEGER DEFAULT 0,
    is_via_rejected BOOLEAN NOT NULL DEFAULT 0,
    via_rejected_by TEXT,
    via_rejection TEXT,
    rejected_miv_id TEXT,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE,
    FOREIGN KEY (owner) REFERENCES desks(id) ON DELETE CASCADE,
    FOREIGN KEY (from_desk_id) REFERENCES desks(id) ON DELETE CASCADE,
    FOREIGN KEY (to_desk_id) REFERENCES desks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_conversation_mivs_conversation_id ON conversation_mivs(conversation_id);
CREATE INDEX IF NOT EXISTS idx_conversation_mivs_owner_state ON conversation_mivs(owner, state, deleted);
CREATE INDEX IF NOT EXISTS idx_conversation_mivs_created_at ON conversation_mivs(created_at);
CREATE INDEX IF NOT EXISTS idx_conversation_mivs_arrow_to ON conversation_mivs(arrow_to);
CREATE INDEX IF NOT EXISTS idx_conversation_mivs_state ON conversation_mivs(state);

-- Contacts table
CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    desk_id TEXT NOT NULL,
    desk_id_ref TEXT NOT NULL,
    display_name TEXT NOT NULL,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    greeting_name TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL,
    FOREIGN KEY (desk_id) REFERENCES desks(id) ON DELETE CASCADE,
    UNIQUE(desk_id, desk_id_ref)
);

CREATE INDEX IF NOT EXISTS idx_contacts_desk_id ON contacts(desk_id);

-- Notifications table
CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    desk_id TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL,
    FOREIGN KEY (desk_id) REFERENCES desks(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_notifications_desk_id ON notifications(desk_id);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at DESC);

-- Legacy MIVs table (for backward compatibility with single-user mode)
CREATE TABLE IF NOT EXISTS mivs (
    id TEXT PRIMARY KEY,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at DATETIME NOT NULL,
    read_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_mivs_state ON mivs(state);

-- Identity table (for legacy single-user mode)
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    phone_number TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key BLOB NOT NULL,
    created_at DATETIME NOT NULL
);
