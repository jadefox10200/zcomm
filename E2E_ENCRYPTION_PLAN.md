# E2E Encryption Implementation Plan

## Overview

Implement end-to-end encryption for all messages using Curve25519 (X25519) key exchange and XSalsa20-Poly1305 authenticated encryption via NaCl/TweetNaCl.

## Architecture

### Key Management

1. **Key Generation**: Each desk has a Curve25519 key pair (public/private)
2. **Storage**:
   - **Public Key**: Stored in plaintext in database (desks table)
   - **Private Key**:
     - Backend: Encrypted with user's password using Argon2-derived key, stored in database
     - Frontend: Decrypted private key stored in sessionStorage during active session
3. **Key Retrieval**: Frontend fetches recipient's public key before sending message

### Encryption Flow (Sending)

```
1. User composes message in frontend
2. Frontend fetches recipient's public key from backend
3. Frontend encrypts message body using:
   - Sender's private key (from sessionStorage)
   - Recipient's public key (from API)
   - Random nonce (prepended to ciphertext)
4. Frontend sends encrypted body to backend
5. Backend stores encrypted body in database (no decryption server-side)
```

### Decryption Flow (Receiving)

```
1. Frontend fetches encrypted message from backend
2. Frontend decrypts message body using:
   - Sender's public key (fetched from API or cached)
   - Recipient's private key (from sessionStorage)
3. Frontend displays decrypted message
```

## Implementation Tasks

### Backend (Go)

#### 1. Private Key Encryption

**File**: `backend/internal/crypto/password.go`

- [x] Already has `Hash()` function using Argon2
- [ ] Add `EncryptPrivateKey(privateKey []byte, password string) ([]byte, error)`
- [ ] Add `DecryptPrivateKey(encryptedKey []byte, password string) ([]byte, error)`

#### 2. Desk Registration/Login

**File**: `backend/internal/api/users.go`

- [ ] Update `POST /api/register`:
  - Generate key pair for default desk
  - Encrypt private key with user's password
  - Store encrypted private key in database
- [ ] Update `POST /api/login`:
  - Return encrypted private key with login response
  - Frontend will decrypt with password
- [ ] Add `POST /api/desks/:id/private-key`:
  - Decrypt and return private key (requires auth + password confirmation)

####3. Public Key Lookup
**File**: `backend/internal/api/users.go`

- [ ] Add `GET /api/desks/:id/public-key`:
  - Returns public key for given desk ID
  - No authentication required (public keys are public)
- [ ] Add `POST /api/desks/public-keys` (batch):
  - Returns public keys for multiple desk IDs
  - For encrypting CC'd messages

#### 4. Message Handling

**File**: `backend/internal/api/handlers.go`

- [ ] Update `createConversation()`:
  - Accept encrypted body from frontend
  - Set `is_encrypted = true`
  - Store as-is (no server-side decryption)
- [ ] Update `replyToConversation()`:
  - Same as above
- [ ] Update `getConversation()`:
  - Return encrypted bodies as-is
  - Frontend handles decryption

### Frontend (TypeScript/React)

#### 1. Crypto Utilities

**File**: `frontend/src/utils/crypto.ts`

- [x] Created with functions:
  - `generateKeyPair()`: Generate new key pair
  - `encryptMessage()`: Encrypt message for recipient
  - `decryptMessage()`: Decrypt message from sender
  - `encryptPrivateKey()`: Encrypt private key with password
  - `decryptPrivateKey()`: Decrypt private key with password
  - `storePrivateKey()`: Store in sessionStorage
  - `getPrivateKey()`: Retrieve from sessionStorage
  - `clearPrivateKey()`: Clear from sessionStorage

#### 2. API Client Updates

**File**: `frontend/src/api/client.ts`

- [ ] Add `getPublicKey(deskId: string)`: Fetch public key
- [ ] Add `getPublicKeys(deskIds: string[])`: Batch fetch
- [ ] Update `login()`: Handle encrypted private key in response
- [ ] Cache public keys in memory to reduce API calls

#### 3. Auth Component

**File**: `frontend/src/components/Auth.tsx`

- [ ] Update `handleLogin()`:
  - Receive encrypted private key from backend
  - Decrypt with user's password
  - Store decrypted private key in sessionStorage
- [ ] Update `handleRegister()`:
  - Generate key pair in frontend
  - Encrypt private key with password
  - Send public key + encrypted private key to backend

#### 4. Message Composition

**File**: `frontend/src/components/ComposeMiv.tsx`

- [ ] Update `handleSend()`:
  - Fetch recipient's public key(s) (to, cc, via)
  - Get sender's private key from sessionStorage
  - Encrypt message body before sending
  - Set `is_encrypted: true`

**File**: `frontend/src/components/MivDetailWithContext.tsx`

- [ ] Update `handleReply()` and `handleAck()`:
  - Same encryption logic as compose

#### 5. Message Display

**File**: `frontend/src/components/MivDetail.tsx`

- [ ] Update component to decrypt messages:
  - Check `is_encrypted` flag
  - If encrypted:
    - Fetch sender's public key
    - Get recipient's private key from sessionStorage
    - Decrypt body before display
  - If not encrypted: display as-is (backward compatibility)
- [ ] Add error handling for decryption failures
- [ ] Show "[Encrypted Message]" placeholder while decrypting

## Security Considerations

1. **Private Key Protection**:

   - Never send unencrypted private keys over network
   - Clear sessionStorage on logout
   - Use HTTPS for all API calls

2. **Password Verification**:

   - Decryption failure = wrong password
   - No separate password verification needed

3. **Backward Compatibility**:

   - Check `is_encrypted` flag before attempting decryption
   - Old unencrypted messages still displayable

4. **Key Rotation** (Future):
   - Allow users to generate new key pairs
   - Re-encrypt old messages with new keys
   - Implement key versioning

## Testing Plan

1. **Unit Tests**:

   - Test encrypt/decrypt functions
   - Test key generation
   - Test private key encryption with password

2. **Integration Tests**:

   - Test full message flow: compose → encrypt → send → receive → decrypt
   - Test with multiple recipients (CC, Via)
   - Test decryption failure scenarios

3. **E2E Tests**:
   - Register new user with encryption
   - Login and decrypt private key
   - Send encrypted message
   - Receive and decrypt message
   - Verify server never sees plaintext

## Migration Strategy

1. **Phase 1**: Add encryption support (keep backward compatibility)
   - New messages encrypted
   - Old messages displayed as-is
2. **Phase 2**: Gradual migration

   - All new users get encryption by default
   - Existing users can opt-in

3. **Phase 3** (Optional): Full encryption
   - Require encryption for all messages
   - Migrate remaining unencrypted messages

## API Changes Summary

### New Endpoints

- `GET /api/desks/:id/public-key` - Get desk's public key
- `POST /api/desks/public-keys` - Batch get public keys
- `POST /api/desks/:id/private-key` - Get encrypted private key (requires auth + password)

### Modified Endpoints

- `POST /api/register` - Accepts `public_key` and `encrypted_private_key`
- `POST /api/login` - Returns `encrypted_private_key` in response
- `POST /api/conversations` - Accepts pre-encrypted `body`
- `POST /api/conversations/:id/reply` - Accepts pre-encrypted `body`

### Modified Fields

- `conversation_mivs.body` - Now stores encrypted data (base64)
- `conversation_mivs.is_encrypted` - Set to `true` for E2E encrypted messages
