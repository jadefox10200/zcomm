/**
 * E2E Encryption utilities using TweetNaCl (NaCl/libsodium compatible)
 * Uses Curve25519 for key exchange and XSalsa20-Poly1305 for encryption
 */

import nacl from "tweetnacl";
import * as util from "tweetnacl-util";
import { argon2id } from "@noble/hashes/argon2.js";

// Re-export for convenience
export { nacl };

// Helper functions with correct types
const encodeUTF8 = (str: string): Uint8Array => {
  return util.decodeUTF8(str); // Note: tweetnacl-util names are backwards
};

const decodeUTF8 = (arr: Uint8Array): string => {
  return util.encodeUTF8(arr); // Note: tweetnacl-util names are backwards
};

const encodeBase64 = (arr: Uint8Array): string => {
  return util.encodeBase64(arr);
};

const decodeBase64 = (str: string): Uint8Array => {
  return util.decodeBase64(str);
};

/**
 * Generate a new Curve25519 key pair for a desk
 * @returns Object with publicKey and privateKey as base64 strings
 */
export function generateKeyPair(): { publicKey: string; privateKey: string } {
  const keyPair = nacl.box.keyPair();
  return {
    publicKey: encodeBase64(keyPair.publicKey),
    privateKey: encodeBase64(keyPair.secretKey),
  };
}

/**
 * Encrypt a message for a recipient
 * @param message - Plain text message to encrypt
 * @param recipientPublicKey - Recipient's public key (base64)
 * @param senderPrivateKey - Sender's private key (base64)
 * @returns Encrypted message (base64) with nonce prepended
 */
export function encryptMessage(
  message: string,
  recipientPublicKey: string,
  senderPrivateKey: string
): string {
  console.log("🔒 encryptMessage called with:", {
    messageLength: message.length,
    recipientPubKeyLength: recipientPublicKey.length,
    senderPrivKeyLength: senderPrivateKey.length,
  });

  const messageBytes = encodeUTF8(message);
  const recipientPubKey = decodeBase64(recipientPublicKey);
  const senderPrivKey = decodeBase64(senderPrivateKey);

  console.log(
    "🔑 Decoded keys for encryption - recipient pub:",
    recipientPubKey.length,
    "sender priv:",
    senderPrivKey.length
  );
  console.log(
    "💾 Recipient public key (first 20 chars):",
    recipientPublicKey.substring(0, 20)
  );
  console.log(
    "💾 Sender private key (first 20 chars):",
    senderPrivateKey.substring(0, 20)
  );

  // Generate a random nonce
  const nonce = nacl.randomBytes(nacl.box.nonceLength);

  // Encrypt the message
  const encrypted = nacl.box(
    messageBytes,
    nonce,
    recipientPubKey,
    senderPrivKey
  );

  // Prepend nonce to encrypted message
  const fullMessage = new Uint8Array(nonce.length + encrypted.length);
  fullMessage.set(nonce);
  fullMessage.set(encrypted, nonce.length);

  console.log(
    "✅ Message encrypted, total length:",
    fullMessage.length,
    "bytes"
  );
  return encodeBase64(fullMessage);
}

/**
 * Decrypt a message from a sender
 * @param encryptedMessage - Encrypted message (base64) with nonce prepended
 * @param senderPublicKey - Sender's public key (base64)
 * @param recipientPrivateKey - Recipient's private key (base64)
 * @returns Decrypted plain text message
 * @throws Error if decryption fails
 */
export function decryptMessage(
  encryptedMessage: string,
  senderPublicKey: string,
  recipientPrivateKey: string
): string {
  console.log("🔓 decryptMessage called with:", {
    encryptedLength: encryptedMessage.length,
    senderPubKeyLength: senderPublicKey.length,
    recipientPrivKeyLength: recipientPrivateKey.length,
  });
  console.log(
    "💾 Sender public key (first 20 chars):",
    senderPublicKey.substring(0, 20)
  );
  console.log(
    "💾 Recipient private key (first 20 chars):",
    recipientPrivateKey.substring(0, 20)
  );

  // DIAGNOSTIC: Derive public key from private key to verify key pair consistency
  const recipientPrivKeyBytes = decodeBase64(recipientPrivateKey);
  const derivedPublicKey = nacl.box.keyPair.fromSecretKey(
    recipientPrivKeyBytes
  ).publicKey;
  const derivedPubKeyB64 = encodeBase64(derivedPublicKey);
  console.log(
    "🔬 DIAGNOSTIC - Derived public key from private key (first 20):",
    derivedPubKeyB64.substring(0, 20)
  );

  const fullMessage = decodeBase64(encryptedMessage);
  console.log("📦 Decoded message length:", fullMessage.length, "bytes");

  const senderPubKey = decodeBase64(senderPublicKey);
  const recipientPrivKey = decodeBase64(recipientPrivateKey);

  console.log(
    "🔑 Decoded keys - sender pub:",
    senderPubKey.length,
    "recipient priv:",
    recipientPrivKey.length
  );

  // Extract nonce and encrypted message
  const nonce = fullMessage.slice(0, nacl.box.nonceLength);
  const encrypted = fullMessage.slice(nacl.box.nonceLength);

  console.log(
    "🎲 Nonce length:",
    nonce.length,
    "Encrypted data length:",
    encrypted.length
  );

  // Decrypt the message
  const decrypted = nacl.box.open(
    encrypted,
    nonce,
    senderPubKey,
    recipientPrivKey
  );

  if (!decrypted) {
    console.error("❌ nacl.box.open returned null - decryption failed");
    console.error(
      "💥 Key mismatch! The message was encrypted with different keys than we have now."
    );
    throw new Error("Failed to decrypt message");
  }

  console.log("✅ Decryption successful, message length:", decrypted.length);
  return decodeUTF8(decrypted);
}

/**
 * Encrypt private key with password for storage
 * Uses secret box (symmetric encryption) with key derived from password
 * @param privateKey - Private key to encrypt (base64)
 * @param password - User's password
 * @returns Encrypted private key (base64) with salt and nonce prepended
 */
export function encryptPrivateKey(
  privateKey: string,
  password: string
): string {
  const privKeyBytes = decodeBase64(privateKey);
  const salt = nacl.randomBytes(16);

  // Derive key from password using a simple hash (in production, use PBKDF2 or Argon2)
  // For now, we'll use nacl.hash to derive a key
  const passwordBytes = encodeUTF8(password);
  const saltedPassword = new Uint8Array(salt.length + passwordBytes.length);
  saltedPassword.set(salt);
  saltedPassword.set(passwordBytes, salt.length);
  const hashedKey = nacl
    .hash(saltedPassword)
    .slice(0, nacl.secretbox.keyLength);

  // Encrypt private key with derived key
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const encrypted = nacl.secretbox(privKeyBytes, nonce, hashedKey);

  // Prepend salt and nonce to encrypted key
  const fullData = new Uint8Array(
    salt.length + nonce.length + encrypted.length
  );
  fullData.set(salt);
  fullData.set(nonce, salt.length);
  fullData.set(encrypted, salt.length + nonce.length);

  return encodeBase64(fullData);
}

/**
 * Decrypt private key with password
 * @param encryptedPrivateKey - Encrypted private key (base64) with salt and nonce prepended
 * @param password - User's password
 * @returns Decrypted private key (base64)
 * @throws Error if decryption fails
 */
export function decryptPrivateKey(
  encryptedPrivateKey: string,
  password: string
): string {
  const fullData = decodeBase64(encryptedPrivateKey);

  // Extract salt, nonce, and encrypted key
  const salt = fullData.slice(0, 16);
  const nonce = fullData.slice(16, 16 + nacl.secretbox.nonceLength);
  const encrypted = fullData.slice(16 + nacl.secretbox.nonceLength);

  // Derive key from password using Argon2id (matching backend)
  const hashedKey = argon2id(password, salt, {
    t: 1, // iterations (time) - matches backend Argon2Time
    m: 65536, // memory in KiB - matches backend Argon2Memory (64 * 1024)
    p: 4, // parallelism - matches backend Argon2Threads
    dkLen: 32, // output key length - matches backend Argon2KeyLen
  });

  // Decrypt private key
  const decrypted = nacl.secretbox.open(encrypted, nonce, hashedKey);

  if (!decrypted) {
    throw new Error("Failed to decrypt private key - incorrect password?");
  }

  return encodeBase64(decrypted);
}

/**
 * Store private key in sessionStorage (encrypted with password)
 * @param deskId - Desk ID
 * @param privateKey - Private key (base64)
 */
export function storePrivateKey(deskId: string, privateKey: string): void {
  sessionStorage.setItem(`privateKey_${deskId}`, privateKey);
}

/**
 * Retrieve private key from sessionStorage
 * @param deskId - Desk ID
 * @returns Private key (base64) or null if not found
 */
export function getPrivateKey(deskId: string): string | null {
  return sessionStorage.getItem(`privateKey_${deskId}`);
}

/**
 * Clear private key from sessionStorage
 * @param deskId - Desk ID
 */
export function clearPrivateKey(deskId: string): void {
  sessionStorage.removeItem(`privateKey_${deskId}`);
}

/**
 * Clear all private keys from sessionStorage
 */
export function clearAllPrivateKeys(): void {
  const keys = Object.keys(sessionStorage);
  keys.forEach((key) => {
    if (key.startsWith("privateKey_")) {
      sessionStorage.removeItem(key);
    }
  });
}
