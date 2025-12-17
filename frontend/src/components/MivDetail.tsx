import React, { useState, useEffect } from "react";
import { Miv } from "../types";
import "./MivDetail.css";
import * as api from "../api/client";

interface MivDetailProps {
  miv: Miv | null;
  currentDeskId: string;
  onArchive?: (miv: Miv) => void;
}

const MivDetail: React.FC<MivDetailProps> = ({
  miv,
  currentDeskId,
  onArchive,
}) => {
  const [decryptedBody, setDecryptedBody] = useState<string | null>(null);
  const [decryptionError, setDecryptionError] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);

  // Decrypt message when miv changes
  useEffect(() => {
    const decryptMessage = async () => {
      if (!miv || !miv.is_encrypted) {
        setDecryptedBody(null);
        setDecryptionError(null);
        return;
      }

      setIsDecrypting(true);
      setDecryptionError(null);

      try {
        // Import crypto utilities
        const { getPrivateKey, decryptMessage: decrypt } = await import(
          "../utils/crypto"
        );

        // Get recipient's private key (current desk's private key)
        const recipientPrivateKey = getPrivateKey(currentDeskId);
        if (!recipientPrivateKey) {
          throw new Error("Private key not found. Please log in again.");
        }

        // Determine the sender (the other party in the conversation)
        const senderId = miv.from === currentDeskId ? miv.to : miv.from;

        // Fetch sender's public key
        const senderPublicKeyResponse = await api.getDeskPublicKey(senderId);
        const senderPublicKey = senderPublicKeyResponse.public_key;

        // Decrypt the message body
        const decrypted = decrypt(
          miv.body,
          senderPublicKey,
          recipientPrivateKey
        );
        setDecryptedBody(decrypted);
        console.log("✓ Message decrypted successfully");
      } catch (error) {
        console.error("Decryption failed:", error);
        setDecryptionError(
          error instanceof Error ? error.message : "Failed to decrypt message"
        );
        setDecryptedBody(null);
      } finally {
        setIsDecrypting(false);
      }
    };

    decryptMessage();
  }, [miv, currentDeskId]);

  if (!miv) {
    return (
      <div className="miv-detail empty">
        <div className="empty-message">
          <p>Select a miv to view</p>
        </div>
      </div>
    );
  }

  const formatPhoneId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  const formatFullDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const decodeBody = (body: string) => {
    // If message is encrypted, show decrypted body or error
    if (miv.is_encrypted) {
      if (isDecrypting) {
        return "Decrypting message...";
      }
      if (decryptionError) {
        return `[Unable to decrypt: ${decryptionError}]`;
      }
      if (decryptedBody) {
        // Decrypted body is plain text, decode base64 if needed
        try {
          return atob(decryptedBody);
        } catch (e) {
          return decryptedBody;
        }
      }
      return "Decrypting...";
    }

    // For unencrypted messages, decode normally
    try {
      return atob(body);
    } catch (e) {
      return body;
    }
  };

  return (
    <div className="miv-detail">
      <div className="miv-detail-header">
        <div className="miv-detail-subject">{miv.subject}</div>
        <div className="miv-detail-meta">
          <span className={`state-badge state-${miv.state.toLowerCase()}`}>
            {miv.state}
          </span>
        </div>
      </div>

      <div className="miv-detail-info">
        <div className="info-row">
          <span className="info-label">From:</span>
          <span className="info-value">{formatPhoneId(miv.from)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">To:</span>
          <span className="info-value">{formatPhoneId(miv.to)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Date:</span>
          <span className="info-value">{formatFullDate(miv.created_at)}</span>
        </div>
        {miv.sent_at && (
          <div className="info-row">
            <span className="info-label">Sent:</span>
            <span className="info-value">{formatFullDate(miv.sent_at)}</span>
          </div>
        )}
        {miv.received_at && (
          <div className="info-row">
            <span className="info-label">Received:</span>
            <span className="info-value">
              {formatFullDate(miv.received_at)}
            </span>
          </div>
        )}
      </div>

      <div className="miv-detail-body">
        {miv.is_encrypted && (
          <div
            className="encryption-indicator"
            style={{
              fontSize: "0.85em",
              color: "#666",
              marginBottom: "10px",
              fontStyle: "italic",
            }}
          >
            🔒 End-to-end encrypted
          </div>
        )}
        {decodeBody(miv.body)}
      </div>

      {onArchive && miv.state !== "ARCHIVED" && (
        <div className="miv-detail-actions">
          <button onClick={() => onArchive(miv)} className="btn btn-secondary">
            Archive
          </button>
        </div>
      )}
    </div>
  );
};

export default MivDetail;
