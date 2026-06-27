import React, { useState } from "react";
import "./UnlockKeysModal.css";

interface Props {
  encryptedKeys: Record<string, string>;
  onUnlock: (password: string) => Promise<boolean>;
  onCancel: () => void;
}

export default function UnlockKeysModal({ encryptedKeys, onUnlock, onCancel }: Props) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleUnlock = async () => {
    setError(null);
    setLoading(true);
    try {
      const ok = await onUnlock(password);
      if (!ok) {
        setError("Incorrect password — please try again.");
        setLoading(false);
      }
    } catch (e) {
      setError("Failed to unlock keys");
      setLoading(false);
    }
  };

  return (
    <div className="unlock-overlay">
      <div className="unlock-modal">
        <h3>Unlock encryption keys</h3>
        <p>Enter your account password to restore encrypted private keys.</p>
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleUnlock()}
          autoFocus
        />
        {error && <div className="unlock-error">{error}</div>}
        <div className="unlock-actions">
          <button className="btn" onClick={onCancel} disabled={loading}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={handleUnlock} disabled={loading}>
            {loading ? "Unlocking..." : "Unlock"}
          </button>
        </div>
      </div>
    </div>
  );
}
