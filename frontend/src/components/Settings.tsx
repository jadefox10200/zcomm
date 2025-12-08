import React, { useState } from "react";
import { Desk, UpdateDeskRequest } from "../types";
import * as api from "../api/client";
import { parseClosureAndSignature } from "../utils/messageTemplate";
import "./Settings.css";

interface SettingsProps {
  desk: Desk;
  onClose: () => void;
  onDeskUpdated: (desk: Desk) => void;
}

const Settings: React.FC<SettingsProps> = ({
  desk,
  onClose,
  onDeskUpdated,
}) => {
  const [deskName, setDeskName] = useState(desk.name);
  const [autoIndent, setAutoIndent] = useState(desk.auto_indent ?? false);
  const [fontFamily, setFontFamily] = useState(
    desk.font_family || "Georgia, serif"
  );
  const [fontSize, setFontSize] = useState(desk.font_size || "14px");
  const [defaultSalutation, setDefaultSalutation] = useState(
    desk.default_salutation || "Dear [User],"
  );

  // Parse closure and signature from default_closure
  const initialParsed = parseClosureAndSignature(
    desk.default_closure || "Sincerely,"
  );
  const [closure, setClosure] = useState(initialParsed.closure);
  const [signature, setSignature] = useState(initialParsed.signature);

  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setError(null);
    setSuccessMessage(null);

    try {
      // Combine closure and signature with double newline separator
      const combinedClosure = signature
        ? `${closure}\n\n${signature}`
        : closure;

      const request: UpdateDeskRequest = {
        name: deskName,
        auto_indent: autoIndent,
        font_family: fontFamily,
        font_size: fontSize,
        default_salutation: defaultSalutation,
        default_closure: combinedClosure,
      };

      const updatedDesk = await api.updateDesk(desk.id, request);
      onDeskUpdated(updatedDesk);
      setSuccessMessage("Settings saved successfully!");
      // Close the dialog after successful save
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to save settings");
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="settings-overlay" onClick={onClose}>
      <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
        <div className="settings-header">
          <h2>Settings</h2>
          <button className="close-button" onClick={onClose}>
            ×
          </button>
        </div>

        <form onSubmit={handleSave} className="settings-form">
          {error && <div className="error-message">{error}</div>}
          {successMessage && (
            <div className="success-message">{successMessage}</div>
          )}

          <div className="settings-section">
            <h3>Desk Settings</h3>

            <div className="form-group">
              <label htmlFor="deskName">Desk Name</label>
              <input
                id="deskName"
                type="text"
                value={deskName}
                onChange={(e) => setDeskName(e.target.value)}
                placeholder="Enter desk name"
                disabled={isSaving}
              />
            </div>
          </div>

          <div className="settings-section">
            <h3>Rendering Settings</h3>

            <div className="form-group checkbox-group">
              <label>
                <input
                  type="checkbox"
                  checked={autoIndent}
                  onChange={(e) => setAutoIndent(e.target.checked)}
                  disabled={isSaving}
                />
                <span>Auto-indent paragraphs (epistle-style)</span>
              </label>
              <p className="help-text">
                When enabled, paragraphs will be automatically indented for a
                classic letter format
              </p>
            </div>
          </div>

          <div className="settings-section">
            <h3>Typography</h3>

            <div className="form-group">
              <label htmlFor="fontFamily">Font Family</label>
              <select
                id="fontFamily"
                value={fontFamily}
                onChange={(e) => setFontFamily(e.target.value)}
                disabled={isSaving}
              >
                <option value="Georgia, serif">Georgia (Serif)</option>
                <option value="Times New Roman, serif">
                  Times New Roman (Serif)
                </option>
                <option value="Garamond, serif">Garamond (Serif)</option>
                <option value="Arial, sans-serif">Arial (Sans-serif)</option>
                <option value="Helvetica, sans-serif">
                  Helvetica (Sans-serif)
                </option>
                <option value="Verdana, sans-serif">
                  Verdana (Sans-serif)
                </option>
                <option value="Courier New, monospace">
                  Courier New (Monospace)
                </option>
              </select>
            </div>

            <div className="form-group">
              <label htmlFor="fontSize">Font Size</label>
              <select
                id="fontSize"
                value={fontSize}
                onChange={(e) => setFontSize(e.target.value)}
                disabled={isSaving}
              >
                <option value="12px">12px (Small)</option>
                <option value="14px">14px (Medium)</option>
                <option value="16px">16px (Large)</option>
                <option value="18px">18px (Extra Large)</option>
              </select>
            </div>
          </div>

          <div className="settings-section">
            <h3>Default Message Templates</h3>

            <div className="form-group">
              <label htmlFor="defaultSalutation">Default Salutation</label>
              <input
                id="defaultSalutation"
                type="text"
                value={defaultSalutation}
                onChange={(e) => setDefaultSalutation(e.target.value)}
                placeholder="e.g., Dear [User],"
                disabled={isSaving}
              />
              <p className="help-text">
                Use [User] as a placeholder for the recipient's name
              </p>
            </div>

            <div className="form-group">
              <label htmlFor="closure">Default Closure</label>
              <input
                id="closure"
                type="text"
                value={closure}
                onChange={(e) => setClosure(e.target.value)}
                placeholder="e.g., Best Regards,"
                disabled={isSaving}
              />
              <p className="help-text">
                The closing phrase for your messages (e.g., "Sincerely,", "Best
                Regards,")
              </p>
            </div>

            <div className="form-group">
              <label htmlFor="signature">Default Signature</label>
              <textarea
                id="signature"
                value={signature}
                onChange={(e) => setSignature(e.target.value)}
                placeholder="e.g., Your Name&#10;Your Title&#10;Your Address"
                rows={4}
                disabled={isSaving}
              />
              <p className="help-text">
                Your signature block (name, title, contact info, etc.)
              </p>
            </div>
          </div>

          <div className="settings-actions">
            <button
              type="button"
              onClick={onClose}
              className="btn btn-secondary"
              disabled={isSaving}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isSaving}
            >
              {isSaving ? "Saving..." : "Save Settings"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Settings;
