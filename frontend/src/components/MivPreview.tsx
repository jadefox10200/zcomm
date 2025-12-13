import React from "react";
import { Contact, Desk } from "../types";
import "./MivPreview.css";

interface MivPreviewProps {
  to: string;
  via?: string[];
  cc?: string[];
  from: string;
  subject: string;
  body: string;
  sequenceNumber: number;
  date?: Date;
  contacts: Contact[];
  desk: Desk;
  onClose: () => void;
}

const MivPreview: React.FC<MivPreviewProps> = ({
  to,
  via,
  cc,
  from,
  subject,
  body,
  sequenceNumber,
  date = new Date(),
  contacts,
  desk,
  onClose,
}) => {
  const formatPhoneId = (value: string) => {
    const digits = value.replace(/\D/g, "");

    if (digits.length <= 4) {
      return digits;
    } else if (digits.length <= 6) {
      return `${digits.slice(0, 4)}-${digits.slice(4)}`;
    } else {
      return `${digits.slice(0, 4)}-${digits.slice(4, 6)}-${digits.slice(
        6,
        10
      )}`;
    }
  };

  const getContactName = (deskId: string) => {
    const contact = contacts.find((c) => c.desk_id_ref === deskId);
    return contact?.name || formatPhoneId(deskId);
  };

  return (
    <div className="preview-overlay" onClick={onClose}>
      <div className="preview-modal" onClick={(e) => e.stopPropagation()}>
        <div className="preview-header">
          <h3>Message Preview</h3>
          <button className="close-button" onClick={onClose}>
            ×
          </button>
        </div>
        <div className="preview-content">
          <div
            className="epistle-preview"
            style={
              {
                fontFamily: desk?.font_family || "Georgia, serif",
                fontSize: desk?.font_size || "14px",
                "--preview-line-height": desk?.line_height || "1.65",
              } as React.CSSProperties
            }
          >
            <div className="preview-header-info">
              <div className="preview-header-left">
                <div className="preview-field">
                  <span className="preview-field-label">To:</span>
                  <span className="preview-field-value">
                    {getContactName(to)}
                  </span>
                </div>
                {via && via.length > 0 && (
                  <div className="preview-field">
                    <span className="preview-field-label">Via:</span>
                    <span className="preview-field-value">
                      {via.map((v) => getContactName(v)).join(" ← ")}
                    </span>
                  </div>
                )}
                <div className="preview-field">
                  <span className="preview-field-label">From:</span>
                  <span className="preview-field-value">{from}</span>
                </div>
              </div>
              <div className="preview-header-right">
                <div className="preview-field">
                  <span className="preview-field-value">
                    {date.toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "short",
                      day: "numeric",
                    })}
                  </span>
                </div>
                <div className="preview-field preview-sequence">
                  <span className="preview-field-value">
                    Message #{sequenceNumber}
                  </span>
                </div>
                {cc && cc.length > 0 && (
                  <div className="preview-cc-list">
                    {cc.map((ccRecipient, index) => (
                      <div key={index} className="preview-cc-item">
                        <span className="preview-cc-label">cc:</span>
                        <span className="preview-cc-value">
                          {getContactName(ccRecipient)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="preview-subject">
              <h2>{subject || "(No subject)"}</h2>
            </div>
            <div
              className={`preview-body ${
                desk?.auto_indent ? "auto-indent" : ""
              }`}
              dangerouslySetInnerHTML={{
                __html: body || "<p>(No message)</p>",
              }}
            />
          </div>
        </div>
        <div className="preview-actions">
          <button className="btn btn-secondary" onClick={onClose}>
            Close Preview
          </button>
        </div>
      </div>
    </div>
  );
};

export default MivPreview;
