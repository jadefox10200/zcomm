import React, { useState, useEffect, useRef } from "react";
import { CKEditor } from "@ckeditor/ckeditor5-react";
import ClassicEditor from "@ckeditor/ckeditor5-build-classic";
import { CreateMivRequest, Contact, Desk } from "../types";
import * as api from "../api/client";
import { uploadPlugin } from "../utils/ckEditorUploadAdapter";
import { buildMessageWithTemplate } from "../utils/messageTemplate";
import "./ComposeMiv.css";

interface ComposeMivProps {
  onSend: (request: CreateMivRequest) => Promise<void>;
  onCancel: () => void;
  deskId: string;
  desk: Desk;
}

const ComposeMiv: React.FC<ComposeMivProps> = ({
  onSend,
  onCancel,
  deskId,
  desk,
}) => {
  const [to, setTo] = useState("");
  const [cc, setCc] = useState<string[]>([]);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<{
    to?: boolean;
    subject?: boolean;
    body?: boolean;
    cc?: number[]; // Array of indices for CC fields with errors
  }>({});
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [showContactDropdown, setShowContactDropdown] = useState(false);
  const [showCcDropdowns, setShowCcDropdowns] = useState<boolean[]>([]);
  const [contactSearchTerm, setContactSearchTerm] = useState("");
  const [ccSearchTerms, setCcSearchTerms] = useState<string[]>([]);
  const [showPreview, setShowPreview] = useState(false);
  const [templateInitialized, setTemplateInitialized] = useState(false);
  const [showContactModal, setShowContactModal] = useState(false);
  const [contactModalTarget, setContactModalTarget] = useState<
    "to" | { type: "cc"; index: number }
  >("to");
  const [contactModalSearch, setContactModalSearch] = useState("");
  const errorRef = useRef<HTMLDivElement>(null);

  // Scroll to error message when error occurs
  useEffect(() => {
    if (error && errorRef.current) {
      errorRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [error]);

  useEffect(() => {
    const loadContacts = async () => {
      try {
        const response = await api.listContacts(deskId);
        setContacts(response.contacts || []);
      } catch (err) {
        console.error("Failed to load contacts:", err);
      }
    };

    loadContacts();
  }, [deskId]);

  // Auto-insert salutation and signature when recipient is selected
  useEffect(() => {
    if (to && contacts.length > 0 && !templateInitialized) {
      const initialTemplate = buildMessageWithTemplate(
        desk.default_salutation || "",
        to,
        contacts,
        desk.default_closure || "",
        "<p><br></p>" // Empty paragraph for typing
      );
      setBody(initialTemplate);
      setTemplateInitialized(true);
    }
  }, [
    to,
    contacts,
    desk.default_salutation,
    desk.default_closure,
    templateInitialized,
  ]);

  // Reset template flag when recipient changes
  useEffect(() => {
    setTemplateInitialized(false);
  }, [to]);

  const filteredContacts = contacts.filter(
    (contact) =>
      contact.name.toLowerCase().includes(contactSearchTerm.toLowerCase()) ||
      contact.desk_id_ref.includes(contactSearchTerm.replace(/\D/g, ""))
  );

  const filteredCcContacts = (index: number) =>
    contacts.filter(
      (contact) =>
        contact.name
          .toLowerCase()
          .includes(ccSearchTerms[index]?.toLowerCase() || "") ||
        contact.desk_id_ref.includes(
          ccSearchTerms[index]?.replace(/\D/g, "") || ""
        )
    );

  const selectContact = (contact: Contact) => {
    setTo(contact.desk_id_ref);
    setContactSearchTerm(contact.name);
    setShowContactDropdown(false);
  };

  const selectCcContact = (contact: Contact, index: number) => {
    const newCc = [...cc];
    newCc[index] = contact.desk_id_ref;
    setCc(newCc);

    const newCcSearchTerms = [...ccSearchTerms];
    newCcSearchTerms[index] = contact.name;
    setCcSearchTerms(newCcSearchTerms);

    const newShowCcDropdowns = [...showCcDropdowns];
    newShowCcDropdowns[index] = false;
    setShowCcDropdowns(newShowCcDropdowns);
  };

  const openContactModal = (target: "to" | { type: "cc"; index: number }) => {
    setContactModalTarget(target);
    setContactModalSearch("");
    setShowContactModal(true);
  };

  const addCcField = () => {
    setCc([...cc, ""]);
    setCcSearchTerms([...ccSearchTerms, ""]);
    setShowCcDropdowns([...showCcDropdowns, false]);
  };

  const removeCcField = (index: number) => {
    const newCc = cc.filter((_, i) => i !== index);
    const newCcSearchTerms = ccSearchTerms.filter((_, i) => i !== index);
    const newShowCcDropdowns = showCcDropdowns.filter((_, i) => i !== index);
    setCc(newCc);
    setCcSearchTerms(newCcSearchTerms);
    setShowCcDropdowns(newShowCcDropdowns);
  };

  const updateCcField = (index: number, value: string) => {
    const newCc = [...cc];
    newCc[index] = value;
    setCc(newCc);
  };

  const updateCcSearchTerm = (index: number, value: string) => {
    const newCcSearchTerms = [...ccSearchTerms];
    newCcSearchTerms[index] = value;
    setCcSearchTerms(newCcSearchTerms);
  };

  const selectContactFromModal = (contact: Contact) => {
    if (contactModalTarget === "to") {
      setTo(contact.desk_id_ref);
      setContactSearchTerm(contact.name);
    } else if (
      typeof contactModalTarget === "object" &&
      contactModalTarget.type === "cc"
    ) {
      const index = contactModalTarget.index;
      const newCc = [...cc];
      newCc[index] = contact.desk_id_ref;
      setCc(newCc);

      const newCcSearchTerms = [...ccSearchTerms];
      newCcSearchTerms[index] = contact.name;
      setCcSearchTerms(newCcSearchTerms);
    }
    setShowContactModal(false);
  };

  const updateCcDropdownVisibility = (index: number, visible: boolean) => {
    const newShowCcDropdowns = [...showCcDropdowns];
    newShowCcDropdowns[index] = visible;
    setShowCcDropdowns(newShowCcDropdowns);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    // Reset field errors
    setFieldErrors({});

    if (!to || !subject || !body) {
      const newFieldErrors: any = {};
      if (!to) newFieldErrors.to = true;
      if (!subject) newFieldErrors.subject = true;
      if (!body) newFieldErrors.body = true;
      setFieldErrors(newFieldErrors);
      setError("All fields are required");
      return;
    }

    // Validate phone-style ID (10 digits)
    if (!/^\d{10}$/.test(to)) {
      setFieldErrors({ to: true });
      setError("Recipient ID must be a 10-digit number");
      return;
    }

    // Validate CC if provided
    if (cc.length > 0) {
      const ccErrors: number[] = [];
      for (let i = 0; i < cc.length; i++) {
        const ccRecipient = cc[i];
        if (ccRecipient && !/^\d{10}$/.test(ccRecipient)) {
          ccErrors.push(i);
        }
      }
      if (ccErrors.length > 0) {
        setFieldErrors({ cc: ccErrors });
        setError("All CC recipient IDs must be 10-digit numbers");
        return;
      }
    }

    setIsSending(true);
    setError(null);

    try {
      await onSend({
        to,
        cc: cc || undefined,
        subject,
        body,
        font_family: desk.font_family,
        font_size: desk.font_size,
      });
      // Reset form on success
      setTo("");
      setCc([]);
      setSubject("");
      setBody("");
      setTemplateInitialized(false);
      setContactSearchTerm("");
      setCcSearchTerms([]);
      setShowCcDropdowns([]);
    } catch (err) {
      console.error("Failed to send miv:", err);

      let errorMessage = "Failed to send miv. Please try again.";
      let newFieldErrors: any = {};

      if (err instanceof Error) {
        const errorText = err.message.toLowerCase();

        // Handle specific desk validation errors
        // Check CC errors first (more specific)
        if (
          errorText.includes("cc recipient desk") &&
          errorText.includes("does not exist")
        ) {
          // Extract the desk ID from the error message
          const deskIdMatch = err.message.match(/'([^']+)' does not exist/);
          const invalidDeskId = deskIdMatch ? deskIdMatch[1] : "";

          // Find which CC field contains this invalid ID
          // Compare normalized versions to handle any formatting differences
          const normalizedInvalidId = invalidDeskId.replace(/\D/g, "");
          const ccErrors: number[] = [];

          cc.forEach((ccRecipient, index) => {
            const normalizedCc = ccRecipient.replace(/\D/g, "");
            if (normalizedCc === normalizedInvalidId) {
              ccErrors.push(index);
            }
          });

          if (ccErrors.length > 0) {
            newFieldErrors.cc = ccErrors;
            errorMessage = `The CC recipient desk ID '${invalidDeskId}' is not found. Please use the contacts button to select valid CC recipients or remove this entry.`;
          } else {
            // If we can't find the specific field, highlight all CC fields
            console.warn(
              "Could not identify specific CC field with error, highlighting all CC fields"
            );
            const allCcIndices = cc
              .map((_, index) => index)
              .filter((index) => cc[index] && cc[index].trim() !== "");
            if (allCcIndices.length > 0) {
              newFieldErrors.cc = allCcIndices;
            }
            errorMessage = `The CC recipient desk ID '${invalidDeskId}' is not found. Please check your CC recipients.`;
          }
        } else if (
          errorText.includes("recipient desk") &&
          errorText.includes("does not exist")
        ) {
          errorMessage =
            "The recipient desk ID is not found. Please use the contacts button to select a valid recipient.";
          newFieldErrors.to = true;
        } else {
          // Use the backend error message for other cases
          errorMessage = err.message;
        }
      }

      setFieldErrors(newFieldErrors);
      setError(errorMessage);
    } finally {
      setIsSending(false);
    }
  };

  const formatPhoneId = (value: string) => {
    // Remove non-digits
    const digits = value.replace(/\D/g, "");

    // Format as XXXX-XX-XXXX
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

  const getRecipientDisplay = () => {
    if (contactSearchTerm) {
      return contactSearchTerm;
    }
    if (to) {
      // Check if this desk ID matches a contact
      const contact = contacts.find((c) => c.desk_id_ref === to);
      if (contact) {
        return contact.name;
      }
      return formatPhoneId(to);
    }
    return "";
  };

  const getCcDisplay = (index: number) => {
    if (ccSearchTerms[index]) {
      return ccSearchTerms[index];
    }
    if (cc[index]) {
      // Check if this desk ID matches a contact
      const contact = contacts.find((c) => c.desk_id_ref === cc[index]);
      if (contact) {
        return contact.name;
      }
      return formatPhoneId(cc[index]);
    }
    return "";
  };

  return (
    <div className="compose-miv">
      <div className="compose-header">
        <h2>Compose New Miv</h2>
      </div>

      <form onSubmit={handleSubmit} className="compose-form">
        {error && (
          <div ref={errorRef} className="error-message">
            {error}
          </div>
        )}

        <div className="form-group">
          <label htmlFor="to">To:</label>
          <div className="recipient-input-container">
            <input
              id="to"
              type="text"
              className={fieldErrors.to ? "error" : ""}
              value={getRecipientDisplay()}
              onChange={(e) => {
                setContactSearchTerm(e.target.value);
                setShowContactDropdown(true);
                // Clear field error when user starts typing
                if (fieldErrors.to) {
                  setFieldErrors((prev) => ({ ...prev, to: false }));
                }
                // If typing a phone number, also set the 'to' field
                const digits = e.target.value.replace(/\D/g, "");
                if (digits) {
                  setTo(digits.slice(0, 10));
                } else {
                  setTo("");
                }
              }}
              onFocus={() => setShowContactDropdown(true)}
              onBlur={() =>
                setTimeout(() => setShowContactDropdown(false), 200)
              }
              placeholder="Search contacts or enter 5551-23-4567"
              disabled={isSending}
              autoComplete="off"
            />
            <button
              type="button"
              className="contact-select-btn"
              onClick={() => openContactModal("to")}
              title="Select contact"
              disabled={isSending}
            >
              <i className="address book icon"></i>
            </button>
            {showContactDropdown && filteredContacts.length > 0 && (
              <div className="contact-dropdown">
                {filteredContacts.slice(0, 5).map((contact) => (
                  <div
                    key={contact.id}
                    className="contact-dropdown-item"
                    onClick={() => selectContact(contact)}
                  >
                    <div className="contact-dropdown-name">{contact.name}</div>
                    <div className="contact-dropdown-id">
                      {formatPhoneId(contact.desk_id_ref)}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
          <span className="help-text">
            {to && contactSearchTerm && `mivID: ${formatPhoneId(to)}`}
            {to && !contactSearchTerm && `Sending to: ${formatPhoneId(to)}`}
            {!to && "Search for a contact or enter a 10-digit ID"}
          </span>
        </div>

        <div className="form-group">
          <div className="cc-header">
            <label>CC: (Optional)</label>
            <button
              type="button"
              className="add-cc-btn"
              onClick={addCcField}
              title="Add CC recipient"
              disabled={isSending}
            >
              <i className="plus icon"></i>
            </button>
          </div>
          {cc.map((ccRecipient, index) => (
            <div key={index} className="cc-field">
              <div className="recipient-input-container">
                <input
                  type="text"
                  className={
                    fieldErrors.cc && fieldErrors.cc.includes(index)
                      ? "error"
                      : ""
                  }
                  value={getCcDisplay(index)}
                  onChange={(e) => {
                    updateCcSearchTerm(index, e.target.value);
                    updateCcDropdownVisibility(index, true);
                    // Clear field error when user starts typing
                    if (fieldErrors.cc && fieldErrors.cc.includes(index)) {
                      setFieldErrors((prev) => ({
                        ...prev,
                        cc: prev.cc ? prev.cc.filter((i) => i !== index) : [],
                      }));
                    }
                    // If typing a phone number, also set the 'cc' field
                    const digits = e.target.value.replace(/\D/g, "");
                    if (digits) {
                      updateCcField(index, digits.slice(0, 10));
                    } else {
                      updateCcField(index, "");
                    }
                  }}
                  onFocus={() => updateCcDropdownVisibility(index, true)}
                  onBlur={() =>
                    setTimeout(
                      () => updateCcDropdownVisibility(index, false),
                      200
                    )
                  }
                  placeholder="Search contacts or enter 5551-23-4567"
                  disabled={isSending}
                  autoComplete="off"
                />
                <button
                  type="button"
                  className="contact-select-btn"
                  onClick={() => openContactModal({ type: "cc", index })}
                  title="Select contact"
                  disabled={isSending}
                >
                  <i className="address book icon"></i>
                </button>
                <button
                  type="button"
                  className="remove-cc-btn"
                  onClick={() => removeCcField(index)}
                  title="Remove CC recipient"
                  disabled={isSending}
                >
                  <i className="minus icon"></i>
                </button>
                {showCcDropdowns[index] &&
                  filteredCcContacts(index).length > 0 && (
                    <div className="contact-dropdown">
                      {filteredCcContacts(index)
                        .slice(0, 5)
                        .map((contact) => (
                          <div
                            key={contact.id}
                            className="contact-dropdown-item"
                            onClick={() => selectCcContact(contact, index)}
                          >
                            <div className="contact-dropdown-name">
                              {contact.name}
                            </div>
                            <div className="contact-dropdown-id">
                              {formatPhoneId(contact.desk_id_ref)}
                            </div>
                          </div>
                        ))}
                    </div>
                  )}
              </div>
              <span className="help-text">
                {cc[index] &&
                  ccSearchTerms[index] &&
                  `CC mivID: ${formatPhoneId(cc[index])}`}
                {cc[index] &&
                  !ccSearchTerms[index] &&
                  `CC to: ${formatPhoneId(cc[index])}`}
                {!cc[index] && "Optional CC recipient"}
              </span>
            </div>
          ))}
        </div>

        <div className="form-group">
          <label htmlFor="subject">Subject:</label>
          <input
            id="subject"
            type="text"
            className={fieldErrors.subject ? "error" : ""}
            value={subject}
            onChange={(e) => {
              setSubject(e.target.value);
              // Clear field error when user starts typing
              if (fieldErrors.subject) {
                setFieldErrors((prev) => ({ ...prev, subject: false }));
              }
            }}
            placeholder="Enter subject"
            disabled={isSending}
          />
        </div>

        <div className="form-group">
          <label htmlFor="body">Message:</label>
          <div className="editor-container">
            <CKEditor
              editor={ClassicEditor as any}
              config={
                {
                  extraPlugins: [uploadPlugin],
                  toolbar: {
                    items: [
                      "undo",
                      "redo",
                      "|",
                      "heading",
                      "|",
                      "bold",
                      "italic",
                      "underline",
                      "strikethrough",
                      "|",
                      "code",
                      "subscript",
                      "superscript",
                      "|",
                      "link",
                      "insertTable",
                      "imageUpload",
                      "mediaEmbed",
                      "|",
                      "bulletedList",
                      "numberedList",
                      "|",
                      "blockQuote",
                      "horizontalLine",
                    ],
                  },
                  image: {
                    toolbar: [
                      "imageStyle:alignLeft",
                      "imageStyle:alignCenter",
                      "imageStyle:alignRight",
                      "|",
                      "resizeImage",
                    ],
                  },
                  heading: {
                    options: [
                      {
                        model: "paragraph",
                        title: "Paragraph",
                        class: "ck-heading_paragraph",
                      },
                      {
                        model: "heading1",
                        view: "h1",
                        title: "Heading 1",
                        class: "ck-heading_heading1",
                      },
                      {
                        model: "heading2",
                        view: "h2",
                        title: "Heading 2",
                        class: "ck-heading_heading2",
                      },
                      {
                        model: "heading3",
                        view: "h3",
                        title: "Heading 3",
                        class: "ck-heading_heading3",
                      },
                    ],
                  },
                  placeholder: "Enter your message...",
                } as any
              }
              data={body}
              disabled={isSending}
              onChange={(event, editor) => {
                const data = editor.getData();
                setBody(data);
              }}
            />
          </div>
        </div>

        <div className="form-actions">
          <button
            type="button"
            onClick={onCancel}
            className="btn btn-secondary"
            disabled={isSending}
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={() => setShowPreview(true)}
            className="btn btn-preview"
            disabled={isSending || !body}
          >
            👁️ Preview
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={isSending}
          >
            {isSending ? "Sending..." : "Send Miv"}
          </button>
        </div>
      </form>

      {showPreview && (
        <div className="preview-overlay" onClick={() => setShowPreview(false)}>
          <div className="preview-modal" onClick={(e) => e.stopPropagation()}>
            <div className="preview-header">
              <h3>Message Preview</h3>
              <button
                className="close-button"
                onClick={() => setShowPreview(false)}
              >
                ×
              </button>
            </div>
            <div className="preview-content">
              <div className="preview-header-info">
                <div className="preview-header-left">
                  <div className="preview-field">
                    <span className="preview-field-label">To:</span>
                    <span className="preview-field-value">
                      {contacts.find((c) => c.desk_id_ref === to)?.name ||
                        formatPhoneId(to)}
                    </span>
                  </div>
                  <div className="preview-field">
                    <span className="preview-field-label">From:</span>
                    <span className="preview-field-value">{desk.name}</span>
                  </div>
                </div>
                <div className="preview-header-right">
                  <div className="preview-field">
                    <span className="preview-field-value">
                      {new Date().toLocaleDateString("en-US", {
                        year: "numeric",
                        month: "short",
                        day: "numeric",
                      })}
                    </span>
                  </div>
                  <div className="preview-field preview-sequence">
                    <span className="preview-field-value">Message #1</span>
                  </div>
                  {cc.length > 0 && (
                    <div className="preview-cc-list">
                      {cc.map((ccRecipient, index) => (
                        <div key={index} className="preview-cc-item">
                          <span className="preview-cc-label">cc:</span>
                          <span className="preview-cc-value">
                            {contacts.find((c) => c.desk_id_ref === ccRecipient)
                              ?.name || formatPhoneId(ccRecipient)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div
                className="epistle-preview"
                style={{
                  fontFamily: desk?.font_family || "Georgia, serif",
                  fontSize: desk?.font_size || "14px",
                }}
              >
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
              <button
                className="btn btn-secondary"
                onClick={() => setShowPreview(false)}
              >
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Contact Selection Modal */}
      {showContactModal && (
        <div
          className="modal-overlay"
          onClick={() => setShowContactModal(false)}
        >
          <div
            className="modal-content contact-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-header">
              <h3>Select Contact</h3>
              <button
                className="modal-close"
                onClick={() => setShowContactModal(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <input
                type="text"
                placeholder="Search contacts..."
                value={contactModalSearch}
                onChange={(e) => setContactModalSearch(e.target.value)}
                className="contact-search-input"
                autoFocus
              />
              <div className="contact-list">
                {contacts
                  .filter(
                    (contact) =>
                      contact.name
                        .toLowerCase()
                        .includes(contactModalSearch.toLowerCase()) ||
                      contact.id.toString().includes(contactModalSearch)
                  )
                  .map((contact) => (
                    <div
                      key={contact.id}
                      className="contact-item"
                      onClick={() => selectContactFromModal(contact)}
                    >
                      <div className="contact-info">
                        <div className="contact-name">{contact.name}</div>
                        <div className="contact-id">
                          mivID: {formatPhoneId(contact.desk_id_ref)}
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ComposeMiv;
