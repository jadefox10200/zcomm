import React, { useState, useEffect } from "react";
import { CKEditor } from "@ckeditor/ckeditor5-react";
import ClassicEditor from "@ckeditor/ckeditor5-build-classic";
import {
  ConversationMiv,
  GetConversationResponse,
  Contact,
  Desk,
} from "../types";
import * as api from "../api/client";
import { uploadPlugin } from "../utils/ckEditorUploadAdapter";
import { parseClosureAndSignature } from "../utils/messageTemplate";
import "./MivDetailWithContext.css";

interface MivDetailWithContextProps {
  miv: ConversationMiv;
  currentDeskId: string;
  currentDesk: Desk;
  onReply: (body: string, isAck?: boolean) => void;
  onForget?: () => void; // Callback when miv is forgotten
  onDeleteCc?: (conversationId: string) => void; // Callback when CC recipient deletes
  onBack?: () => void; // Callback to go back to basket view
}

function MivDetailWithContext({
  miv,
  currentDeskId,
  currentDesk,
  onReply,
  onForget,
  onDeleteCc,
  onBack,
}: MivDetailWithContextProps) {
  const [conversation, setConversation] =
    useState<GetConversationResponse | null>(null);
  const [selectedMiv, setSelectedMiv] = useState<ConversationMiv>(miv);
  const [replyBody, setReplyBody] = useState("");
  const [showReply, setShowReply] = useState(false);
  const [showAckConfirm, setShowAckConfirm] = useState(false);
  const [ackBody, setAckBody] = useState("");
  const [showForgetConfirm, setShowForgetConfirm] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [showPreview, setShowPreview] = useState(false);
  const [loading, setLoading] = useState(true);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [showAddContactModal, setShowAddContactModal] = useState(false);
  const [newContactName, setNewContactName] = useState("");
  const [newContactDeskId, setNewContactDeskId] = useState("");

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [convResponse, contactsResponse] = await Promise.all([
          api.getConversation(miv.conversation_id),
          api.listContacts(currentDeskId),
        ]);
        setConversation(convResponse);
        setContacts(contactsResponse.contacts || []);
        // Find the current miv in the conversation
        const mivArray = convResponse.mivs || [];
        const currentMiv = mivArray.find((m) => m.id === miv.id) || miv;
        setSelectedMiv(currentMiv);

        // Mark message as read (move from IN/CC to PENDING) if it's currently in IN or CC state
        if (currentMiv.state === "IN" || currentMiv.state === "CC") {
          try {
            const updatedMiv = await api.markMivAsRead(
              currentMiv.id,
              currentDeskId
            );
            // Update local state to reflect the change
            setSelectedMiv(updatedMiv);
            // Also update in conversation if it exists
            if (convResponse.mivs) {
              const updatedMivs = convResponse.mivs.map((m) =>
                m.id === currentMiv.id ? updatedMiv : m
              );
              setConversation({ ...convResponse, mivs: updatedMivs });
            }
          } catch (err) {
            console.error("Failed to mark message as read:", err);
          }
        }
      } catch (err) {
        console.error("Failed to load data:", err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [miv, currentDeskId]);

  const handleMivClick = (clickedMiv: ConversationMiv) => {
    setSelectedMiv(clickedMiv);
  };

  const handleShowReply = () => {
    // Auto-load salutation and closure for replies (not ACK)
    const salutationTemplate =
      currentDesk?.default_salutation || "Dear [User],";
    const closureStr = currentDesk?.default_closure || "Sincerely,";

    // Find the recipient (the person we're replying to)
    const recipientDeskId =
      selectedMiv.from === currentDeskId ? selectedMiv.to : selectedMiv.from;

    // Find contact info for proper name lookup (same logic as compose)
    const contact = contacts.find((c) => c.desk_id_ref === recipientDeskId);
    let recipientName = "Sir/Madam";
    if (contact) {
      recipientName =
        contact.greeting_name || contact.first_name || contact.name;
    }

    // Replace [User] placeholder with the recipient's greeting name
    const salutation = salutationTemplate.replace(/\[User\]/gi, recipientName);

    // Parse closure and signature
    const { closure, signature } = parseClosureAndSignature(closureStr);

    // Build HTML content like the compose view
    const parts = [];
    parts.push(`<p>${salutation}</p>`);
    parts.push("<p><br></p>"); // Empty paragraph for content
    if (signature) {
      const signatureHtml = signature
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line)
        .join("<br>");
      parts.push(`<p>${closure}</p>`);
      parts.push(`<p>${signatureHtml}</p>`);
    } else {
      parts.push(`<p>${closure}</p>`);
    }

    const initialContent = parts.join("");
    setReplyBody(initialContent);
    setShowReply(true);
  };

  const handleReplySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!replyBody.trim()) return;

    // Optimistically add the reply to local state
    const recipientId =
      selectedMiv.from === currentDeskId ? selectedMiv.to : selectedMiv.from;
    const optimisticMiv: ConversationMiv = {
      id: `temp-${Date.now()}`,
      conversation_id: selectedMiv.conversation_id,
      seq_no: conversation ? (conversation.mivs || []).length + 1 : 1,
      from: currentDeskId,
      to: recipientId,
      arrow_to: recipientId,
      type: "MIV",
      subject: selectedMiv.subject,
      body: btoa(replyBody),
      state: "SENT" as any,
      created_at: new Date().toISOString(),
      is_encrypted: false,
      is_ack: false,
      is_forgotten: false,
      font_family: currentDesk?.font_family,
      font_size: currentDesk?.font_size,
    };

    // Update conversation immediately
    if (conversation) {
      const currentMivs = conversation.mivs || [];
      setConversation({
        ...conversation,
        mivs: [...currentMivs, optimisticMiv],
      });
    }

    setReplyBody("");
    setShowReply(false);

    // Then sync with server in background
    try {
      await onReply(replyBody, false);
      // Reload conversation to get the real data from server
      const updatedConv = await api.getConversation(
        selectedMiv.conversation_id
      );
      setConversation(updatedConv);
    } catch (err) {
      console.error("Failed to send reply:", err);
      // Revert optimistic update on error
      if (conversation) {
        const currentMivs = conversation.mivs || [];
        setConversation({
          ...conversation,
          mivs: currentMivs.filter((m) => m.id !== optimisticMiv.id),
        });
      }
      alert("Failed to send reply. Please try again.");
    }
  };

  const handleAck = async () => {
    const messageToSend = ackBody.trim() || "ACK - Conversation ended";
    // Optimistically add ACK to local state
    const recipientId =
      selectedMiv.from === currentDeskId ? selectedMiv.to : selectedMiv.from;
    const optimisticAck: ConversationMiv = {
      id: `temp-ack-${Date.now()}`,
      conversation_id: selectedMiv.conversation_id,
      seq_no: conversation ? (conversation.mivs || []).length + 1 : 1,
      from: currentDeskId,
      to: recipientId,
      arrow_to: recipientId,
      type: "MIV",
      subject: selectedMiv.subject,
      body: btoa(messageToSend),
      state: "SENT" as any,
      created_at: new Date().toISOString(),
      is_encrypted: false,
      is_ack: true,
      is_forgotten: false,
      font_family: currentDesk?.font_family,
      font_size: currentDesk?.font_size,
    };

    // Update conversation immediately
    if (conversation) {
      const currentMivs = conversation.mivs || [];
      setConversation({
        ...conversation,
        mivs: [...currentMivs, optimisticAck],
      });
    }

    setShowAckConfirm(false);
    setAckBody("");

    // Then sync with server in background
    try {
      await onReply(messageToSend, true);
      // Reload conversation to get the real data from server
      const updatedConv = await api.getConversation(
        selectedMiv.conversation_id
      );
      setConversation(updatedConv);
    } catch (err) {
      console.error("Failed to send ACK:", err);
      // Revert optimistic update on error
      if (conversation) {
        const currentMivs = conversation.mivs || [];
        setConversation({
          ...conversation,
          mivs: currentMivs.filter((m) => m.id !== optimisticAck.id),
        });
      }
      alert("Failed to send ACK. Please try again.");
    }
  };

  const handleForget = async () => {
    try {
      await api.forgetMiv(selectedMiv.id);
      setShowForgetConfirm(false);
      // Call the callback to refresh the parent view
      if (onForget) {
        onForget();
      }
      alert("Message forgotten. It will no longer appear in your SENT basket.");
    } catch (err) {
      console.error("Failed to forget miv:", err);
      alert("Failed to forget message. Please try again.");
    }
  };

  const handleDelete = async () => {
    try {
      await api.archiveConversation(selectedMiv.conversation_id);
      setShowDeleteConfirm(false);
      // Call the callback to refresh the parent view
      if (onForget) {
        onForget();
      }
      alert("Conversation archived successfully.");
    } catch (err) {
      console.error("Failed to archive conversation:", err);
      alert("Failed to archive conversation. Please try again.");
    }
  };

  const handleDeleteCc = async () => {
    try {
      await api.forgetMiv(selectedMiv.id);
      // Call the callback to refresh the parent view
      if (onForget) {
        onForget();
      }
    } catch (err) {
      console.error("Failed to remove CC miv:", err);
      alert("Failed to remove message. Please try again.");
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
      hour: "numeric",
      minute: "2-digit",
    });
  };

  const formatPhoneId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  const normalizeDeskId = (id: string) => {
    return id.replace(/\D/g, ""); // Remove all non-digits
  };

  const getDisplayName = (deskIdRef: string) => {
    const contact = contacts.find((c) => c.desk_id_ref === deskIdRef);
    const formattedId = formatPhoneId(deskIdRef);
    if (contact) {
      return `${contact.name} @ ${formattedId}`;
    }
    return formattedId;
  };

  const isContact = (deskIdRef: string) => {
    const normalizedId = normalizeDeskId(deskIdRef);
    return contacts.some((c) => c.desk_id_ref === normalizedId);
  };

  const isOwnDeskId = (deskIdRef: string) => {
    const normalizedId = normalizeDeskId(deskIdRef);
    return normalizedId === currentDeskId;
  };

  const handleAddContact = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newContactName.trim() || !newContactDeskId) return;

    try {
      await api.createContact(currentDeskId, {
        name: newContactName.trim(),
        desk_id_ref: newContactDeskId, // This is already normalized
        notes: "",
      });

      // Reload contacts
      const contactsResponse = await api.listContacts(currentDeskId);
      setContacts(contactsResponse.contacts || []);

      // Close modal
      setShowAddContactModal(false);
      setNewContactName("");
      setNewContactDeskId("");
    } catch (err) {
      console.error("Failed to add contact:", err);
      alert("Failed to add contact. Please try again.");
    }
  };

  const openAddContactModal = (displayString: string) => {
    const normalizedId = normalizeDeskId(displayString);
    setNewContactDeskId(normalizedId);
    setNewContactName("");
    setShowAddContactModal(true);
  };

  if (loading || !conversation) {
    return (
      <div className="miv-detail-with-context">
        <div className="loading">Loading conversation...</div>
      </div>
    );
  }

  return (
    <div className="miv-detail-with-context">
      {/* Back button - shows on desktop when viewing a miv */}
      {onBack && (
        <div className="miv-back-button-container">
          <button className="miv-back-button" onClick={onBack}>
            ← Back to Basket
          </button>
        </div>
      )}

      {/* Conversation thread icons - keep at top */}
      <div className="thread-context">
        <div className="thread-header">
          <h3>Conversation Thread</h3>
          <span className="thread-count">
            {(conversation.mivs || []).length} messages
          </span>
        </div>
        <div className="thread-icons">
          {(conversation.mivs || []).map((m, index) => (
            <div
              key={m.id}
              className={`thread-icon ${
                m.id === selectedMiv.id ? "active" : ""
              } ${m.from === currentDeskId ? "outgoing" : "incoming"}`}
              onClick={() => handleMivClick(m)}
              title={`Message #${m.seq_no} - ${
                m.from === currentDeskId ? "You" : formatPhoneId(m.from)
              }`}
            >
              <span className="icon-number">{m.seq_no}</span>
              <span className="icon-direction">
                {m.from === currentDeskId ? "→" : "←"}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Miv content - flexible height */}
      <div className="miv-content-area">
        <div className="miv-detail-content">
          <div className="epistle-document">
            {/* Epistle-style header with formal layout */}
            <div className="epistle-header">
              <div className="epistle-header-left">
                <div className="epistle-field">
                  <span className="epistle-field-label">To:</span>
                  <span className="epistle-field-value">
                    {getDisplayName(selectedMiv.to)}
                  </span>
                  {!isContact(selectedMiv.to) &&
                    !isOwnDeskId(selectedMiv.to) && (
                      <button
                        className="btn-add-contact-inline"
                        onClick={() => openAddContactModal(selectedMiv.to)}
                        title="Add as contact"
                      >
                        + Add Contact
                      </button>
                    )}
                </div>
                <div className="epistle-field">
                  <span className="epistle-field-label">From:</span>
                  <span className="epistle-field-value">
                    {getDisplayName(selectedMiv.from)}
                  </span>
                  {!isContact(selectedMiv.from) &&
                    !isOwnDeskId(selectedMiv.from) && (
                      <button
                        className="btn-add-contact-inline"
                        onClick={() => openAddContactModal(selectedMiv.from)}
                        title="Add as contact"
                      >
                        + Add Contact
                      </button>
                    )}
                </div>
              </div>
              <div className="epistle-header-right">
                <div className="epistle-field">
                  <span className="epistle-field-value">
                    {formatDate(selectedMiv.created_at)}
                  </span>
                </div>
                <div className="epistle-field epistle-sequence">
                  <span className="epistle-field-value">
                    Message #{selectedMiv.seq_no}
                  </span>
                </div>
                {selectedMiv.cc && selectedMiv.cc.length > 0 && (
                  <div className="epistle-cc-list">
                    {selectedMiv.cc.map((ccRecipient, index) => (
                      <div key={index} className="epistle-cc-item">
                        <span className="epistle-cc-label">cc:</span>
                        <span className="epistle-cc-value">
                          {getDisplayName(ccRecipient)}
                        </span>
                        {!isContact(ccRecipient) &&
                          !isOwnDeskId(ccRecipient) && (
                            <button
                              className="btn-add-contact-inline"
                              onClick={() => openAddContactModal(ccRecipient)}
                              title="Add as contact"
                            >
                              + Add Contact
                            </button>
                          )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Centered subject */}
            <div className="epistle-subject">
              <h2>
                {selectedMiv.type === "CC" && (
                  <span className="cc-badge">[CC] </span>
                )}
                {selectedMiv.subject}
              </h2>
            </div>

            {/* Body content */}
            <div className="epistle-body">
              {selectedMiv.is_ack && <span className="ack-badge">[ACK] </span>}
              <div
                className={`epistle-content ${
                  currentDesk?.auto_indent ? "auto-indent" : ""
                }`}
                style={{
                  fontFamily: selectedMiv.font_family || "Georgia, serif",
                  fontSize: selectedMiv.font_size || "14px",
                }}
                dangerouslySetInnerHTML={{ __html: atob(selectedMiv.body) }}
              />
            </div>
          </div>

          <div className="miv-actions">
            {/* CC recipient actions - only for CC type mivs */}
            {selectedMiv.type === "CC" && !selectedMiv.is_forgotten && (
              <>
                <button className="btn btn-danger" onClick={handleDeleteCc}>
                  Remove
                </button>
              </>
            )}

            {/* Normal recipient actions - for non-CC mivs */}
            {selectedMiv.type !== "CC" &&
              selectedMiv.arrow_to === currentDeskId &&
              !showReply &&
              !showAckConfirm &&
              !showForgetConfirm &&
              !showDeleteConfirm && (
                <>
                  {selectedMiv.is_ack ? (
                    // For ACK mivs, show "Answer" and "Delete" buttons
                    <>
                      <button
                        className="btn btn-primary"
                        onClick={handleShowReply}
                      >
                        Answer
                      </button>
                      <button
                        className="btn btn-danger"
                        onClick={() => setShowDeleteConfirm(true)}
                      >
                        Delete
                      </button>
                    </>
                  ) : (
                    // For non-ACK mivs, show "Reply" and "Send ACK" buttons
                    <>
                      <button
                        className="btn btn-primary"
                        onClick={handleShowReply}
                      >
                        Reply
                      </button>
                      <button
                        className="btn btn-ack"
                        onClick={() => setShowAckConfirm(true)}
                      >
                        Send ACK
                      </button>
                    </>
                  )}
                </>
              )}

            {/* Add forget button for sent messages */}
            {selectedMiv.from === currentDeskId &&
              !selectedMiv.is_forgotten &&
              selectedMiv.state === "SENT" &&
              !showForgetConfirm && (
                <button
                  className="btn btn-forget"
                  onClick={() => setShowForgetConfirm(true)}
                  title="Stop tracking replies for this message"
                >
                  Forget
                </button>
              )}

            {selectedMiv.is_forgotten && (
              <span className="forgotten-label">
                This message has been forgotten
              </span>
            )}
          </div>

          {showForgetConfirm && (
            <div className="forget-confirm">
              <p>
                Are you sure you want to forget this message? It will be removed
                from your SENT basket and you will no longer track replies to
                it.
              </p>
              <div className="forget-actions">
                <button onClick={handleForget} className="btn btn-danger">
                  Yes, Forget This Message
                </button>
                <button
                  onClick={() => setShowForgetConfirm(false)}
                  className="btn"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {showDeleteConfirm && (
            <div className="delete-confirm">
              <p>
                Are you sure you want to delete this conversation? The
                conversation will be archived and removed from your inbox.
              </p>
              <div className="delete-actions">
                <button onClick={handleDelete} className="btn btn-danger">
                  Yes, Archive This Conversation
                </button>
                <button
                  onClick={() => setShowDeleteConfirm(false)}
                  className="btn"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {showAckConfirm && (
            <div className="ack-confirm">
              <h3>Send Acknowledgment</h3>
              <p>
                Send an acknowledgment message? The recipient can reply to
                continue the conversation or delete it to end.
              </p>
              <textarea
                className="ack-body"
                value={ackBody}
                onChange={(e) => setAckBody(e.target.value)}
                placeholder="Optional: Type your acknowledgment message..."
                rows={4}
              />
              <div className="ack-actions">
                <button onClick={handleAck} className="btn btn-danger">
                  Yes, Send ACK
                </button>
                <button
                  onClick={() => {
                    setShowAckConfirm(false);
                    setAckBody("");
                  }}
                  className="btn"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {showReply && (
            <form onSubmit={handleReplySubmit} className="reply-form">
              <h3>Reply</h3>
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
                      placeholder: "Write your reply...",
                    } as any
                  }
                  data={replyBody}
                  onChange={(event, editor) => {
                    const data = editor.getData();
                    setReplyBody(data);
                  }}
                />
              </div>
              <div className="reply-actions">
                <button type="submit" className="btn btn-primary">
                  Send Reply
                </button>
                <button
                  type="button"
                  className="btn btn-info"
                  onClick={() => setShowPreview(true)}
                >
                  Preview
                </button>
                {!selectedMiv.is_ack && (
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={() => {
                      setShowReply(false);
                      setShowAckConfirm(true);
                    }}
                  >
                    Send ACK
                  </button>
                )}
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => {
                    setShowReply(false);
                    setReplyBody("");
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          {showPreview && (
            <div
              className="preview-modal-overlay"
              onClick={() => setShowPreview(false)}
            >
              <div
                className="preview-modal"
                onClick={(e) => e.stopPropagation()}
              >
                <div className="preview-header">
                  <h3>Reply Preview</h3>
                  <button
                    className="close-button"
                    onClick={() => setShowPreview(false)}
                  >
                    ×
                  </button>
                </div>
                <div
                  className="preview-content"
                  style={{
                    fontFamily: currentDesk?.font_family || "Georgia, serif",
                    fontSize: currentDesk?.font_size || "14px",
                  }}
                  dangerouslySetInnerHTML={{ __html: replyBody }}
                />
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
        </div>
      </div>

      {/* Add Contact Modal */}
      {showAddContactModal && (
        <div
          className="add-contact-modal-overlay"
          onClick={() => setShowAddContactModal(false)}
        >
          <div
            className="add-contact-modal"
            onClick={(e) => e.stopPropagation()}
          >
            <h3>Add New Contact</h3>
            <form onSubmit={handleAddContact}>
              <div className="modal-form-group">
                <label htmlFor="contactName">Name</label>
                <input
                  id="contactName"
                  type="text"
                  value={newContactName}
                  onChange={(e) => setNewContactName(e.target.value)}
                  placeholder="Enter contact name"
                  autoFocus
                  required
                />
              </div>
              <div className="modal-form-group">
                <label htmlFor="contactDeskId">Desk ID</label>
                <input
                  id="contactDeskId"
                  type="text"
                  value={formatPhoneId(newContactDeskId)}
                  disabled
                />
              </div>
              <div className="modal-actions">
                <button
                  type="button"
                  onClick={() => setShowAddContactModal(false)}
                  className="btn btn-secondary"
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Add Contact
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default MivDetailWithContext;
