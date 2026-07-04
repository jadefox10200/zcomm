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
import MivPreview from "./MivPreview";
import "./MivDetailWithContext.css";

const CKEditorAny = CKEditor as any;

interface MivDetailWithContextProps {
  miv: ConversationMiv;
  currentDeskId: string;
  currentDesk: Desk;
  onReply: (body: string, isAck?: boolean) => void;
  onForget?: () => void; // Callback when miv is forgotten
  onDeleteCc?: (conversationId: string) => void; // Callback when CC recipient deletes
  onBack?: () => void; // Callback to go back to basket view
  onResubmit?: (miv: ConversationMiv) => void; // Callback to resubmit a rejected via routing message
  isArchived?: boolean; // Whether viewing from archived conversations
}

function MivDetailWithContext({
  miv,
  currentDeskId,
  currentDesk,
  onReply,
  onForget,
  onDeleteCc,
  onBack,
  onResubmit,
  isArchived = false,
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
  const [showViaReject, setShowViaReject] = useState(false);
  const [viaRejectReason, setViaRejectReason] = useState("");
  const [showPreview, setShowPreview] = useState(false);
  const [loading, setLoading] = useState(true);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [showAddContactModal, setShowAddContactModal] = useState(false);
  const [newContactName, setNewContactName] = useState("");
  const [newContactDeskId, setNewContactDeskId] = useState("");
  const [decryptedBody, setDecryptedBody] = useState<string | null>(null);
  const [decryptionError, setDecryptionError] = useState<string | null>(null);
  const [isDecrypting, setIsDecrypting] = useState(false);

  useEffect(() => {
    const loadData = async () => {
      setLoading(true);
      try {
        const [convResponse, contactsResponse] = await Promise.all([
          api.getConversation(miv.conversation_id, currentDeskId),
          api.listContacts(currentDeskId),
        ]);
        setConversation(convResponse);
        setContacts(contactsResponse.contacts || []);
        // Find the current miv in the conversation
        const mivArray = convResponse.mivs || [];
        const currentMiv = mivArray.find((m) => m.id === miv.id) || miv;
        setSelectedMiv(currentMiv);

        // Mark message as read (move from IN/CC to PENDING) if it's currently in IN or CC state
        // BUT: Don't mark as read if current user is a via recipient (they're just routing, not reading)
        const isViaRecipient =
          currentMiv.via &&
          currentMiv.via.length > 0 &&
          !currentMiv.is_via_rejected &&
          currentMiv.via_index < currentMiv.via.length &&
          currentMiv.via[currentMiv.via_index] === currentDeskId;

        if (
          (currentMiv.state === "IN" || currentMiv.state === "CC") &&
          !isViaRecipient
        ) {
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

  // Decrypt message when selectedMiv changes
  useEffect(() => {
    const decryptMessage = async () => {
      if (!selectedMiv) {
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

        // Get current user's private key

        const myPrivateKey = getPrivateKey(currentDeskId);
        if (!myPrivateKey) {
          throw new Error("Private key not found. Please log in again.");
        }

        // Determine who encrypted this message for the current recipient
        // For via routing: the previous person in the chain encrypted it
        // For direct messages: the sender (from) encrypted it
        let encryptorId = selectedMiv.from;

        if (selectedMiv.via && selectedMiv.via.length > 0) {
          // This message went through via routing
          // Find current recipient's position in the chain
          const myPosition = selectedMiv.via.indexOf(currentDeskId);

          if (myPosition > 0) {
            // Current user is not the first via recipient
            // Message was encrypted by the previous via recipient
            encryptorId = selectedMiv.via[myPosition - 1];
          } else if (myPosition === -1 && currentDeskId === selectedMiv.to) {
            // Current user is the final recipient (not in via chain)
            // Message was encrypted by the last via recipient
            encryptorId = selectedMiv.via[selectedMiv.via.length - 1];
          } else {
            // Current user is the first via recipient
            // Message was encrypted by the original sender
          }
        }

        const encryptorPublicKeyResponse = await api.getDeskPublicKey(
          encryptorId
        );
        const encryptorPublicKey = encryptorPublicKeyResponse.public_key;

        // For NaCl box decryption:
        // Message was encrypted with: box(message, nonce, myPublicKey, encryptorPrivateKey)
        // Decrypt with: box.open(encrypted, nonce, encryptorPublicKey, myPrivateKey)
        // ..
        const decrypted = decrypt(
          selectedMiv.body,
          encryptorPublicKey,
          myPrivateKey
        );
        setDecryptedBody(decrypted);
      } catch (error) {
        console.error("❌ Decryption failed:", error);
        setDecryptionError(
          error instanceof Error ? error.message : "Failed to decrypt message"
        );
        setDecryptedBody(null);
      } finally {
        setIsDecrypting(false);
      }
    };

    decryptMessage();
  }, [selectedMiv, currentDeskId]);

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
      owner: currentDeskId, // Current user owns their copy of the reply
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
      deleted: false,
      font_family: currentDesk?.font_family,
      font_size: currentDesk?.font_size,
      line_height: currentDesk?.line_height,
      via_index: 0,
      is_via_rejected: false,
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
        selectedMiv.conversation_id,
        currentDeskId
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
      owner: currentDeskId, // Current user owns their ACK copy
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
      deleted: false,
      font_family: currentDesk?.font_family,
      font_size: currentDesk?.font_size,
      line_height: currentDesk?.line_height,
      via_index: 0,
      is_via_rejected: false,
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
        selectedMiv.conversation_id,
        currentDeskId
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

  // Check if current user is the current via recipient
  const isCurrentViaRecipient = () => {
    if (!selectedMiv.via || selectedMiv.via.length === 0) return false;
    if (selectedMiv.is_via_rejected) return false;

    const currentViaIndex = selectedMiv.via_index;
    if (currentViaIndex >= selectedMiv.via.length) return false;

    return selectedMiv.via[currentViaIndex] === currentDeskId;
  };

  const handleApproveVia = async () => {
    try {
      // Import crypto utilities
      const { getPrivateKey, encryptMessage } = await import("../utils/crypto");

      // Get current user's private key
      const myPrivateKey = getPrivateKey(currentDeskId);
      if (!myPrivateKey) {
        throw new Error("Private key not found. Please log in again.");
      }

      // Determine the next recipient
      const nextViaIndex = selectedMiv.via_index + 1;
      let nextRecipient: string;

      if (selectedMiv.via && nextViaIndex < selectedMiv.via.length) {
        // Forward to next via recipient
        nextRecipient = selectedMiv.via[nextViaIndex];
      } else {
        // Reached the end of via chain, deliver to final recipient
        nextRecipient = selectedMiv.to;
      }

      // Use the already decrypted body from state
      if (!decryptedBody) {
        throw new Error("Message must be decrypted before forwarding");
      }

      // Fetch next recipient's public key
      const nextPublicKeyResponse = await api.getDeskPublicKey(nextRecipient);
      const nextPublicKey = nextPublicKeyResponse.public_key;

      // Re-encrypt the message for the next recipient
      const reEncryptedBody = encryptMessage(
        decryptedBody,
        nextPublicKey,
        myPrivateKey
      );

      // Approve with the re-encrypted body
      await api.approveViaRouting(
        selectedMiv.id,
        currentDeskId,
        reEncryptedBody
      );

      // Navigate back to basket view immediately - handleBackToBasket will refresh conversations
      // The miv should now be filtered out because arrow_to has been updated
      onBack?.();
    } catch (err) {
      console.error("Failed to approve via routing:", err);
      alert("Failed to approve routing. Please try again.");
    }
  };

  const handleRejectVia = async () => {
    if (!viaRejectReason.trim()) {
      alert("Please provide a reason for rejection.");
      return;
    }

    try {
      // Import crypto utilities
      const { getPrivateKey, encryptMessage } = await import("../utils/crypto");
      const myPrivateKey = getPrivateKey(currentDeskId);
      if (!myPrivateKey) {
        throw new Error("Private key not found. Please log in again.");
      }

      // Determine who to send the rejection to (previous via hop or original sender)
      let rejectionRecipient: string;
      if (selectedMiv.via && selectedMiv.via.length > 0) {
        const myPosition = selectedMiv.via.indexOf(currentDeskId);
        if (myPosition > 0) {
          rejectionRecipient = selectedMiv.via[myPosition - 1];
        } else {
          rejectionRecipient = selectedMiv.from;
        }
      } else {
        rejectionRecipient = selectedMiv.from;
      }

      // Build the rejection message
      const rejectionBody = `<p><strong>Via Routing Rejected</strong></p><p>Your message was rejected by ${currentDeskId} during via routing.</p><p><strong>Reason:</strong> ${viaRejectReason}</p><p><strong>Original Subject:</strong> ${selectedMiv.subject}</p>`;

      // Fetch recipient's public key
      const recipientPublicKeyResponse = await api.getDeskPublicKey(
        rejectionRecipient
      );
      const recipientPublicKey = recipientPublicKeyResponse.public_key;

      // Encrypt the rejection message for the recipient
      const encryptedRejectionBody = encryptMessage(
        rejectionBody,
        recipientPublicKey,
        myPrivateKey
      );

      await api.rejectViaRouting(
        selectedMiv.id,
        currentDeskId,
        viaRejectReason,
        encryptedRejectionBody
      );

      setShowViaReject(false);
      setViaRejectReason("");
      onBack?.();
    } catch (err) {
      console.error("Failed to reject via routing:", err);
      alert("Failed to reject routing. Please try again.");
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
      await api.deleteConversation(selectedMiv.conversation_id, currentDeskId);
      setShowDeleteConfirm(false);
      // Call the callback to refresh the parent view
      if (onForget) {
        onForget();
      }
    } catch (err) {
      console.error("Failed to delete conversation:", err);
      alert("Failed to delete conversation. Please try again.");
    }
  };

  const handleDeleteCc = async () => {
    if (!selectedMiv.conversation_id) {
      console.error("No conversation ID found");
      alert("Cannot delete CC: no conversation ID");
      return;
    }

    try {
      await api.deleteCcMiv(selectedMiv.conversation_id, currentDeskId);
      // Call the callback to refresh the parent view and navigate back
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

  const handleAttachmentDownload = async (
    attachment: NonNullable<ConversationMiv["attachments"]>[number]
  ) => {
    try {
      const blob = await api.downloadAttachment(attachment.id);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = attachment.original_filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download attachment:", err);
      alert("Failed to download attachment. Please try again.");
    }
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

  // Check if user has an actionable miv (IN or PENDING) in this conversation
  const hasActionableMiv = () => {
    if (!conversation || !conversation.mivs) return false;
    return conversation.mivs.some(
      (m) =>
        (m.state === "IN" || m.state === "PENDING") &&
        m.arrow_to === currentDeskId
    );
  };

  // Check if the selected MIV is the latest in the conversation
  const isLatestMiv = () => {
    if (!conversation || !conversation.mivs || conversation.mivs.length === 0)
      return false;
    const latestMiv = conversation.mivs[conversation.mivs.length - 1];
    return selectedMiv.id === latestMiv.id;
  };

  // Check if actions should be shown (not archived and viewing latest MIV)
  // Exception: CC mivs are individual copies and can always be acted upon
  const canShowActions = () => {
    if (isArchived) return false;
    if (selectedMiv.state === "REMOVED") return false;
    // CC mivs can always be acted upon since they are individual copies
    if (selectedMiv.type === "CC") return true;
    // For all other miv types, only allow actions on the latest one
    return isLatestMiv();
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
                {selectedMiv.via && selectedMiv.via.length > 0 && (
                  <>
                    {[...selectedMiv.via]
                      .reverse()
                      .map((viaRecipient, reverseIdx) => {
                        // Calculate the original index (for logic) and via number (for display)
                        const originalIdx =
                          selectedMiv.via!.length - 1 - reverseIdx;
                        const viaNumber = selectedMiv.via!.length - originalIdx;
                        const displayName = getDisplayName(viaRecipient);

                        // For CC copies, show arrow to whoever matches arrow_to (the CC recipient viewing this copy)
                        // For VIA copies, show arrow to current via recipient based on via_index
                        // For regular mivs, show arrow to current via recipient based on via_index
                        let isCurrent = false;
                        if (selectedMiv.type === "CC") {
                          // For CC copies, arrow points to the CC recipient (arrow_to)
                          isCurrent = viaRecipient === selectedMiv.arrow_to;
                        } else {
                          // For VIA and regular mivs, arrow follows via_index
                          isCurrent = originalIdx === selectedMiv.via_index;
                        }

                        const hasPassed =
                          originalIdx < (selectedMiv.via_index || 0);

                        let statusSuffix = "";
                        if (isCurrent) {
                          statusSuffix = " ←";
                        } else if (hasPassed) {
                          // Show approval date if passed (using created_at as placeholder)
                          const approvalDate = selectedMiv.created_at
                            ? new Date(
                                selectedMiv.created_at
                              ).toLocaleDateString("en-GB", {
                                day: "numeric",
                                month: "short",
                                year: "2-digit",
                              })
                            : "";
                          statusSuffix = approvalDate
                            ? ` [OK ${approvalDate}]`
                            : " [OK]";
                        }

                        return (
                          <div key={originalIdx} className="epistle-field">
                            <span className="epistle-field-label">
                              via {viaNumber}:
                            </span>
                            <span className="epistle-field-value">
                              {displayName}
                              {statusSuffix}
                              {!isContact(viaRecipient) &&
                                !isOwnDeskId(viaRecipient) && (
                                  <button
                                    className="btn-add-contact-inline"
                                    onClick={() =>
                                      openAddContactModal(viaRecipient)
                                    }
                                    title="Add as contact"
                                  >
                                    + Add Contact
                                  </button>
                                )}
                            </span>
                          </div>
                        );
                      })}
                    {selectedMiv.is_via_rejected && (
                      <div className="epistle-field">
                        <span className="epistle-field-label"></span>
                        <span
                          className="epistle-field-value"
                          style={{ color: "#db2828", fontWeight: "600" }}
                        >
                          [REJECTED]
                        </span>
                      </div>
                    )}
                  </>
                )}
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
              {selectedMiv.is_encrypted && (
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
              {selectedMiv.is_ack && <span className="ack-badge">[ACK] </span>}
              <div
                className={`epistle-content ${
                  currentDesk?.auto_indent ? "auto-indent" : ""
                }`}
                style={
                  {
                    fontFamily: selectedMiv.font_family || "Georgia, serif",
                    fontSize: selectedMiv.font_size || "14px",
                    "--message-line-height": selectedMiv.line_height || "1.65",
                  } as React.CSSProperties
                }
                dangerouslySetInnerHTML={{
                  __html: isDecrypting
                    ? "Decrypting message..."
                    : decryptionError
                    ? `[Unable to decrypt: ${decryptionError}]`
                    : decryptedBody || "[Encrypted - unable to display]",
                }}
              />
              {selectedMiv.attachments && selectedMiv.attachments.length > 0 && (
                <div className="message-attachments">
                  <div className="message-attachments-title">Attachments</div>
                  <ul className="message-attachments-list">
                    {selectedMiv.attachments.map((attachment) => (
                      <li key={attachment.id} className="message-attachment-item">
                        <button
                          type="button"
                          className="message-attachment-link"
                          onClick={() => handleAttachmentDownload(attachment)}
                        >
                          {attachment.original_filename}
                        </button>
                        <span className="message-attachment-size">
                          {Math.max(1, Math.round(attachment.size / 1024))} KB
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="miv-actions">
            {/* CC recipient actions - only for CC type mivs */}
            {canShowActions() &&
              selectedMiv.type === "CC" &&
              !selectedMiv.is_forgotten && (
                <>
                  <button className="btn btn-danger" onClick={handleDeleteCc}>
                    Remove
                  </button>
                </>
              )}

            {/* Via routing actions - show OK/Reject if current user is the current via recipient */}
            {canShowActions() &&
              isCurrentViaRecipient() &&
              !showViaReject &&
              !showForgetConfirm &&
              !showDeleteConfirm && (
                <>
                  <button
                    className="btn btn-primary"
                    onClick={handleApproveVia}
                  >
                    OK (Forward)
                  </button>
                  <button
                    className="btn btn-danger"
                    onClick={() => setShowViaReject(true)}
                  >
                    Reject
                  </button>
                </>
              )}

            {/* Normal recipient actions - only show if user has an actionable miv (IN or PENDING) and NOT a via recipient */}
            {canShowActions() &&
              selectedMiv.type !== "CC" &&
              selectedMiv.arrow_to === currentDeskId &&
              !isCurrentViaRecipient() &&
              !showReply &&
              !showAckConfirm &&
              !showForgetConfirm &&
              !showDeleteConfirm &&
              hasActionableMiv() && (
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
            {canShowActions() &&
              selectedMiv.from === currentDeskId &&
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

          {showViaReject && (
            <div className="ack-confirm">
              <h3>Reject Routing</h3>
              <p>
                This will send the message back to the sender with your
                rejection reason.
              </p>
              <textarea
                className="ack-body"
                value={viaRejectReason}
                onChange={(e) => setViaRejectReason(e.target.value)}
                placeholder="Required: Enter reason for rejection..."
                rows={4}
                required
              />
              <div className="ack-actions">
                <button onClick={handleRejectVia} className="btn btn-danger">
                  Reject and Return
                </button>
                <button
                  onClick={() => {
                    setShowViaReject(false);
                    setViaRejectReason("");
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
                <CKEditorAny
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
                  onChange={(_event: any, editor: any) => {
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
            <MivPreview
              to={selectedMiv.to}
              via={selectedMiv.via}
              cc={selectedMiv.cc}
              from={currentDesk.name}
              subject={conversation?.conversation.subject || ""}
              body={replyBody}
              sequenceNumber={(conversation?.mivs.length || 0) + 1}
              date={new Date()}
              contacts={contacts}
              desk={currentDesk}
              onClose={() => setShowPreview(false)}
            />
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
