import React, { useState, useEffect } from 'react';
import { CKEditor } from '@ckeditor/ckeditor5-react';
import ClassicEditor from '@ckeditor/ckeditor5-build-classic';
import { GetConversationResponse, Contact, ConversationMiv, Desk, Account } from '../types';
import * as api from '../api/client';
import { uploadPlugin } from '../utils/ckEditorUploadAdapter';
import { buildMessageWithTemplate } from '../utils/messageTemplate';
import './ConversationThread.css';

interface ConversationThreadProps {
  conversation: GetConversationResponse;
  currentDeskId: string;
  desk: Desk;
  account?: Account;
  onReply: (body: string, isAck?: boolean) => void;
  onArchive?: () => void;
}

function ConversationThread({ conversation, currentDeskId, desk, account, onReply, onArchive }: ConversationThreadProps) {
  const [replyBody, setReplyBody] = useState('');
  const [showReplyForm, setShowReplyForm] = useState(false);
  const [showAckConfirm, setShowAckConfirm] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [ackBody, setAckBody] = useState('');
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [selectedMiv, setSelectedMiv] = useState<ConversationMiv | null>(null);
  const [showPreview, setShowPreview] = useState(false);
  const [replyTemplateInitialized, setReplyTemplateInitialized] = useState(false);

  useEffect(() => {
    const loadContactsData = async () => {
      try {
        const response = await api.listContacts(currentDeskId);
        setContacts(response.contacts || []);
      } catch (err) {
        console.error('Failed to load contacts:', err);
      }
    };
    
    loadContactsData();
  }, [currentDeskId]);

  // Auto-insert salutation and signature when reply form is shown
  useEffect(() => {
    const shouldInitializeReplyTemplate = 
      showReplyForm && !replyTemplateInitialized && contacts.length > 0 && conversation;
    
    if (shouldInitializeReplyTemplate) {
      // Get the recipient (who we're replying to - the other party in conversation)
      const latestMiv = conversation.mivs[conversation.mivs.length - 1];
      const recipient = latestMiv.from === currentDeskId ? latestMiv.to : latestMiv.from;
      
      const initialTemplate = buildMessageWithTemplate(
        desk.default_salutation || '',
        recipient,
        contacts,
        desk.default_closure || '',
        '<p><br></p>' // Empty paragraph for typing
      );
      setReplyBody(initialTemplate);
      setReplyTemplateInitialized(true);
    }
    
    // Reset template flag when reply form is hidden
    if (!showReplyForm) {
      setReplyTemplateInitialized(false);
    }
  }, [showReplyForm, replyTemplateInitialized, contacts, conversation, currentDeskId, desk.default_salutation, desk.default_closure]);

  const handleReply = (e: React.FormEvent) => {
    e.preventDefault();
    if (replyBody.trim()) {
      onReply(replyBody.trim(), false);
      setReplyBody('');
      setShowReplyForm(false);
      setReplyTemplateInitialized(false);
    }
  };

  const handleAck = () => {
    const messageToSend = ackBody.trim() || 'ACK - Conversation ended';
    onReply(messageToSend, true);
    setShowAckConfirm(false);
    setAckBody('');
  };

  const handleDelete = async () => {
    try {
      await api.archiveConversation(conversation.conversation.id);
      setShowDeleteConfirm(false);
      if (onArchive) {
        onArchive();
      }
    } catch (err) {
      console.error('Failed to archive conversation:', err);
      alert('Failed to archive conversation. Please try again.');
    }
  };

  // Ping-pong style: only show reply buttons if latest miv is to us and unanswered
  const shouldShowReplyButtons = () => {
    if (!conversation || conversation.mivs.length === 0) return false;
    
    const latestMiv = conversation.mivs[conversation.mivs.length - 1];
    
    // Only show if the latest message is TO us (not from us)
    if (latestMiv.to !== currentDeskId) return false;
    
    // Don't show if archived
    if (conversation.conversation.is_archived) return false;
    
    return true;
  };

  const isLatestMivAck = () => {
    if (!conversation || conversation.mivs.length === 0) return false;
    const latestMiv = conversation.mivs[conversation.mivs.length - 1];
    return latestMiv.is_ack;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
    });
  };

  const formatDeskId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  const getDisplayName = (deskIdRef: string) => {
    const contact = contacts.find(c => c.desk_id_ref === deskIdRef);
    const formattedId = formatDeskId(deskIdRef);
    if (contact) {
      return `${contact.name} @ ${formattedId}`;
    }
    return formattedId;
  };

  if (!conversation) {
    return (
      <div className="conversation-thread empty">
        <div className="empty-state">
          <p>Select a conversation to view</p>
        </div>
      </div>
    );
  }

  const handleMivClick = (miv: ConversationMiv) => {
    setSelectedMiv(miv);
  };

  return (
    <div className="conversation-thread miv-detail-with-context">
      {/* Conversation thread context at the top - similar to basket view */}
      <div className="thread-context">
        <div className="thread-header">
          <h3>Conversation Thread</h3>
          <span className="thread-count">
            {conversation.mivs.length} {conversation.mivs.length === 1 ? 'message' : 'messages'}
          </span>
        </div>
        <div className="thread-icons">
          {conversation.mivs.map((m) => (
            <div
              key={m.id}
              className={`thread-icon ${
                selectedMiv?.id === m.id ? "active" : ""
              } ${m.from === currentDeskId ? "outgoing" : "incoming"}`}
              onClick={() => handleMivClick(m)}
              title={`Message #${m.seq_no} - ${
                m.from === currentDeskId ? "You" : formatDeskId(m.from)
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

      <div className="conversation-thread-header">
        <h2>{conversation.conversation.subject}</h2>
        <div className="thread-meta">
          {conversation.conversation.is_archived && (
            <span className="archived-badge">Archived</span>
          )}
        </div>
      </div>

      <div className="conversation-messages-inbox-style">
        {conversation.mivs.map((miv, index) => {
          const isFromMe = miv.from === currentDeskId;
          
          return (
            <div
              key={miv.id}
              className={`message-inbox-item ${selectedMiv?.id === miv.id ? "selected" : ""}`}
              onClick={() => handleMivClick(miv)}
            >
              {/* INBOX-style layout: FROM, DATE, SUBJECT (inline) */}
              <div className="message-inbox-header">
                <span className="message-inbox-from">
                  {isFromMe ? `To: ${getDisplayName(miv.to)}` : `From: ${getDisplayName(miv.from)}`}
                </span>
                <span className="message-inbox-date">{formatDate(miv.created_at)}</span>
                <span className="message-inbox-seq">#{miv.seq_no}</span>
              </div>
              
              <div className="message-inbox-body epistle-document">
                {miv.is_ack && <span className="ack-badge">[ACK] </span>}
                {/* Message body only - salutations and closures are not displayed */}
                <div 
                  className="epistle-content"
                  style={{
                    fontFamily: desk?.font_family || 'Georgia, serif',
                    fontSize: desk?.font_size || '14px'
                  }}
                >
                  <div 
                    className={desk?.auto_indent ? 'auto-indent' : ''}
                    dangerouslySetInnerHTML={{ __html: atob(miv.body) }} 
                  />
                </div>
              </div>

              {miv.read_at && (
                <div className="message-status">
                  Read {formatDate(miv.read_at)}
                </div>
              )}
              
              {!miv.read_at && miv.sent_at && isFromMe && (
                <div className="message-status">
                  Sent {formatDate(miv.sent_at)}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="conversation-reply">
        {shouldShowReplyButtons() && (
          <>
            {showDeleteConfirm ? (
              <div className="delete-confirm">
                <h3>Archive Conversation</h3>
                <p>Are you sure you want to archive this conversation? It will be removed from your inbox.</p>
                <div className="delete-actions">
                  <button onClick={handleDelete} className="btn btn-danger">
                    Yes, Archive
                  </button>
                  <button
                    onClick={() => setShowDeleteConfirm(false)}
                    className="btn"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : showAckConfirm ? (
              <div className="ack-confirm">
                <h3>Send Acknowledgment</h3>
                <p>Send an acknowledgment message? The recipient can reply to continue the conversation or delete it to end.</p>
                <textarea
                  value={ackBody}
                  onChange={(e) => setAckBody(e.target.value)}
                  placeholder="Optional: Type your acknowledgment message..."
                  rows={3}
                />
                <div className="ack-actions">
                  <button onClick={handleAck} className="btn btn-danger">
                    Yes, Send ACK
                  </button>
                  <button
                    onClick={() => {
                      setShowAckConfirm(false);
                      setAckBody('');
                    }}
                    className="btn"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : showReplyForm ? (
              <form onSubmit={handleReply} className="reply-form">
                <div className="editor-container">
                  <CKEditor
                    editor={ClassicEditor as any}
                    config={{
                      extraPlugins: [uploadPlugin],
                      toolbar: {
                        items: [
                          'undo', 'redo', '|',
                          'heading', '|',
                          'bold', 'italic', 'underline', 'strikethrough', '|',
                          'code', 'subscript', 'superscript', '|',
                          'link', 'insertTable', 'imageUpload', 'mediaEmbed', '|',
                          'bulletedList', 'numberedList', '|',
                          'blockQuote', 'horizontalLine'
                        ]
                      },
                      image: {
                        toolbar: [
                          'imageStyle:alignLeft',
                          'imageStyle:alignCenter',
                          'imageStyle:alignRight',
                          '|',
                          'resizeImage'
                        ]
                      },
                      heading: {
                        options: [
                          { model: 'paragraph', title: 'Paragraph', class: 'ck-heading_paragraph' },
                          { model: 'heading1', view: 'h1', title: 'Heading 1', class: 'ck-heading_heading1' },
                          { model: 'heading2', view: 'h2', title: 'Heading 2', class: 'ck-heading_heading2' },
                          { model: 'heading3', view: 'h3', title: 'Heading 3', class: 'ck-heading_heading3' }
                        ]
                      },
                      placeholder: 'Type your reply...'
                    } as any}
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
                    className="btn btn-preview"
                    onClick={() => setShowPreview(true)}
                    disabled={!replyBody.trim()}
                  >
                    👁️ Preview
                  </button>
                  {!isLatestMivAck() && (
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() => {
                        setShowReplyForm(false);
                        setShowAckConfirm(true);
                      }}
                    >
                      Send ACK
                    </button>
                  )}
                  <button
                    type="button"
                    className="btn"
                    onClick={() => {
                      setShowReplyForm(false);
                      setReplyBody('');
                      setReplyTemplateInitialized(false);
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            ) : (
              <div className="reply-buttons">
                {isLatestMivAck() ? (
                  // For ACK mivs, show "Answer" and "Delete" buttons
                  <>
                    <button
                      className="btn btn-primary"
                      onClick={() => setShowReplyForm(true)}
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
                      className="btn btn-reply"
                      onClick={() => setShowReplyForm(true)}
                    >
                      Reply to conversation
                    </button>
                    <button
                      className="btn btn-ack"
                      onClick={() => setShowAckConfirm(true)}
                    >
                      Send ACK
                    </button>
                  </>
                )}
              </div>
            )}
          </>
        )}
      </div>

      {showPreview && (
        <div className="preview-overlay" onClick={() => setShowPreview(false)}>
          <div className="preview-modal" onClick={(e) => e.stopPropagation()}>
            <div className="preview-header">
              <h3>Reply Preview</h3>
              <button className="close-button" onClick={() => setShowPreview(false)}>×</button>
            </div>
            <div className="preview-content">
              <div 
                className="epistle-preview" 
                style={{
                  fontFamily: desk?.font_family || 'Georgia, serif',
                  fontSize: desk?.font_size || '14px'
                }}
              >
                <div className="preview-subject">
                  <h2>{conversation.conversation.subject}</h2>
                </div>
                <div 
                  className={`preview-body ${desk?.auto_indent ? 'auto-indent' : ''}`}
                  dangerouslySetInnerHTML={{ __html: replyBody || '<p>(No message)</p>' }}
                />
              </div>
            </div>
            <div className="preview-actions">
              <button className="btn btn-secondary" onClick={() => setShowPreview(false)}>
                Close Preview
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default ConversationThread;
