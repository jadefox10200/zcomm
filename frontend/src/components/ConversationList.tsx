import React, { useState, useEffect } from 'react';
import { ConversationWithLatest, Contact, ConversationMiv } from '../types';
import * as api from '../api/client';
import ConversationItem from './ConversationItem';
import './ConversationList.css';

interface ConversationListProps {
  conversations: ConversationWithLatest[];
  selectedConversationId?: string;
  onConversationClick: (conversation: ConversationWithLatest) => void;
  currentDeskId?: string;
  onMivClick?: (miv: ConversationMiv) => void;
  selectedMivId?: string;
}

function ConversationList({ 
  conversations, 
  selectedConversationId, 
  onConversationClick,
  currentDeskId,
  onMivClick,
  selectedMivId
}: ConversationListProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [expandedConversationId, setExpandedConversationId] = useState<string | null>(null);
  const [conversationMivs, setConversationMivs] = useState<ConversationMiv[]>([]);
  const [loadingMivs, setLoadingMivs] = useState(false);

  useEffect(() => {
    const loadContactsData = async () => {
      if (!currentDeskId) return;
      try {
        const response = await api.listContacts(currentDeskId);
        setContacts(response.contacts || []);
      } catch (err) {
        console.error('Failed to load contacts:', err);
      }
    };
    
    loadContactsData();
  }, [currentDeskId]);

  // Load mivs when a conversation is expanded
  useEffect(() => {
    const loadConversationMivs = async () => {
      if (!expandedConversationId || !currentDeskId) return;
      
      setLoadingMivs(true);
      try {
        const response = await api.getConversation(expandedConversationId, currentDeskId);
        setConversationMivs(response.mivs || []);
      } catch (err) {
        console.error('Failed to load conversation mivs:', err);
      } finally {
        setLoadingMivs(false);
      }
    };

    loadConversationMivs();
  }, [expandedConversationId, currentDeskId]);

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));

    if (hours < 1) {
      const minutes = Math.floor(diff / (1000 * 60));
      return `${minutes}m ago`;
    } else if (hours < 24) {
      return `${hours}h ago`;
    } else {
      return date.toLocaleDateString();
    }
  };

  const formatPhoneId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  const getConversationPartner = (conv: ConversationWithLatest) => {
    // Get the "other person" in the conversation
    if (!conv.latest_miv || !currentDeskId) return 'Unknown';
    
    // If the latest miv is from us, the partner is the recipient
    const partnerDeskId = conv.latest_miv.from === currentDeskId 
      ? conv.latest_miv.to 
      : conv.latest_miv.from;
    
    // Check if we have a contact for this desk ID
    const contact = contacts.find(c => c.desk_id_ref === partnerDeskId);
    return contact ? contact.name : formatPhoneId(partnerDeskId);
  };

  const getDisplayName = (deskIdRef: string) => {
    const contact = contacts.find((c) => c.desk_id_ref === deskIdRef);
    const formattedId = formatPhoneId(deskIdRef);
    if (contact) {
      return `${contact.name} @ ${formattedId}`;
    }
    return formattedId;
  };

  const handleConversationItemClick = async (conv: ConversationWithLatest) => {
    setExpandedConversationId(conv.conversation.id);
    onConversationClick(conv);
  };

  if (!conversations || conversations.length === 0) {
    return (
      <div className="conversation-list">
        <div className="conversation-list-header">
          <h2>Conversations</h2>
          <p className="conversation-description">All your conversation threads</p>
          <div className="conversation-count">0 conversations</div>
        </div>
        <div className="empty-state">
          <p>No conversations yet</p>
          <p className="empty-hint">Start a new conversation to get started</p>
        </div>
      </div>
    );
  }

  return (
    <div className="conversation-list">
      <div className="conversation-list-header">
        <h2>Conversations</h2>
        <p className="conversation-description">All your conversation threads</p>
        <div className="conversation-count">{conversations.length} {conversations.length === 1 ? 'conversation' : 'conversations'}</div>
      </div>

      <div className="conversation-list-items">
        {/* Show conversation items when no conversation is expanded */}
        {!expandedConversationId ? (
          conversations.map(conv => (
            <ConversationItem
              key={conv.conversation.id}
              conversation={conv}
              isSelected={false}
              onClick={() => handleConversationItemClick(conv)}
              partnerName={getConversationPartner(conv)}
              formatDate={formatDate}
            />
          ))
        ) : (
          /* Show mivs from expanded conversation */
          loadingMivs ? (
            <div className="empty-state">
              <p>Loading messages...</p>
            </div>
          ) : conversationMivs.length === 0 ? (
            <div className="empty-state">
              <p>No messages in this conversation</p>
            </div>
          ) : (
            conversationMivs.map((miv) => (
              <div
                key={miv.id}
                className={`basket-item ${
                  selectedMivId === miv.id ? "selected" : ""
                }`}
                onClick={() => onMivClick && onMivClick(miv)}
              >
                {/* Two-row layout: FROM and SUBJECT on first row, DATE/TIME and read/unread icons on second row */}
                <div className="basket-item-row">
                  <div className="basket-item-first-row">
                    <span className="basket-from">
                      {miv.from === currentDeskId
                        ? `To: ${getDisplayName(miv.to)}`
                        : `From: ${getDisplayName(miv.from)}`}
                    </span>
                    {miv.cc && miv.cc.length > 0 && (
                      <span className="basket-cc">
                        CC:{" "}
                        {miv.cc
                          .map((ccRecipient) => {
                            const contact = contacts.find(
                              (c) => c.desk_id_ref === ccRecipient
                            );
                            return contact
                              ? contact.name
                              : formatPhoneId(ccRecipient);
                          })
                          .join(", ")}
                      </span>
                    )}
                    <span className="basket-subject">{miv.subject}</span>
                  </div>
                  <div className="basket-item-second-row">
                    <span className="basket-date">
                      {formatDate(miv.created_at)}
                    </span>
                    <span
                      className={miv.read_at ? "basket-read" : "basket-unread"}
                    >
                      {miv.read_at ? "✓ Read" : "○ Unread"}
                    </span>
                    <span className="basket-seq">#{miv.seq_no}</span>
                  </div>
                </div>
              </div>
            ))
          )
        )}
      </div>
    </div>
  );
}

export default ConversationList;
