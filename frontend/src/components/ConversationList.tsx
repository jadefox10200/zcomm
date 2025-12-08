import React, { useState, useEffect } from 'react';
import { ConversationWithLatest, Contact } from '../types';
import * as api from '../api/client';
import './ConversationList.css';

interface ConversationListProps {
  conversations: ConversationWithLatest[];
  selectedConversationId?: string;
  onConversationClick: (conversation: ConversationWithLatest) => void;
  currentDeskId?: string;
}

function ConversationList({ 
  conversations, 
  selectedConversationId, 
  onConversationClick,
  currentDeskId 
}: ConversationListProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);

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
        {conversations.map(conv => (
          <div
            key={conv.conversation.id}
            className={`conversation-item ${
              selectedConversationId === conv.conversation.id ? 'selected' : ''
            } ${conv.unread_count > 0 ? 'unread' : ''}`}
            onClick={() => onConversationClick(conv)}
          >
            {/* Thin-line format: FROM (partner) • DATE/TIME (range) • SUBJECT • COUNT */}
            <div className="conversation-item-row">
              <span className="conversation-partner">
                {getConversationPartner(conv)}
              </span>
              <span className="conversation-separator">•</span>
              <span className="conversation-date-range">
                {formatDate(conv.conversation.created_at)} - {formatDate(conv.conversation.updated_at)}
              </span>
              <span className="conversation-separator">•</span>
              <span className="conversation-subject">{conv.conversation.subject}</span>
              <span className="conversation-separator">•</span>
              <span className="conversation-miv-count">
                {conv.conversation.miv_count} {conv.conversation.miv_count === 1 ? 'miv' : 'mivs'}
              </span>
              {conv.unread_count > 0 && (
                <span className="unread-badge-inline">{conv.unread_count}</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default ConversationList;
