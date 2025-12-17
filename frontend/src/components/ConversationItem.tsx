import React from "react";
import { ConversationWithLatest } from "../types";
import "./ConversationItem.css";

interface ConversationItemProps {
  conversation: ConversationWithLatest;
  isSelected: boolean;
  onClick: () => void;
  partnerName: string;
  formatDate: (dateString: string) => string;
}

function ConversationItem({
  conversation,
  isSelected,
  onClick,
  partnerName,
  formatDate,
}: ConversationItemProps) {
  return (
    <div
      className={`conversation-item ${isSelected ? "selected" : ""} ${
        conversation.unread_count > 0 ? "unread" : ""
      }`}
      onClick={onClick}
    >
      {/* Single-row format: FROM (partner) • DATE/TIME (range) • SUBJECT • COUNT */}
      <div className="conversation-item-row">
        <span className="conversation-partner">{partnerName}</span>
        <span className="conversation-separator">•</span>
        <span className="conversation-date-range">
          {formatDate(conversation.conversation.created_at)} -{" "}
          {formatDate(conversation.conversation.updated_at)}
        </span>
        <span className="conversation-separator">•</span>
        <span className="conversation-subject">
          {conversation.conversation.subject}
        </span>
        <span className="conversation-separator">•</span>
        <span className="conversation-miv-count">
          {conversation.latest_miv?.seq_no || 0}{" "}
          {conversation.latest_miv?.seq_no === 1 ? "miv" : "mivs"}
        </span>
      </div>
    </div>
  );
}

export default ConversationItem;
