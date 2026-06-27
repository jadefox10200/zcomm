import React, { useState, useEffect } from "react";
import {
  ConversationMiv,
  MivState,
  Contact,
  ConversationWithLatest,
} from "../types";
import * as api from "../api/client";
import { useSwipe } from "../utils/useSwipe";
import ConversationItem from "./ConversationItem";
import "./BasketView.css";

interface BasketViewProps {
  deskId: string;
  selectedBasket: MivState;
  onMivClick: (miv: ConversationMiv) => void;
  selectedMivId?: string;
  onBasketChange?: (basket: MivState) => void;
  // Optional callback to navigate to the Conversations view when swiping
  onNavigateToConversations?: () => void;
  refreshToken?: number;
}

function BasketView({
  deskId,
  selectedBasket,
  onMivClick,
  selectedMivId,
  onBasketChange,
  onNavigateToConversations,
  refreshToken,
}: BasketViewProps) {
  const [mivs, setMivs] = useState<ConversationMiv[]>([]);
  const [archivedConversations, setArchivedConversations] = useState<
    ConversationWithLatest[]
  >([]);
  const [loading, setLoading] = useState(true);
  const [contacts, setContacts] = useState<Contact[]>([]);
  const firstLoadRef = React.useRef(true);
  const fullConvCacheRef = React.useRef<Map<string, any>>(new Map());

  // Basket navigation order for swipe gestures (mobile swipe only between these three)
  const basketOrder: MivState[] = ["IN", "PENDING", "SENT"];
  const currentBasketIndex = basketOrder.indexOf(selectedBasket);

  const handleSwipeLeft = () => {
    if (onBasketChange && currentBasketIndex >= 0 && currentBasketIndex < basketOrder.length - 1) {
      onBasketChange(basketOrder[currentBasketIndex + 1]);
    }
  };

  const handleSwipeRight = () => {
    if (onBasketChange && currentBasketIndex > 0) {
      onBasketChange(basketOrder[currentBasketIndex - 1]);
    }
  };

  // Add swipe gesture support
  useSwipe(handleSwipeLeft, handleSwipeRight);

  useEffect(() => {
    const loadMivs = async () => {
      if (firstLoadRef.current) {
        setLoading(true);
      }
      try {
        // Load contacts first
        const contactsResponse = await api.listContacts(deskId);
        setContacts(contactsResponse.contacts || []);

        // Handle ARCHIVED view separately - use dedicated API endpoint
        if (selectedBasket === "ARCHIVED") {
          const archivedResponse = await api.listArchivedConversations(deskId);
          const archived = archivedResponse?.conversations || [];
          setArchivedConversations(archived);
          setMivs([]);
        } else {
          // For regular baskets, get active conversations only
          const response = await api.listConversations(deskId);
          const allMivs: ConversationMiv[] = [];
          const conversations = response?.conversations || [];

          setArchivedConversations([]);

          // Prepare fetches for conversations not already cached
          const fetchPromises: Promise<any>[] = [];
          const convIdsToFetch: string[] = [];

          for (const conv of conversations) {
            const cid = conv.conversation.id;
            if (!fullConvCacheRef.current.has(cid)) {
              convIdsToFetch.push(cid);
            }
          }

          // Fetch missing conversations in parallel to reduce latency
          if (convIdsToFetch.length > 0) {
            for (const cid of convIdsToFetch) {
              fetchPromises.push(
                api.getConversation(cid, deskId).then((fc) => {
                  fullConvCacheRef.current.set(cid, fc);
                })
              );
            }
            try {
              await Promise.all(fetchPromises);
            } catch (err) {
              console.error("Failed to fetch some conversations:", err);
            }
          }

          // Build miv list from cached/full conversations
          for (const conv of conversations) {
            const cid = conv.conversation.id;
            const fullConv = fullConvCacheRef.current.get(cid);
            if (!fullConv) continue;
            const mivArray = fullConv.mivs || [];
              const filteredMivs = mivArray.filter((miv: ConversationMiv) => {
              // CRITICAL: Only show mivs owned by current user
              if (miv.owner !== deskId) return false;

              // Filter based on miv state from backend
              if (miv.state !== selectedBasket) return false;

              // Exclude deleted mivs from basket views (only affects ACKs)
              if (miv.deleted) return false;

              // Exclude forgotten mivs
              if (miv.is_forgotten) return false;

              // Exclude ACK mivs from SENT basket (they don't expect replies)
              if (selectedBasket === "SENT" && miv.is_ack) return false;
              if (selectedBasket === "SENT" && miv.type === "VIA") return false;

              return true;
            });
            allMivs.push(...filteredMivs);
          }

          // Sort by most recent first
          allMivs.sort(
            (a, b) =>
              new Date(b.created_at).getTime() -
              new Date(a.created_at).getTime()
          );

          setMivs(allMivs);
        }
      } catch (err) {
        console.error("Failed to load basket mivs:", err);
      } finally {
        firstLoadRef.current = false;
        setLoading(false);
      }
    };

    loadMivs();
  }, [deskId, selectedBasket, refreshToken]);

  // Clear cache when desk or refresh token changes
  useEffect(() => {
    fullConvCacheRef.current.clear();
  }, [deskId, refreshToken]);

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

  const getDisplayName = (deskIdRef: string) => {
    const contact = contacts.find((c) => c.desk_id_ref === deskIdRef);
    const formattedId = formatPhoneId(deskIdRef);
    if (contact) {
      return `${contact.name} @ ${formattedId}`;
    }
    return formattedId;
  };

  const getConversationPartner = (conv: ConversationWithLatest) => {
    // Get the "other person" in the conversation
    if (!conv.latest_miv) return "Unknown";

    // If the latest miv is from us, the partner is the recipient
    const partnerDeskId =
      conv.latest_miv.from === deskId
        ? conv.latest_miv.to
        : conv.latest_miv.from;

    return getDisplayName(partnerDeskId);
  };

  const getBasketTitle = () => {
    switch (selectedBasket) {
      case "IN":
        return "Inbox";
      case "PENDING":
        return "Pending";
      case "SENT":
        return "Sent";
      case "ARCHIVED":
        return "Archived";
      default:
        return "Messages";
    }
  };

  const getBasketDescription = () => {
    switch (selectedBasket) {
      case "IN":
        return "Unread received messages";
      case "PENDING":
        return "Messages you've looked at but not answered";
      case "SENT":
        return "Sent messages awaiting replies";
      case "ARCHIVED":
        return "Archived conversations";
      default:
        return "";
    }
  };

  if (loading) {
    return (
      <div className="basket-view">
        <div className="basket-header">
          <h2>{getBasketTitle()}</h2>
        </div>
        <div className="basket-loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="basket-view">
      <div className="basket-header">
        <h2>{getBasketTitle()}</h2>
        <p className="basket-description">{getBasketDescription()}</p>
        {selectedBasket !== "ARCHIVED" && (
          <div className="basket-count">
            {mivs.length} {mivs.length === 1 ? "message" : "messages"}
          </div>
        )}
      </div>

      <div className="basket-list">
        {selectedBasket === "ARCHIVED" ? (
          archivedConversations.length === 0 ? (
            <div className="empty-state">
              <p>No archived conversations</p>
            </div>
          ) : (
            archivedConversations.map((conv) => (
              <ConversationItem
                key={conv.conversation.id}
                conversation={conv}
                isSelected={false}
                onClick={() => conv.latest_miv && onMivClick(conv.latest_miv)}
                partnerName={getConversationPartner(conv)}
                formatDate={formatDate}
              />
            ))
          )
        ) : mivs.length === 0 ? (
          <div className="empty-state">
            <p>No messages in {getBasketTitle().toLowerCase()}</p>
          </div>
        ) : (
          mivs.map((miv) => (
            <div
              key={miv.id}
              className={`basket-item ${
                selectedMivId === miv.id ? "selected" : ""
              }`}
              onClick={() => onMivClick(miv)}
            >
              {/* Two-row layout: FROM and SUBJECT on first row, DATE/TIME and read/unread icons on second row */}
              <div className="basket-item-row">
                <div className="basket-item-first-row">
                  <span className="basket-from">
                    {miv.state === "SENT"
                      ? `To: ${getDisplayName(miv.to)}`
                      : miv.type === "CC"
                      ? `CC from: ${getDisplayName(miv.from)}`
                      : `From: ${getDisplayName(miv.from)}`}
                  </span>
                  {miv.cc && miv.cc.length > 0 && (
                    <span className="basket-cc">
                      CC:{" "}
                      {miv.cc
                        .map((ccRecipient) => getDisplayName(ccRecipient))
                        .join(", ")}
                    </span>
                  )}
                  {miv.via && miv.via.length > 0 && (
                    <span className="basket-via">
                      via:{" "}
                      {miv.via
                        .map((viaRecipient, idx) => {
                          const name = getDisplayName(viaRecipient);

                          // Check if this is the current via recipient
                          const isCurrent = idx === miv.via_index;
                          // Check if this via recipient has already passed it
                          const hasPassed = idx < (miv.via_index || 0);

                          if (isCurrent) {
                            return `${name} ←`;
                          } else if (hasPassed) {
                            return `${name} [OK]`;
                          } else {
                            return name;
                          }
                        })
                        .join(", ")}
                      {miv.is_via_rejected && (
                        <span className="via-rejected"> [REJECTED]</span>
                      )}
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
        )}
      </div>
    </div>
  );
}

export default BasketView;
