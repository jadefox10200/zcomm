import React from 'react';
import { Miv } from '../types';
import './MivDetail.css';

interface MivDetailProps {
  miv: Miv | null;
  onArchive?: (miv: Miv) => void;
}

const MivDetail: React.FC<MivDetailProps> = ({ miv, onArchive }) => {
  if (!miv) {
    return (
      <div className="miv-detail empty">
        <div className="empty-message">
          <p>Select a miv to view</p>
        </div>
      </div>
    );
  }

  const formatPhoneId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  const formatFullDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const decodeBody = (body: string) => {
    try {
      return atob(body);
    } catch (e) {
      return body;
    }
  };

  return (
    <div className="miv-detail">
      <div className="miv-detail-header">
        <div className="miv-detail-subject">{miv.subject}</div>
        <div className="miv-detail-meta">
          <span className={`state-badge state-${miv.state.toLowerCase()}`}>
            {miv.state}
          </span>
        </div>
      </div>
      
      <div className="miv-detail-info">
        <div className="info-row">
          <span className="info-label">From:</span>
          <span className="info-value">{formatPhoneId(miv.from)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">To:</span>
          <span className="info-value">{formatPhoneId(miv.to)}</span>
        </div>
        <div className="info-row">
          <span className="info-label">Date:</span>
          <span className="info-value">{formatFullDate(miv.created_at)}</span>
        </div>
        {miv.sent_at && (
          <div className="info-row">
            <span className="info-label">Sent:</span>
            <span className="info-value">{formatFullDate(miv.sent_at)}</span>
          </div>
        )}
        {miv.received_at && (
          <div className="info-row">
            <span className="info-label">Received:</span>
            <span className="info-value">{formatFullDate(miv.received_at)}</span>
          </div>
        )}
      </div>

      <div className="miv-detail-body">
        {decodeBody(miv.body)}
      </div>

      {onArchive && miv.state !== 'ARCHIVED' && (
        <div className="miv-detail-actions">
          <button onClick={() => onArchive(miv)} className="btn btn-secondary">
            Archive
          </button>
        </div>
      )}
    </div>
  );
};

export default MivDetail;
