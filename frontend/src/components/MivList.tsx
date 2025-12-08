import React from 'react';
import { Miv } from '../types';
import './MivList.css';

interface MivListProps {
  mivs: Miv[];
  onMivClick: (miv: Miv) => void;
  selectedMivId?: string;
}

const MivList: React.FC<MivListProps> = ({ mivs, onMivClick, selectedMivId }) => {
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

  return (
    <div className="miv-list">
      {mivs.length === 0 ? (
        <div className="empty-state">
          <p>No mivs found</p>
        </div>
      ) : (
        mivs.map((miv) => (
          <div
            key={miv.id}
            className={`miv-item ${selectedMivId === miv.id ? 'selected' : ''}`}
            onClick={() => onMivClick(miv)}
          >
            <div className="miv-item-header">
              <span className="miv-from">{formatPhoneId(miv.from)}</span>
              <span className="miv-date">{formatDate(miv.created_at)}</span>
            </div>
            <div className="miv-subject">{miv.subject}</div>
            <div className="miv-preview">
              {atob(miv.body).substring(0, 100)}...
            </div>
            <div className="miv-state">
              <span className={`state-badge state-${miv.state.toLowerCase()}`}>
                {miv.state}
              </span>
            </div>
          </div>
        ))
      )}
    </div>
  );
};

export default MivList;
