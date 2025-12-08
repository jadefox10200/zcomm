import React, { useState } from 'react';
import { Desk } from '../types';
import './DeskSwitcher.css';

interface DeskSwitcherProps {
  desks: Desk[];
  activeDeskId: string;
  onSwitchDesk: (deskId: string) => void;
  onCreateDesk: (name: string) => void;
}

function DeskSwitcher({ desks, activeDeskId, onSwitchDesk, onCreateDesk }: DeskSwitcherProps) {
  const [showDropdown, setShowDropdown] = useState(false);
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newDeskName, setNewDeskName] = useState('');

  const activeDesk = desks.find(d => d.id === activeDeskId);

  const handleCreateDesk = (e: React.FormEvent) => {
    e.preventDefault();
    if (newDeskName.trim()) {
      onCreateDesk(newDeskName.trim());
      setNewDeskName('');
      setShowCreateForm(false);
      setShowDropdown(false);
    }
  };

  const formatDeskId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  return (
    <div className="desk-switcher">
      <button 
        className="desk-switcher-button"
        onClick={() => setShowDropdown(!showDropdown)}
      >
        <div className="desk-info">
          <div className="desk-name">{activeDesk?.name || 'Select Desk'}</div>
          <div className="desk-id">{activeDesk ? formatDeskId(activeDesk.id) : ''}</div>
        </div>
        <span className="dropdown-arrow">▼</span>
      </button>

      {showDropdown && (
        <div className="desk-dropdown">
          <div className="desk-list">
            {desks.map(desk => (
              <button
                key={desk.id}
                className={`desk-item ${desk.id === activeDeskId ? 'active' : ''}`}
                onClick={() => {
                  onSwitchDesk(desk.id);
                  setShowDropdown(false);
                }}
              >
                <div className="desk-name">{desk.name}</div>
                <div className="desk-id">{formatDeskId(desk.id)}</div>
              </button>
            ))}
          </div>

          {showCreateForm ? (
            <form onSubmit={handleCreateDesk} className="create-desk-form">
              <input
                type="text"
                value={newDeskName}
                onChange={(e) => setNewDeskName(e.target.value)}
                placeholder="Desk name"
                autoFocus
              />
              <div className="form-buttons">
                <button type="submit" className="btn btn-sm btn-primary">
                  Create
                </button>
                <button 
                  type="button" 
                  className="btn btn-sm"
                  onClick={() => {
                    setShowCreateForm(false);
                    setNewDeskName('');
                  }}
                >
                  Cancel
                </button>
              </div>
            </form>
          ) : (
            <button
              className="create-desk-button"
              onClick={() => setShowCreateForm(true)}
            >
              + Create New Desk
            </button>
          )}
        </div>
      )}

      {showDropdown && (
        <div 
          className="desk-dropdown-overlay"
          onClick={() => setShowDropdown(false)}
        />
      )}
    </div>
  );
}

export default DeskSwitcher;
