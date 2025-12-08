import React, { useState, useEffect } from 'react';
import MivList from './components/MivList';
import MivDetail from './components/MivDetail';
import ComposeMiv from './components/ComposeMiv';
import { Miv, CreateMivRequest, Identity } from './types';
import * as api from './api/client';
import './App.css';

type View = 'inbox' | 'pending' | 'sent' | 'unanswered' | 'archived' | 'compose';

function App() {
  const [identity, setIdentity] = useState<Identity | null>(null);
  const [mivs, setMivs] = useState<Miv[]>([]);
  const [selectedMiv, setSelectedMiv] = useState<Miv | null>(null);
  const [currentView, setCurrentView] = useState<View>('inbox');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [identityName, setIdentityName] = useState('');
  const [showIdentitySetup, setShowIdentitySetup] = useState(false);

  useEffect(() => {
    loadIdentity();
  }, []);

  useEffect(() => {
    if (identity) {
      loadMivs();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentView, identity]);

  const loadIdentity = async () => {
    try {
      const id = await api.getIdentity();
      setIdentity(id);
      setLoading(false);
    } catch (err) {
      setShowIdentitySetup(true);
      setLoading(false);
    }
  };

  const createIdentity = async () => {
    if (!identityName.trim()) {
      setError('Please enter a name');
      return;
    }

    try {
      const id = await api.createIdentity(identityName);
      setIdentity(id);
      setShowIdentitySetup(false);
      setError(null);
    } catch (err) {
      setError('Failed to create identity');
    }
  };

  const loadMivs = async () => {
    try {
      let data: Miv[];
      switch (currentView) {
        case 'inbox':
          data = await api.getInbox();
          break;
        case 'pending':
          data = await api.getPending();
          break;
        case 'sent':
          data = await api.getSent();
          break;
        case 'unanswered':
          data = await api.getUnanswered();
          break;
        case 'archived':
          data = await api.getArchived();
          break;
        case 'compose':
          return; // Don't load mivs in compose view
        default:
          data = await api.listMivs();
      }
      setMivs(data || []);
    } catch (err) {
      console.error('Failed to load mivs:', err);
      setMivs([]);
    }
  };

  const handleSendMiv = async (request: CreateMivRequest) => {
    await api.createMiv(request);
    setCurrentView('pending');
    await loadMivs();
  };

  const handleArchiveMiv = async (miv: Miv) => {
    await api.updateMivState(miv.id, { state: 'ARCHIVED' });
    setSelectedMiv(null);
    await loadMivs();
  };

  const handleMivClick = (miv: Miv) => {
    setSelectedMiv(miv);
  };

  if (loading) {
    return (
      <div className="app loading">
        <div>Loading...</div>
      </div>
    );
  }

  if (showIdentitySetup) {
    return (
      <div className="app identity-setup">
        <div className="identity-setup-card">
          <h1>Welcome to Missiv</h1>
          <p>Create your identity to get started</p>
          {error && <div className="error-message">{error}</div>}
          <div className="form-group">
            <input
              type="text"
              value={identityName}
              onChange={(e) => setIdentityName(e.target.value)}
              placeholder="Enter your name"
              onKeyPress={(e) => e.key === 'Enter' && createIdentity()}
            />
          </div>
          <button onClick={createIdentity} className="btn btn-primary">
            Create Identity
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <div className="sidebar">
        <div className="sidebar-header">
          <h1>Missiv</h1>
          {identity && (
            <div className="user-info">
              <div className="user-name">{identity.name}</div>
              <div className="user-id">
                ID: {identity.id.slice(0, 3)}-{identity.id.slice(3, 6)}-{identity.id.slice(6)}
              </div>
            </div>
          )}
        </div>
        
        <button
          onClick={() => setCurrentView('compose')}
          className="compose-btn"
        >
          + Compose New Miv
        </button>

        <nav className="nav-menu">
          <button
            className={currentView === 'inbox' ? 'active' : ''}
            onClick={() => setCurrentView('inbox')}
          >
            📥 Inbox
          </button>
          <button
            className={currentView === 'pending' ? 'active' : ''}
            onClick={() => setCurrentView('pending')}
          >
            ⏳ Pending
          </button>
          <button
            className={currentView === 'sent' ? 'active' : ''}
            onClick={() => setCurrentView('sent')}
          >
            📤 Sent
          </button>
          <button
            className={currentView === 'unanswered' ? 'active' : ''}
            onClick={() => setCurrentView('unanswered')}
          >
            ❓ Unanswered
          </button>
          <button
            className={currentView === 'archived' ? 'active' : ''}
            onClick={() => setCurrentView('archived')}
          >
            📦 Archived
          </button>
        </nav>
      </div>

      <div className="main-content">
        {currentView === 'compose' ? (
          <ComposeMiv
            onSend={handleSendMiv}
            onCancel={() => setCurrentView('inbox')}
          />
        ) : (
          <>
            <div className="miv-list-container">
              <MivList
                mivs={mivs}
                onMivClick={handleMivClick}
                selectedMivId={selectedMiv?.id}
              />
            </div>
            <div className="miv-detail-container">
              <MivDetail
                miv={selectedMiv}
                onArchive={handleArchiveMiv}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default App;
