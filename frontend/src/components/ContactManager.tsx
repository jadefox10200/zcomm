import React, { useState, useEffect } from 'react';
import { Contact, CreateContactRequest } from '../types';
import * as api from '../api/client';
import './ContactManager.css';

interface ContactManagerProps {
  deskId: string;
}

function ContactManager({ deskId }: ContactManagerProps) {
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [loading, setLoading] = useState(true);
  const [showForm, setShowForm] = useState(false);
  const [editingContact, setEditingContact] = useState<Contact | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    first_name: '',
    last_name: '',
    greeting_name: '',
    desk_id_ref: '',
    notes: ''
  });

  useEffect(() => {
    const loadContactsData = async () => {
      setLoading(true);
      try {
        const response = await api.listContacts(deskId);
        setContacts(response.contacts || []);
      } catch (err) {
        console.error('Failed to load contacts:', err);
      } finally {
        setLoading(false);
      }
    };
    
    loadContactsData();
  }, [deskId]);

  const loadContacts = async () => {
    setLoading(true);
    try {
      const response = await api.listContacts(deskId);
      setContacts(response.contacts || []);
    } catch (err) {
      console.error('Failed to load contacts:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    try {
      if (editingContact) {
        // Update existing contact
        await api.updateContact(editingContact.id, formData);
      } else {
        // Create new contact
        await api.createContact(deskId, formData as CreateContactRequest);
      }
      
      // Reset form and reload
      setFormData({ name: '', first_name: '', last_name: '', greeting_name: '', desk_id_ref: '', notes: '' });
      setShowForm(false);
      setEditingContact(null);
      await loadContacts();
    } catch (err) {
      console.error('Failed to save contact:', err);
      alert('Failed to save contact. Please try again.');
    }
  };

  const handleEdit = (contact: Contact) => {
    setEditingContact(contact);
    setFormData({
      name: contact.name,
      first_name: contact.first_name || '',
      last_name: contact.last_name || '',
      greeting_name: contact.greeting_name || '',
      desk_id_ref: contact.desk_id_ref,
      notes: contact.notes
    });
    setShowForm(true);
  };

  const handleDelete = async (contactId: string) => {
    if (!window.confirm('Are you sure you want to delete this contact?')) {
      return;
    }
    
    try {
      await api.deleteContact(contactId);
      await loadContacts();
    } catch (err) {
      console.error('Failed to delete contact:', err);
      alert('Failed to delete contact. Please try again.');
    }
  };

  const handleCancel = () => {
    setFormData({ name: '', first_name: '', last_name: '', greeting_name: '', desk_id_ref: '', notes: '' });
    setShowForm(false);
    setEditingContact(null);
  };

  const formatPhoneId = (id: string) => {
    if (id.length === 10) {
      return `${id.slice(0, 4)}-${id.slice(4, 6)}-${id.slice(6)}`;
    }
    return id;
  };

  if (loading) {
    return <div className="contact-manager loading">Loading contacts...</div>;
  }

  return (
    <div className="contact-manager">
      <div className="contact-header">
        <h2>Contacts</h2>
        <button 
          className="btn-add-contact"
          onClick={() => setShowForm(true)}
        >
          + Add Contact
        </button>
      </div>

      {showForm && (
        <div className="contact-form-overlay">
          <div className="contact-form-container">
            <h3>{editingContact ? 'Edit Contact' : 'New Contact'}</h3>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label htmlFor="name">Name *</label>
                <input
                  id="name"
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  required
                  placeholder="John Doe"
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="first_name">First Name</label>
                <input
                  id="first_name"
                  type="text"
                  value={formData.first_name}
                  onChange={(e) => setFormData({ ...formData, first_name: e.target.value })}
                  placeholder="John"
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="last_name">Last Name</label>
                <input
                  id="last_name"
                  type="text"
                  value={formData.last_name}
                  onChange={(e) => setFormData({ ...formData, last_name: e.target.value })}
                  placeholder="Doe"
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="greeting_name">Greeting Name</label>
                <input
                  id="greeting_name"
                  type="text"
                  value={formData.greeting_name}
                  onChange={(e) => setFormData({ ...formData, greeting_name: e.target.value })}
                  placeholder="John (used in salutations)"
                />
                <p className="help-text">Name to use in greetings (e.g., "John" or "Dr. Smith")</p>
              </div>
              
              <div className="form-group">
                <label htmlFor="desk_id_ref">Desk ID (10 digits) *</label>
                <input
                  id="desk_id_ref"
                  type="text"
                  value={formData.desk_id_ref}
                  onChange={(e) => setFormData({ ...formData, desk_id_ref: e.target.value })}
                  required
                  placeholder="1234567890"
                  pattern="[0-9]{10}"
                  maxLength={10}
                />
              </div>
              
              <div className="form-group">
                <label htmlFor="notes">Notes</label>
                <textarea
                  id="notes"
                  value={formData.notes}
                  onChange={(e) => setFormData({ ...formData, notes: e.target.value })}
                  placeholder="Optional notes about this contact"
                  rows={3}
                />
              </div>
              
              <div className="form-actions">
                <button type="button" onClick={handleCancel} className="btn-cancel">
                  Cancel
                </button>
                <button type="submit" className="btn-save">
                  {editingContact ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="contact-list">
        {contacts.length === 0 ? (
          <div className="empty-state">
            <p>No contacts yet</p>
            <p className="empty-hint">Add contacts to message by names instead of IDs</p>
          </div>
        ) : (
          contacts.map(contact => (
            <div key={contact.id} className="contact-item">
              <div className="contact-info">
                <div className="contact-name">{contact.name}</div>
                <div className="contact-desk-id">{formatPhoneId(contact.desk_id_ref)}</div>
                {contact.notes && (
                  <div className="contact-notes">{contact.notes}</div>
                )}
              </div>
              <div className="contact-actions">
                <button 
                  className="btn-edit"
                  onClick={() => handleEdit(contact)}
                >
                  Edit
                </button>
                <button 
                  className="btn-delete"
                  onClick={() => handleDelete(contact.id)}
                >
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ContactManager;
