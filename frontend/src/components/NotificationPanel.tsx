import React from 'react';
import { Notification } from '../types';
import './NotificationPanel.css';

interface NotificationPanelProps {
  notifications: Notification[];
  onNotificationClick: (notification: Notification) => void;
  onMarkAsRead: (notificationId: string) => void;
}

function NotificationPanel({ 
  notifications, 
  onNotificationClick, 
  onMarkAsRead 
}: NotificationPanelProps) {
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    if (days === 1) return 'Yesterday';
    return `${days}d ago`;
  };

  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'READ_RECEIPT':
        return '✓';
      case 'NEW_MIV':
        return '📨';
      case 'REPLY':
        return '💬';
      default:
        return '📌';
    }
  };

  const unreadNotifications = notifications.filter(n => !n.read);
  const readNotifications = notifications.filter(n => n.read);

  return (
    <div className="notification-panel">
      <div className="notification-header">
        <h3>Notifications</h3>
        {unreadNotifications.length > 0 && (
          <span className="unread-count">{unreadNotifications.length} unread</span>
        )}
      </div>

      {notifications.length === 0 ? (
        <div className="empty-notifications">
          <p>No notifications</p>
        </div>
      ) : (
        <div className="notification-list">
          {unreadNotifications.length > 0 && (
            <div className="notification-section">
              <div className="section-title">Unread</div>
              {unreadNotifications.map(notif => (
                <div
                  key={notif.id}
                  className="notification-item unread"
                  onClick={() => onNotificationClick(notif)}
                >
                  <div className="notification-icon">
                    {getNotificationIcon(notif.type)}
                  </div>
                  <div className="notification-content">
                    <div className="notification-message">{notif.message}</div>
                    <div className="notification-time">{formatDate(notif.created_at)}</div>
                  </div>
                  <button
                    className="mark-read-btn"
                    onClick={(e) => {
                      e.stopPropagation();
                      onMarkAsRead(notif.id);
                    }}
                  >
                    ×
                  </button>
                </div>
              ))}
            </div>
          )}

          {readNotifications.length > 0 && (
            <div className="notification-section">
              <div className="section-title">Read</div>
              {readNotifications.map(notif => (
                <div
                  key={notif.id}
                  className="notification-item read"
                  onClick={() => onNotificationClick(notif)}
                >
                  <div className="notification-icon">
                    {getNotificationIcon(notif.type)}
                  </div>
                  <div className="notification-content">
                    <div className="notification-message">{notif.message}</div>
                    <div className="notification-time">{formatDate(notif.created_at)}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default NotificationPanel;
