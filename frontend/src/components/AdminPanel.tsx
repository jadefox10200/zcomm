import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Account,
  AdminUserCounts,
} from "../types";
import {
  closeAdminUser,
  getAdminUserCounts,
  listAdminUsers,
  lockAdminUser,
  reopenAdminUser,
  resetAdminUserPassword,
  unlockAdminUser,
} from "../api/client";
import "./AdminPanel.css";

interface Props {
  currentAccountId: string;
}

const initialCounts: AdminUserCounts = {
  total: 0,
  active: 0,
  locked: 0,
  closed: 0,
  admins: 0,
};

function AdminPanel({ currentAccountId }: Props) {
  const [counts, setCounts] = useState<AdminUserCounts>(initialCounts);
  const [users, setUsers] = useState<Account[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyUserId, setBusyUserId] = useState<string | null>(null);
  const [resetTargetUser, setResetTargetUser] = useState<Account | null>(null);
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const sortedUsers = useMemo(
    () =>
      [...users].sort((a, b) => {
        const roleOrder = (a.role === "admin" ? 0 : 1) - (b.role === "admin" ? 0 : 1);
        if (roleOrder !== 0) return roleOrder;
        return a.username.localeCompare(b.username);
      }),
    [users]
  );

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [countsResponse, usersResponse] = await Promise.all([
        getAdminUserCounts(),
        listAdminUsers(),
      ]);
      setCounts(countsResponse);
      setUsers(usersResponse.users || []);
    } catch (err: any) {
      setError(err.message || "Failed to load admin data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const runAction = async (user: Account, action: () => Promise<void>) => {
    setBusyUserId(user.id);
    setError(null);
    try {
      await action();
      await loadData();
    } catch (err: any) {
      setError(err.message || "Admin action failed");
    } finally {
      setBusyUserId(null);
    }
  };

  const openResetModal = (user: Account) => {
    setResetTargetUser(user);
    setNewPassword("");
    setConfirmPassword("");
  };

  const closeResetModal = () => {
    setResetTargetUser(null);
    setNewPassword("");
    setConfirmPassword("");
  };

  const submitResetPassword = async () => {
    if (!resetTargetUser) return;
    if (newPassword.length < 8) {
      setError("New password must be at least 8 characters.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    await runAction(resetTargetUser, () =>
      resetAdminUserPassword(resetTargetUser.id, newPassword)
    );
    closeResetModal();
  };

  return (
    <div className="admin-view">
      <div className="admin-header">
        <h2>Administrator Tools</h2>
        <button className="btn btn-primary" onClick={loadData} disabled={loading}>
          Refresh
        </button>
      </div>

      {error && <div className="admin-error">{error}</div>}

      <div className="admin-counts">
        <div className="admin-count-card">
          <div className="admin-count-label">Total</div>
          <div className="admin-count-value">{counts.total}</div>
        </div>
        <div className="admin-count-card">
          <div className="admin-count-label">Active</div>
          <div className="admin-count-value">{counts.active}</div>
        </div>
        <div className="admin-count-card">
          <div className="admin-count-label">Locked</div>
          <div className="admin-count-value">{counts.locked}</div>
        </div>
        <div className="admin-count-card">
          <div className="admin-count-label">Closed</div>
          <div className="admin-count-value">{counts.closed}</div>
        </div>
        <div className="admin-count-card">
          <div className="admin-count-label">Admins</div>
          <div className="admin-count-value">{counts.admins}</div>
        </div>
      </div>

      {loading ? (
        <div className="admin-loading">Loading admin data...</div>
      ) : (
        <div className="admin-table-wrap">
          <table className="admin-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Display Name</th>
                <th>Role</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {sortedUsers.map((user) => {
                const isBusy = busyUserId === user.id;
                const isSelf = user.id === currentAccountId;
                const status = user.status || "active";

                return (
                  <tr key={user.id}>
                    <td>@{user.username}</td>
                    <td>{user.display_name}</td>
                    <td>{user.role || "user"}</td>
                    <td>{status}</td>
                    <td className="admin-actions-cell">
                      {status === "active" && (
                        <button
                          className="btn admin-btn"
                          disabled={isBusy || isSelf}
                          onClick={() => {
                            if (
                              window.confirm(`Lock @${user.username}? They will not be able to sign in.`)
                            ) {
                              runAction(user, () => lockAdminUser(user.id));
                            }
                          }}
                        >
                          Lock
                        </button>
                      )}

                      {status === "locked" && (
                        <button
                          className="btn admin-btn"
                          disabled={isBusy}
                          onClick={() => runAction(user, () => unlockAdminUser(user.id))}
                        >
                          Unlock
                        </button>
                      )}

                      {status !== "closed" && (
                        <button
                          className="btn admin-btn admin-btn-danger"
                          disabled={isBusy || isSelf}
                          onClick={() => {
                            if (
                              window.confirm(
                                `Close @${user.username}? This prevents login until reopened by an admin.`
                              )
                            ) {
                              runAction(user, () => closeAdminUser(user.id));
                            }
                          }}
                        >
                          Close
                        </button>
                      )}

                      {status === "closed" && (
                        <button
                          className="btn admin-btn"
                          disabled={isBusy}
                          onClick={() => runAction(user, () => reopenAdminUser(user.id))}
                        >
                          Reopen
                        </button>
                      )}

                      <button
                        className="btn admin-btn"
                        disabled={isBusy || isSelf}
                        onClick={() => openResetModal(user)}
                      >
                        Reset Password
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {resetTargetUser && (
        <div className="admin-modal-overlay" onClick={closeResetModal}>
          <div className="admin-modal" onClick={(e) => e.stopPropagation()}>
            <h3>Reset Password</h3>
            <p>Set a new password for @{resetTargetUser.username}.</p>
            <input
              type="password"
              placeholder="New password (min 8 characters)"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              autoFocus
            />
            <input
              type="password"
              placeholder="Confirm new password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
            />
            <div className="admin-modal-actions">
              <button className="btn" onClick={closeResetModal}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                onClick={submitResetPassword}
                disabled={busyUserId === resetTargetUser.id}
              >
                Save Password
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default AdminPanel;
