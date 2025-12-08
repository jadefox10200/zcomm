import React, { useState } from 'react';
import { RegisterRequest } from '../types';
import './Auth.css';

interface AuthProps {
  onLogin: (username: string, password: string) => Promise<void>;
  onRegister: (request: RegisterRequest) => Promise<void>;
}

function Auth({ onLogin, onRegister }: AuthProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [isRecovery, setIsRecovery] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [birthday, setBirthday] = useState('');
  const [firstPetName, setFirstPetName] = useState('');
  const [motherMaiden, setMotherMaiden] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await onLogin(username, password);
    } catch (err: any) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await onRegister({
        username,
        password,
        display_name: displayName,
        birthday,
        first_pet_name: firstPetName,
        mother_maiden: motherMaiden,
      });
    } catch (err: any) {
      setError(err.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRecovery = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      // TODO: Implement password recovery API call
      const response = await fetch('http://localhost:8080/api/accounts/recover-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username,
          birthday,
          first_pet_name: firstPetName,
          mother_maiden: motherMaiden,
          new_password: newPassword,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Password recovery failed');
      }

      alert('Password updated successfully! Please log in with your new password.');
      setIsRecovery(false);
      setIsLogin(true);
      setUsername('');
      setBirthday('');
      setFirstPetName('');
      setMotherMaiden('');
      setNewPassword('');
    } catch (err: any) {
      setError(err.message || 'Password recovery failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <h1>Missiv</h1>
        <p className="auth-subtitle">Secure, self-hosted messaging</p>

        {!isRecovery && (
          <div className="auth-tabs">
            <button
              className={isLogin ? 'active' : ''}
              onClick={() => {
                setIsLogin(true);
                setError(null);
              }}
            >
              Sign In
            </button>
            <button
              className={!isLogin ? 'active' : ''}
              onClick={() => {
                setIsLogin(false);
                setError(null);
              }}
            >
              Register
            </button>
          </div>
        )}

        {error && <div className="auth-error">{error}</div>}

        {isRecovery ? (
          <form onSubmit={handleRecovery} className="auth-form">
            <h3>Password Recovery</h3>
            <p>Answer your security questions to reset your password</p>
            
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Your username"
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label>Birthday (YYYY-MM-DD)</label>
              <input
                type="text"
                value={birthday}
                onChange={(e) => setBirthday(e.target.value)}
                placeholder="YYYY-MM-DD"
                required
              />
            </div>
            <div className="form-group">
              <label>First Pet's Name</label>
              <input
                type="text"
                value={firstPetName}
                onChange={(e) => setFirstPetName(e.target.value)}
                placeholder="Your first pet's name"
                required
              />
            </div>
            <div className="form-group">
              <label>Mother's Maiden Name</label>
              <input
                type="text"
                value={motherMaiden}
                onChange={(e) => setMotherMaiden(e.target.value)}
                placeholder="Your mother's maiden name"
                required
              />
            </div>
            <div className="form-group">
              <label>New Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter new password (min 8 characters)"
                required
                minLength={8}
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Recovering...' : 'Reset Password'}
            </button>
            <button 
              type="button" 
              className="btn btn-secondary" 
              onClick={() => {
                setIsRecovery(false);
                setError(null);
              }}
            >
              Back to Sign In
            </button>
          </form>
        ) : isLogin ? (
          <form onSubmit={handleLogin} className="auth-form">
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                required
                autoFocus
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter your password"
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
            <button 
              type="button" 
              className="btn btn-link" 
              onClick={() => {
                setIsRecovery(true);
                setError(null);
              }}
            >
              Forgot password?
            </button>
          </form>
        ) : (
          <form onSubmit={handleRegister} className="auth-form">
            <div className="form-group">
              <label>Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Choose a username"
                required
                minLength={3}
                maxLength={32}
                autoFocus
              />
            </div>
            <div className="form-group">
              <label>Display Name</label>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Your name"
                required
              />
            </div>
            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Choose a password (min 8 characters)"
                required
                minLength={8}
              />
            </div>
            
            <h4 style={{ marginTop: '20px', marginBottom: '10px' }}>Security Questions</h4>
            <p style={{ fontSize: '0.9em', color: '#666', marginBottom: '15px' }}>
              These will be used to recover your password if you forget it
            </p>
            
            <div className="form-group">
              <label>Birthday (YYYY-MM-DD)</label>
              <input
                type="text"
                value={birthday}
                onChange={(e) => setBirthday(e.target.value)}
                placeholder="YYYY-MM-DD (e.g., 1990-05-15)"
                required
              />
            </div>
            <div className="form-group">
              <label>First Pet's Name</label>
              <input
                type="text"
                value={firstPetName}
                onChange={(e) => setFirstPetName(e.target.value)}
                placeholder="Your first pet's name"
                required
              />
            </div>
            <div className="form-group">
              <label>Mother's Maiden Name</label>
              <input
                type="text"
                value={motherMaiden}
                onChange={(e) => setMotherMaiden(e.target.value)}
                placeholder="Your mother's maiden name"
                required
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Creating account...' : 'Create Account'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default Auth;
