import React from "react";
import "./LandingPage.css";

interface LandingPageProps {
  onLoginClick?: () => void;
}

const LandingPage: React.FC<LandingPageProps> = ({ onLoginClick }) => {
  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-logo">Zcomm</div>
        <button className="landing-login-btn" onClick={onLoginClick}>Login</button>
      </header>
      <main className="landing-main">
        <h1>Welcome to Zcomm</h1>
        <p>
          Zcomm is a secure, professional communication platform designed for privacy, accountability, and efficient workflow. Send and receive Despatches (secure messages), manage conversations, and collaborate with confidence.
        </p>
        <ul className="landing-goals">
          <li>End-to-end encrypted Despatches for all users</li>
          <li>CC and via-routing for flexible message delivery</li>
          <li>Progressive Web App (PWA) support for mobile access</li>
          <li>Modern, intuitive interface for productivity</li>
        </ul>
        <div className="landing-pwa">
          <h2>Mobile Users</h2>
          <p>
            Add Zcomm to your home screen for a native app experience. <br />
            <button className="landing-pwa-link" onClick={onLoginClick} style={{background: 'none', border: 'none', padding: 0, font: 'inherit', cursor: 'pointer', textDecoration: 'underline'}}>
              Open the PWA
            </button>
          </p>
          <div className="pwa-instructions" style={{marginTop: '1rem', color: '#333', fontSize: '0.98rem'}}>
            <strong>To install:</strong><br />
            <span style={{fontWeight: 400}}>
              On iPhone/iPad: Tap <b>Share</b> <span role="img" aria-label="share">&#x1f5d2;</span> then <b>Add to Home Screen</b>.<br />
              On Android: Tap <b>⋮</b> (menu) then <b>Add to Home screen</b>.<br />
              This will add a Zcomm icon to your home screen for instant access.
            </span>
          </div>
        </div>
      </main>
      <footer className="landing-footer">
        &copy; {new Date().getFullYear()} Zcomm. All rights reserved.
      </footer>
    </div>
  );
};

export default LandingPage;
