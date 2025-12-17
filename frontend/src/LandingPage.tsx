import React from "react";
import "./LandingPage.css";

const LandingPage: React.FC = () => {
  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-logo">Zcomm</div>
        <a href="/" className="landing-login-btn">Login</a>
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
            <a href="/" className="landing-pwa-link">Open the PWA</a>
          </p>
        </div>
      </main>
      <footer className="landing-footer">
        &copy; {new Date().getFullYear()} Zcomm. All rights reserved.
      </footer>
    </div>
  );
};

export default LandingPage;
