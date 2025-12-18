import React from "react";
import ReactDOM from "react-dom/client";

import "./index.css";

import App from "./App";
import LandingPage from "./LandingPage";

import * as serviceWorkerRegistration from "./serviceWorkerRegistration";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement
);

function RootSwitcher() {
  const [showApp, setShowApp] = React.useState(() => {
    // If user is already logged in, show App
    const token = localStorage.getItem("token");
    return !!token;
  });

  React.useEffect(() => {
    // Listen for login events (App should set token in localStorage)
    const onStorage = () => {
      if (localStorage.getItem("token")) setShowApp(true);
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  if (showApp) return <App />;
  return <LandingPage onLoginClick={() => setShowApp(true)} />;
}

root.render(
  <React.StrictMode>
    <RootSwitcher />
  </React.StrictMode>
);

// Register service worker for PWA support
// serviceWorkerRegistration.register();
// serviceWorkerRegistration.unregister();
