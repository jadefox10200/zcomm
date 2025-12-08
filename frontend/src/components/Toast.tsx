import React, { useEffect } from 'react';
import './Toast.css';

export interface ToastProps {
  message: string;
  duration?: number;
  onClose: () => void;
}

function Toast({ message, duration = 3000, onClose }: ToastProps) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose();
    }, duration);

    return () => clearTimeout(timer);
  }, [duration, onClose]);

  return (
    <div className="toast">
      <div className="toast-content">
        {message}
      </div>
    </div>
  );
}

export default Toast;
