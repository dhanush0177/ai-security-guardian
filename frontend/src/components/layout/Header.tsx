import React from 'react';
import { Shield, Radio, Terminal } from 'lucide-react';

interface HeaderProps {
  activeTabTitle: string;
}

export const Header: React.FC<HeaderProps> = ({ activeTabTitle }) => {
  return (
    <header className="top-header">
      <div className="header-title-area">
        <h2 className="header-page-title">{activeTabTitle}</h2>
      </div>

      <div className="header-actions">
        <div className="header-pill">
          <Terminal size={14} style={{ color: 'var(--color-primary)' }} />
          <span>API: FastAPI (Port 8000)</span>
        </div>

        <div className="header-pill">
          <Radio size={14} style={{ color: 'var(--color-safe)' }} />
          <span>Rule Engine v1.0</span>
        </div>

        <div className="header-pill" style={{ borderColor: 'var(--color-primary-border)' }}>
          <Shield size={14} style={{ color: 'var(--color-primary)' }} />
          <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>University Hackathon Build</span>
        </div>
      </div>
    </header>
  );
};
