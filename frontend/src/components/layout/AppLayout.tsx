import React from 'react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';

interface AppLayoutProps {
  activeTab: string;
  onTabChange: (tabId: string) => void;
  children: React.ReactNode;
}

const pageTitles: Record<string, string> = {
  dashboard: 'Security Guardian Dashboard',
  scanner: 'Threat Scanner & Risk Analysis',
  agent: 'Secure AI Agent Playground',
  monitoring: 'Real-Time Event Monitoring',
  lab: 'Adversarial Attack Lab',
  reports: 'Security Reports & Audit Trail'
};

export const AppLayout: React.FC<AppLayoutProps> = ({ activeTab, onTabChange, children }) => {
  return (
    <div className="app-container">
      <Sidebar activeTab={activeTab} onTabChange={onTabChange} />
      <div className="main-wrapper">
        <Header activeTabTitle={pageTitles[activeTab] || 'Security Guardian'} />
        <main className="content-area">
          {children}
        </main>
      </div>
    </div>
  );
};
