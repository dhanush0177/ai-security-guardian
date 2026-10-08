import React, { useState } from 'react';
import { AppLayout } from './components/layout/AppLayout';
import { DashboardPage } from './pages/DashboardPage';
import { ThreatScannerPage } from './pages/ThreatScannerPage';
import { SecureAgentPage } from './pages/SecureAgentPage';
import { MonitoringPage } from './pages/MonitoringPage';
import { AttackLabPage } from './pages/AttackLabPage';
import { ReportsPage } from './pages/ReportsPage';
import './styles/theme.css';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('dashboard');

  const renderCurrentPage = () => {
    switch (activeTab) {
      case 'dashboard':
        return <DashboardPage onNavigate={setActiveTab} />;
      case 'scanner':
        return <ThreatScannerPage />;
      case 'agent':
        return <SecureAgentPage />;
      case 'monitoring':
        return <MonitoringPage />;
      case 'lab':
        return <AttackLabPage />;
      case 'reports':
        return <ReportsPage />;
      default:
        return <DashboardPage onNavigate={setActiveTab} />;
    }
  };

  return (
    <AppLayout activeTab={activeTab} onTabChange={setActiveTab}>
      {renderCurrentPage()}
    </AppLayout>
  );
};

export default App;
