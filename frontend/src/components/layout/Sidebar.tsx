import React from 'react';
import { Shield, LayoutDashboard, Search, Cpu, Activity, Radio, FileText, Lock } from 'lucide-react';

export interface NavItemDef {
  id: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
  badgeType?: 'safe' | 'warning' | 'danger' | 'primary' | 'neutral';
}

interface SidebarProps {
  activeTab: string;
  onTabChange: (tabId: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeTab, onTabChange }) => {
  const navItems: NavItemDef[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: <LayoutDashboard size={18} />
    },
    {
      id: 'scanner',
      label: 'Threat Scanner',
      icon: <Search size={18} />,
      badge: 'Rules Active',
      badgeType: 'primary'
    },
    {
      id: 'agent',
      label: 'Secure Agent',
      icon: <Cpu size={18} />,
      badge: 'Gateway',
      badgeType: 'safe'
    },
    {
      id: 'monitoring',
      label: 'Monitoring',
      icon: <Activity size={18} />
    },
    {
      id: 'lab',
      label: 'Attack Lab',
      icon: <Radio size={18} />,
      badge: 'Sandbox',
      badgeType: 'warning'
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: <FileText size={18} />
    }
  ];

  return (
    <aside className="sidebar" role="navigation" aria-label="Main Navigation">
      <div className="sidebar-header">
        <div className="brand-icon">
          <Shield size={20} />
        </div>
        <div>
          <div className="brand-title">AI Security Guardian</div>
          <div className="brand-tagline">Deterministic Defense</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              className={`nav-item ${isActive ? 'active' : ''}`}
              onClick={() => onTabChange(item.id)}
              aria-current={isActive ? 'page' : undefined}
            >
              <span className="nav-item-icon">{item.icon}</span>
              <span style={{ flex: 1 }}>{item.label}</span>
              {item.badge && (
                <span className={`badge badge-${item.badgeType || 'neutral'}`} style={{ fontSize: '0.65rem' }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div className="status-badge">
          <span className="status-indicator-dot"></span>
          Gateway Online
        </div>
        <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <Lock size={12} /> Deterministic Enforcement
        </div>
      </div>
    </aside>
  );
};
