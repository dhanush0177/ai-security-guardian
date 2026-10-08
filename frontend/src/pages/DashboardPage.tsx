import React, { useState, useEffect } from 'react';
import { Shield, Cpu, Terminal, Radio, Lock, Activity, CheckCircle2, ShieldAlert, AlertOctagon, Link, MessageSquare } from 'lucide-react';

interface DashboardPageProps {
  onNavigate: (pageId: string) => void;
}

interface SystemStats {
  total_events: number;
  status_breakdown: {
    ALLOWED: number;
    BLOCKED: number;
    REVIEW: number;
    REJECTED: number;
  };
  gateway_status: string;
  active_rules_count: number;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({ onNavigate }) => {
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [events, setEvents] = useState<any[]>([]);

  useEffect(() => {
    fetchDashboardTelemetry();
  }, []);

  const fetchDashboardTelemetry = async () => {
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const statsRes = await fetch(`${apiHost}/api/security/stats`);
      if (statsRes.ok) setStats(await statsRes.json());

      const eventsRes = await fetch(`${apiHost}/api/security/events?limit=20`);
      if (eventsRes.ok) setEvents(await eventsRes.json());
    } catch {
      // Handle offline gracefully
    }
  };

  const calculateStatus = () => {
    const hasCrit = events.some((e) => e.risk_level === 'CRITICAL');
    const hasReview = events.some((e) => e.status === 'REVIEW' || e.risk_level === 'HIGH');
    if (hasCrit) return { label: 'CRITICAL THREAT ACTIVITY DETECTED', badge: 'CRITICAL ACTIVITY', color: 'var(--color-danger)', bg: 'var(--color-danger-bg)' };
    if (hasReview) return { label: 'ATTENTION REQUIRED — GATEWAY ENFORCING', badge: 'ATTENTION REQUIRED', color: 'var(--color-warning)', bg: 'var(--color-warning-bg)' };
    return { label: 'SYSTEM PROTECTED — DETERMINISTIC GATEWAY ACTIVE', badge: 'PROTECTED', color: 'var(--color-safe)', bg: 'var(--color-safe-bg)' };
  };

  const sysStatus = calculateStatus();

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">Security Guardian Overview</h1>
        <p className="page-description">
          Deterministic AI Security Control System — Real-time threat analysis and permission gateway.
        </p>
      </div>

      {/* Dynamic System Status Banner (Part 17) */}
      <div className="card" style={{ marginBottom: '1.5rem', backgroundColor: sysStatus.bg, borderColor: sysStatus.color }}>
        <div className="card-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <div className="status-indicator-dot" style={{ width: '12px', height: '12px', backgroundColor: sysStatus.color, boxShadow: `0 0 8px ${sysStatus.color}` }}></div>
            <div>
              <div style={{ fontWeight: 700, fontSize: '1.1rem', color: sysStatus.color }}>{sysStatus.label}</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                Server-side security logic enforces all permissions. The LLM is NEVER the sole authority.
              </div>
            </div>
          </div>
          <span className="badge badge-neutral" style={{ backgroundColor: 'rgba(255,255,255,0.08)' }}>
            STATUS: {sysStatus.badge}
          </span>
        </div>
      </div>

      {/* System Health Metric Cards */}
      <div className="grid-cols-4" style={{ marginBottom: '1.75rem' }}>
        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Deterministic Gateway</span>
            <Shield size={20} style={{ color: 'var(--color-safe)' }} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            ENFORCING
          </div>
          <div className="badge badge-safe" style={{ marginTop: '0.5rem' }}>
            <CheckCircle2 size={12} /> {stats?.active_rules_count || 18} Rules Active
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Total Evaluated Events</span>
            <Activity size={20} style={{ color: 'var(--color-primary)' }} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {stats?.total_events || events.length}
          </div>
          <div className="badge badge-primary" style={{ marginTop: '0.5rem' }}>
            Live Audit Stream
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Blocked Actions</span>
            <AlertOctagon size={20} style={{ color: 'var(--color-danger)' }} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {stats?.status_breakdown.BLOCKED || 0}
          </div>
          <div className="badge badge-danger" style={{ marginTop: '0.5rem' }}>
            Policy Intercepted
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Pending Approvals</span>
            <Lock size={20} style={{ color: 'var(--color-warning)' }} />
          </div>
          <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {stats?.status_breakdown.REVIEW || 0}
          </div>
          <div className="badge badge-warning" style={{ marginTop: '0.5rem' }}>
            Human Gate Pause
          </div>
        </div>
      </div>

      {/* Quick Actions Panel (Part 16) */}
      <div className="card" style={{ marginBottom: '1.75rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
            Security Workstation Quick Actions
          </div>
          <span className="badge badge-neutral">Direct Module Access</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '0.75rem' }}>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('scanner')}>
            <Link size={18} style={{ color: 'var(--color-primary)' }} />
            Analyze URL
          </button>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('scanner')}>
            <MessageSquare size={18} style={{ color: 'var(--color-warning)' }} />
            Scan Message
          </button>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('scanner')}>
            <ShieldAlert size={18} style={{ color: 'var(--color-danger)' }} />
            Check AI Prompt
          </button>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('agent')}>
            <Cpu size={18} style={{ color: 'var(--color-primary)' }} />
            Secure Agent
          </button>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('lab')}>
            <Radio size={18} style={{ color: 'var(--color-danger)' }} />
            Run Attack Lab
          </button>
          <button className="btn btn-secondary" style={{ flexDirection: 'column', padding: '0.85rem 0.5rem', gap: '0.4rem', fontSize: '0.8rem' }} onClick={() => onNavigate('monitoring')}>
            <Activity size={18} style={{ color: 'var(--color-safe)' }} />
            View Security Events
          </button>
        </div>
      </div>

      {/* Architecture Enforcement Pipeline */}
      <div className="card" style={{ borderColor: 'var(--border-accent)' }}>
        <div className="card-header">
          <div>
            <div className="card-title">
              <Shield size={18} style={{ color: 'var(--color-primary)' }} />
              Deterministic Security Enforcement Pipeline
            </div>
            <div className="card-subtitle">
              Every tool invocation passes through the Permission Gateway before execution.
            </div>
          </div>
          <span className="badge badge-primary">Deterministic Pipeline</span>
        </div>

        <div className="pipeline-diagram">
          <span className="pipeline-node">Frontend Shell</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Backend API</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Security Rules</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Risk Engine</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Permission Gateway</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Simulated Tools</span>
          <span className="pipeline-arrow">→</span>
          <span className="pipeline-node">Event Logger</span>
        </div>
      </div>
    </div>
  );
};
