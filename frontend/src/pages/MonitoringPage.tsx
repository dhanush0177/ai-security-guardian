import React, { useState, useEffect } from 'react';
import { Activity, Terminal, Shield, AlertOctagon, Filter, RefreshCw, X, ShieldAlert, Eye, Lock } from 'lucide-react';

interface SecurityEvent {
  event_id: string;
  timestamp: string;
  event_type: string;
  source: string;
  action: string;
  risk_level: string;
  score: number;
  status: string;
  reason: string;
  metadata: Record<string, any>;
  is_demo: boolean;
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

export const MonitoringPage: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshMessage, setRefreshMessage] = useState<string | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  // Filters
  const [riskFilter, setRiskFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');

  useEffect(() => {
    fetchTelemetryData();
  }, [statusFilter]);

  const fetchTelemetryData = async () => {
    setIsLoading(true);
    setRefreshMessage(null);

    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';

      const [statsRes, eventsRes] = await Promise.all([
        fetch(`${apiHost}/api/security/stats`),
        fetch(
          `${apiHost}/api/security/events${
            statusFilter !== 'ALL' ? `?status=${statusFilter}` : ''
          }`
        ),
      ]);

      if (!statsRes.ok || !eventsRes.ok) {
        throw new Error('Telemetry API request failed.');
      }

      const [statsData, eventsData] = await Promise.all([
        statsRes.json(),
        eventsRes.json(),
      ]);

      setStats(statsData);
      setEvents(eventsData);
      setRefreshMessage(
        `Telemetry refreshed successfully at ${new Date().toLocaleTimeString()}.`
      );
    } catch {
      setRefreshMessage(
        'Refresh failed. Check your connection to the security API and try again.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  // Filter logic on client for risk & event type
  const filteredEvents = events.filter((e) => {
    if (riskFilter !== 'ALL' && e.risk_level.toUpperCase() !== riskFilter.toUpperCase()) return false;
    if (eventTypeFilter !== 'ALL' && e.event_type.toLowerCase() !== eventTypeFilter.toLowerCase()) return false;
    return true;
  });

  // Calculate System Status dynamically from event telemetry
  const calculateSystemStatus = () => {
    const hasCrit = events.some((e) => e.risk_level === 'CRITICAL');
    const hasReview = events.some((e) => e.status === 'REVIEW' || e.risk_level === 'HIGH');
    if (hasCrit) return { label: 'CRITICAL ACTIVITY DETECTED', color: 'var(--color-danger)', bg: 'var(--color-danger-bg)' };
    if (hasReview) return { label: 'ATTENTION REQUIRED — GATEWAY ENFORCING', color: 'var(--color-warning)', bg: 'var(--color-warning-bg)' };
    return { label: 'SYSTEM PROTECTED — GATEWAY ENFORCING', color: 'var(--color-safe)', bg: 'var(--color-safe-bg)' };
  };

  const sysStatus = calculateSystemStatus();

  // Metrics calculations
  const totalThreats = events.filter((e) => e.risk_level !== 'LOW').length;
  const highCritThreats = events.filter((e) => e.risk_level === 'HIGH' || e.risk_level === 'CRITICAL').length;
  const blockedActions = events.filter((e) => e.status === 'BLOCKED').length;
  const pendingApprovals = stats?.status_breakdown.REVIEW || 0;

  // Risk Distribution counts
  const riskCounts = {
    LOW: events.filter((e) => e.risk_level === 'LOW').length,
    MEDIUM: events.filter((e) => e.risk_level === 'MEDIUM').length,
    HIGH: events.filter((e) => e.risk_level === 'HIGH').length,
    CRITICAL: events.filter((e) => e.risk_level === 'CRITICAL').length
  };
  const totalRiskEvents = events.length || 1;

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'LOW': return <span className="badge badge-safe">LOW</span>;
      case 'MEDIUM': return <span className="badge badge-warning">MEDIUM</span>;
      case 'HIGH': return <span className="badge badge-danger">HIGH</span>;
      case 'CRITICAL': return <span className="badge badge-danger" style={{ backgroundColor: '#7f1d1d', color: '#fca5a5' }}>CRITICAL</span>;
      default: return <span className="badge badge-neutral">{level}</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'ALLOWED': return <span className="badge badge-safe">ALLOWED</span>;
      case 'APPROVED': return <span className="badge badge-safe">APPROVED</span>;
      case 'REVIEW': return <span className="badge badge-warning">REVIEW</span>;
      case 'BLOCKED': return <span className="badge badge-danger">BLOCKED</span>;
      case 'REJECTED': return <span className="badge badge-danger">REJECTED</span>;
      default: return <span className="badge badge-neutral">{status}</span>;
    }
  };

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Real-Time Security Event Monitoring</h1>
          <p className="page-description">
            Live telemetry, rule execution audit log, and server-side decision stream.
          </p>
        </div>

        <div>
          <button className="btn btn-secondary" onClick={fetchTelemetryData} disabled={isLoading}>
            <RefreshCw size={14} className={isLoading ? 'spin' : ''} /> Refresh Telemetry
          </button>
          {refreshMessage && (
            <p
              style={{
                marginTop: '0.5rem',
                fontSize: '0.8rem',
                color: refreshMessage.startsWith('Refresh failed') ? '#ef4444' : '#22c55e',
                textAlign: 'right',
              }}
            >
              {refreshMessage}
            </p>
          )}
        </div>

      </div>

      {/* System Status Banner */}
      <div
        className="card"
        style={{
          marginBottom: '1.5rem',
          backgroundColor: sysStatus.bg,
          borderColor: sysStatus.color,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div className="status-indicator-dot" style={{ width: '10px', height: '10px', backgroundColor: sysStatus.color }}></div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '1.05rem', color: sysStatus.color }}>{sysStatus.label}</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
              All permission evaluations enforced server-side. Append-only tamper-resistant log active.
            </div>
          </div>
        </div>
        <span className="badge badge-neutral" style={{ fontFamily: 'var(--font-mono)' }}>
          Active Rules: {stats?.active_rules_count || 18}
        </span>
      </div>

      {/* KPI Cards */}
      <div className="grid-cols-4" style={{ marginBottom: '1.75rem' }}>
        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Threats Flagged</span>
            <Activity size={18} style={{ color: 'var(--color-primary)' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
            {totalThreats}
          </div>
          <div className="badge badge-primary" style={{ marginTop: '0.4rem' }}>Live Telemetry</div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">High / Critical Threats</span>
            <ShieldAlert size={18} style={{ color: 'var(--color-danger)' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-danger)', fontFamily: 'var(--font-mono)' }}>
            {highCritThreats}
          </div>
          <div className="badge badge-danger" style={{ marginTop: '0.4rem' }}>Priority Action</div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Blocked Actions</span>
            <AlertOctagon size={18} style={{ color: 'var(--color-warning)' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-warning)', fontFamily: 'var(--font-mono)' }}>
            {blockedActions}
          </div>
          <div className="badge badge-warning" style={{ marginTop: '0.4rem' }}>Gateway Intercepted</div>
        </div>

        <div className="card">
          <div className="card-header">
            <span className="card-subtitle">Pending Approvals</span>
            <Lock size={18} style={{ color: 'var(--color-safe)' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: 'var(--color-safe)', fontFamily: 'var(--font-mono)' }}>
            {pendingApprovals}
          </div>
          <div className="badge badge-safe" style={{ marginTop: '0.4rem' }}>Human Gate Pause</div>
        </div>
      </div>

      {/* Risk Distribution Chart Visualization (Accessible CSS-based) */}
      <div className="card" style={{ marginBottom: '1.75rem' }}>
        <div className="card-header">
          <div className="card-title">
            <Shield size={18} style={{ color: 'var(--color-primary)' }} />
            Telemetry Risk Distribution Breakdown
          </div>
          <span className="badge badge-neutral">Total Events: {events.length}</span>
        </div>

        <div style={{ display: 'flex', height: '24px', borderRadius: 'var(--radius-sm)', overflow: 'hidden', backgroundColor: 'var(--bg-app)', margin: '0.75rem 0' }}>
          <div style={{ width: `${(riskCounts.LOW / totalRiskEvents) * 100}%`, backgroundColor: 'var(--color-safe)' }} title={`LOW: ${riskCounts.LOW}`} />
          <div style={{ width: `${(riskCounts.MEDIUM / totalRiskEvents) * 100}%`, backgroundColor: 'var(--color-warning)' }} title={`MEDIUM: ${riskCounts.MEDIUM}`} />
          <div style={{ width: `${(riskCounts.HIGH / totalRiskEvents) * 100}%`, backgroundColor: '#f97316' }} title={`HIGH: ${riskCounts.HIGH}`} />
          <div style={{ width: `${(riskCounts.CRITICAL / totalRiskEvents) * 100}%`, backgroundColor: 'var(--color-danger)' }} title={`CRITICAL: ${riskCounts.CRITICAL}`} />
        </div>

        <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', fontSize: '0.8rem', marginTop: '0.5rem' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--color-safe)' }}></span>
            LOW: {riskCounts.LOW} ({Math.round((riskCounts.LOW / totalRiskEvents) * 100)}%)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--color-warning)' }}></span>
            MEDIUM: {riskCounts.MEDIUM} ({Math.round((riskCounts.MEDIUM / totalRiskEvents) * 100)}%)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: '#f97316' }}></span>
            HIGH: {riskCounts.HIGH} ({Math.round((riskCounts.HIGH / totalRiskEvents) * 100)}%)
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ width: '10px', height: '10px', borderRadius: '2px', backgroundColor: 'var(--color-danger)' }}></span>
            CRITICAL: {riskCounts.CRITICAL} ({Math.round((riskCounts.CRITICAL / totalRiskEvents) * 100)}%)
          </span>
        </div>
      </div>

      {/* Security Event Table with Filters */}
      <div className="card">
        <div className="card-header" style={{ flexWrap: 'wrap', gap: '1rem' }}>
          <div className="card-title">
            <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
            Security Event Audit Feed ({filteredEvents.length})
          </div>

          {/* Filter Bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <Filter size={14} /> Filter:
            </div>

            {/* Risk Filter */}
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              style={{
                backgroundColor: 'var(--bg-input)',
                border: '1px solid var(--border-card)',
                color: 'var(--text-primary)',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem'
              }}
            >
              <option value="ALL">Risk: ALL</option>
              <option value="LOW">Risk: LOW</option>
              <option value="MEDIUM">Risk: MEDIUM</option>
              <option value="HIGH">Risk: HIGH</option>
              <option value="CRITICAL">Risk: CRITICAL</option>
            </select>

            {/* Status Filter */}
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{
                backgroundColor: 'var(--bg-input)',
                border: '1px solid var(--border-card)',
                color: 'var(--text-primary)',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem'
              }}
            >
              <option value="ALL">Status: ALL</option>
              <option value="ALLOWED">ALLOWED</option>
              <option value="BLOCKED">BLOCKED</option>
              <option value="REVIEW">REVIEW</option>
              <option value="APPROVED">APPROVED</option>
              <option value="REJECTED">REJECTED</option>
            </select>

            {/* Event Type Filter */}
            <select
              value={eventTypeFilter}
              onChange={(e) => setEventTypeFilter(e.target.value)}
              style={{
                backgroundColor: 'var(--bg-input)',
                border: '1px solid var(--border-card)',
                color: 'var(--text-primary)',
                padding: '0.35rem 0.65rem',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.8rem'
              }}
            >
              <option value="ALL">Type: ALL</option>
              <option value="url_scan">URL Scans</option>
              <option value="message_scan">Message Scans</option>
              <option value="prompt_scan">Prompt Scans</option>
              <option value="tool_request">Tool Requests</option>
            </select>
          </div>
        </div>

        {/* Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border-card)', color: 'var(--text-muted)' }}>
                <th style={{ padding: '0.75rem 1rem' }}>Time</th>
                <th style={{ padding: '0.75rem 1rem' }}>Event Action</th>
                <th style={{ padding: '0.75rem 1rem' }}>Type</th>
                <th style={{ padding: '0.75rem 1rem' }}>Risk Level</th>
                <th style={{ padding: '0.75rem 1rem' }}>Score</th>
                <th style={{ padding: '0.75rem 1rem' }}>Status</th>
                <th style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No security events matched the selected filters.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => (
                  <tr
                    key={evt.event_id}
                    style={{
                      borderBottom: '1px solid var(--border-subtle)',
                      cursor: 'pointer',
                      transition: 'background-color var(--transition-fast)'
                    }}
                    onClick={() => setSelectedEvent(evt)}
                  >
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {evt.timestamp.split('T')[1]?.substring(0, 8) || evt.timestamp}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontWeight: 500, color: 'var(--text-primary)' }}>
                      {evt.action}
                      {evt.is_demo && <span className="badge badge-neutral" style={{ fontSize: '0.6rem', marginLeft: '0.4rem' }}>DEMO</span>}
                    </td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {evt.event_type}
                    </td>
                    <td style={{ padding: '0.75rem 1rem' }}>{getRiskBadge(evt.risk_level)}</td>
                    <td style={{ padding: '0.75rem 1rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{evt.score}</td>
                    <td style={{ padding: '0.75rem 1rem' }}>{getStatusBadge(evt.status)}</td>
                    <td style={{ padding: '0.75rem 1rem', textAlign: 'right' }}>
                      <button className="btn btn-secondary" style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}>
                        <Eye size={12} /> Details
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Event Detail Modal */}
      {selectedEvent && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            width: '100vw',
            height: '100vh',
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1rem'
          }}
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="card"
            style={{ width: '100%', maxWidth: '600px', maxHeight: '90vh', overflowY: 'auto' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="card-header">
              <div className="card-title">
                <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
                Security Event Inspection
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: '0.25rem 0.5rem' }}
                onClick={() => setSelectedEvent(null)}
              >
                <X size={16} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', fontSize: '0.85rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-primary)' }}>{selectedEvent.event_id}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Timestamp:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{selectedEvent.timestamp}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Source Component:</span>
                <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{selectedEvent.source}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Event Type:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{selectedEvent.event_type}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Risk Assessment:</span>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  {getRiskBadge(selectedEvent.risk_level)}
                  <span className="badge badge-neutral" style={{ fontFamily: 'var(--font-mono)' }}>Score: {selectedEvent.score}/100</span>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-muted)' }}>Gateway Status:</span>
                {getStatusBadge(selectedEvent.status)}
              </div>

              <div style={{ backgroundColor: 'var(--bg-app)', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.25rem' }}>Reason & Policy Explanation:</div>
                <div style={{ color: 'var(--text-primary)', lineHeight: 1.4 }}>{selectedEvent.reason}</div>
              </div>

              {selectedEvent.metadata && Object.keys(selectedEvent.metadata).length > 0 && (
                <div style={{ backgroundColor: '#091322', padding: '0.85rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-accent)' }}>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-primary)', fontWeight: 600, marginBottom: '0.25rem' }}>
                    EVENT METADATA:
                  </div>
                  <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#e2e8f0', whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(selectedEvent.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div style={{ marginTop: '1.25rem', display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn btn-secondary" onClick={() => setSelectedEvent(null)}>
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
