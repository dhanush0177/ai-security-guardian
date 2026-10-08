import React, { useState, useEffect } from 'react';
import { FileText, Printer, RefreshCw, CheckSquare, ShieldCheck, AlertOctagon, Terminal, AlertTriangle } from 'lucide-react';

interface SecurityReport {
  title: string;
  generated_at: string;
  system_status: string;
  executive_summary: string;
  threat_summary: {
    total_events: number;
    threats_detected: number;
    high_critical_threats: number;
    blocked_actions: number;
    pending_approvals: number;
  };
  risk_breakdown: {
    LOW: number;
    MEDIUM: number;
    HIGH: number;
    CRITICAL: number;
  };
  top_events: Array<{
    event_id: string;
    timestamp: string;
    event_type: string;
    action: string;
    risk_level: string;
    score: number;
    status: string;
    reason: string;
    is_demo: boolean;
  }>;
  recommendations: string[];
}

export const ReportsPage: React.FC = () => {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchSecurityReport();
  }, []);

  const fetchSecurityReport = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/reports/security`);
      if (!res.ok) throw new Error('Failed to generate report');
      const data: SecurityReport = await res.json();
      setReport(data);
    } catch (err: any) {
      setErrorMessage('Unable to connect to Reports API at http://localhost:8000.');
    } finally {
      setIsLoading(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PROTECTED':
        return <span className="badge badge-safe"><ShieldCheck size={13} /> PROTECTED</span>;
      case 'ATTENTION REQUIRED':
        return <span className="badge badge-warning"><AlertTriangle size={13} /> ATTENTION REQUIRED</span>;
      case 'CRITICAL ACTIVITY':
        return <span className="badge badge-danger" style={{ backgroundColor: '#7f1d1d', color: '#fca5a5' }}><AlertOctagon size={13} /> CRITICAL ACTIVITY</span>;
      default:
        return <span className="badge badge-neutral">{status}</span>;
    }
  };

  return (
    <div className="page-container">
      <style>{`
        @media print {
          .sidebar, .top-header, .btn, .page-header p { display: none !important; }
          .main-wrapper { height: auto !important; overflow: visible !important; }
          .content-area { padding: 0 !important; overflow: visible !important; }
          .card { border: 1px solid #ccc !important; box-shadow: none !important; color: #000 !important; background: #fff !important; }
          body { background: #fff !important; color: #000 !important; }
        }
      `}</style>

      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Security Assessment Reports</h1>
          <p className="page-description">
            Generate executive security audit reports compiled dynamically from backend event telemetry.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={fetchSecurityReport} disabled={isLoading}>
            <RefreshCw size={14} className={isLoading ? 'spin' : ''} /> Generate Report
          </button>
          <button className="btn btn-primary" onClick={handlePrint} disabled={!report}>
            <Printer size={14} /> Print Report
          </button>
        </div>
      </div>

      {errorMessage && (
        <div className="card" style={{ borderColor: 'var(--color-danger-border)', backgroundColor: 'var(--color-danger-bg)', color: '#fca5a5', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertOctagon size={20} style={{ color: 'var(--color-danger)' }} />
            <div>
              <div style={{ fontWeight: 600 }}>Report Error</div>
              <div style={{ fontSize: '0.85rem' }}>{errorMessage}</div>
            </div>
          </div>
        </div>
      )}

      {report && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Executive Summary Card */}
          <div className="card">
            <div className="card-header">
              <div>
                <div className="card-title" style={{ fontSize: '1.2rem' }}>
                  <FileText size={20} style={{ color: 'var(--color-primary)' }} />
                  {report.title}
                </div>
                <div className="card-subtitle" style={{ fontFamily: 'var(--font-mono)', marginTop: '0.2rem' }}>
                  Generated UTC: {report.generated_at}
                </div>
              </div>
              {getStatusBadge(report.system_status)}
            </div>

            <div style={{ backgroundColor: 'var(--bg-app)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)', marginTop: '0.5rem' }}>
              <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>EXECUTIVE SUMMARY:</div>
              <p style={{ color: 'var(--text-primary)', fontSize: '0.95rem', lineHeight: 1.5 }}>{report.executive_summary}</p>
            </div>
          </div>

          {/* Threat Summary & Risk Breakdown Grid */}
          <div className="grid-cols-2">
            
            {/* Threat Metrics */}
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <ShieldCheck size={18} style={{ color: 'var(--color-safe)' }} />
                  Threat Metrics Overview
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Total Evaluated Events:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{report.threat_summary.total_events}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Threats Flagged:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-warning)' }}>{report.threat_summary.threats_detected}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>High / Critical Threats:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-danger)' }}>{report.threat_summary.high_critical_threats}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Gateway Blocked Actions:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-danger)' }}>{report.threat_summary.blocked_actions}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Pending Human Approvals:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-safe)' }}>{report.threat_summary.pending_approvals}</span>
                </div>
              </div>
            </div>

            {/* Risk Breakdown */}
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <ShieldCheck size={18} style={{ color: 'var(--color-primary)' }} />
                  Risk Level Breakdown
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', fontSize: '0.9rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span className="badge badge-safe">LOW RISK (0–24)</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{report.risk_breakdown.LOW}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span className="badge badge-warning">MEDIUM RISK (25–49)</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{report.risk_breakdown.MEDIUM}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.5rem' }}>
                  <span className="badge badge-danger">HIGH RISK (50–74)</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{report.risk_breakdown.HIGH}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="badge badge-danger" style={{ backgroundColor: '#7f1d1d', color: '#fca5a5' }}>CRITICAL RISK (75–100)</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{report.risk_breakdown.CRITICAL}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Top High-Risk Security Events Table */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
                Top High-Risk Audit Events
              </div>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--border-card)', color: 'var(--text-muted)' }}>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Event ID</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Timestamp</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Action</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Risk Level</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Score</th>
                    <th style={{ padding: '0.65rem 0.85rem' }}>Gateway Status</th>
                  </tr>
                </thead>
                <tbody>
                  {report.top_events.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No high-risk security events recorded.
                      </td>
                    </tr>
                  ) : (
                    report.top_events.map((evt) => (
                      <tr key={evt.event_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--color-primary)' }}>{evt.event_id}</td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{evt.timestamp.split('T')[1]?.substring(0, 8)}</td>
                        <td style={{ padding: '0.65rem 0.85rem', color: 'var(--text-primary)' }}>{evt.action}</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>
                          <span className={`badge badge-${evt.risk_level === 'CRITICAL' ? 'danger' : 'warning'}`}>{evt.risk_level}</span>
                        </td>
                        <td style={{ padding: '0.65rem 0.85rem', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{evt.score}</td>
                        <td style={{ padding: '0.65rem 0.85rem' }}>
                          <span className={`badge badge-${evt.status === 'BLOCKED' ? 'danger' : 'warning'}`}>{evt.status}</span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Actionable Recommendations */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <CheckSquare size={18} style={{ color: 'var(--color-safe)' }} />
                Actionable Security Recommendations
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {report.recommendations.map((rec, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.65rem' }}>
                  <ShieldCheck size={16} style={{ color: 'var(--color-safe)', marginTop: '0.15rem', flexShrink: 0 }} />
                  <span style={{ fontSize: '0.9rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
