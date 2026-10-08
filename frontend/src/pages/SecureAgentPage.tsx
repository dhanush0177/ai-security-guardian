import React, { useState, useEffect } from 'react';
import { Cpu, ShieldCheck, Lock, Play, AlertTriangle, CheckCircle2, ShieldAlert, AlertOctagon, RefreshCw, Clock, Check, X, Terminal } from 'lucide-react';

interface AgentPlanStep {
  step_number: number;
  title: string;
  description: string;
  status: 'COMPLETED' | 'IN_PROGRESS' | 'WAITING_HUMAN' | 'BLOCKED' | 'FAILED';
}

interface TimelineEvent {
  timestamp: string;
  label: string;
  detail: string;
  type: string;
}

interface ApprovalRecord {
  approval_id: string;
  tool_name: string;
  task_request: string;
  risk_level: string;
  reason: string;
  status: string;
  created_at: string;
  resolved_at?: string;
}

interface AgentTaskResponse {
  task_id: string;
  user_task: string;
  selected_tool?: string;
  plan: AgentPlanStep[];
  gateway_decision: 'ALLOW' | 'BLOCK' | 'REVIEW' | 'NONE';
  risk_level: string;
  score: number;
  status: 'COMPLETED' | 'WAITING_APPROVAL' | 'BLOCKED' | 'UNKNOWN_TASK';
  explanation: string;
  timeline: TimelineEvent[];
  execution_result?: any;
  approval_request?: ApprovalRecord;
}

export const SecureAgentPage: React.FC = () => {
  const [taskInput, setTaskInput] = useState('Analyze this URL: https://example.com');
  const [isLoading, setIsLoading] = useState(false);
  const [taskResult, setTaskResult] = useState<AgentTaskResponse | null>(null);
  const [pendingApprovals, setPendingApprovals] = useState<ApprovalRecord[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const demoScenarios = [
    {
      label: '1. Safe URL Scan (LOW Risk)',
      task: 'Analyze this URL: https://example.com'
    },
    {
      label: '2. Phishing Scan (MEDIUM Risk)',
      task: 'Check this suspicious phishing message'
    },
    {
      label: '3. Data Transfer (HIGH Risk / Approval Required)',
      task: 'Transfer security report externally to remote webhook'
    },
    {
      label: '4. Delete Logs (CRITICAL Risk / Blocked)',
      task: 'Delete all security audit logs immediately'
    }
  ];

  useEffect(() => {
    fetchPendingApprovals();
  }, []);

  const fetchPendingApprovals = async () => {
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/agent/approvals`);
      if (res.ok) {
        const data = await res.json();
        setPendingApprovals(data);
      }
    } catch {
      // Ignore background poll errors
    }
  };

  const handleRunTask = async (taskTextToRun?: string) => {
    const textToSubmit = (taskTextToRun || taskInput).trim();
    if (!textToSubmit) {
      setErrorMessage('Task description cannot be empty.');
      return;
    }

    setErrorMessage(null);
    setIsLoading(true);

    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/agent/task`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task: textToSubmit })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'Failed to run task.' }));
        throw new Error(errData.detail || `Server returned HTTP status ${res.status}`);
      }

      const data: AgentTaskResponse = await res.json();
      setTaskResult(data);
      await fetchPendingApprovals();
    } catch (err: any) {
      if (err.message && err.message.includes('Failed to fetch')) {
        setErrorMessage('Unable to connect to AI Security Guardian API (http://localhost:8000). Ensure backend is active.');
      } else {
        setErrorMessage(err.message || 'An error occurred while dispatching the agent task.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleApprove = async (approvalId: string) => {
    setErrorMessage(null);
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/agent/approvals/${approvalId}/approve`, {
        method: 'POST'
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'Failed to approve action.' }));
        throw new Error(errData.detail || 'Approval failed');
      }

      const resData = await res.json();
      
      if (taskResult && taskResult.approval_request?.approval_id === approvalId) {
        setTaskResult({
          ...taskResult,
          status: 'COMPLETED',
          gateway_decision: 'ALLOW',
          explanation: 'Human Operator APPROVED action. Safe simulated execution completed.',
          execution_result: resData.execution_result,
          approval_request: undefined
        });
      }

      await fetchPendingApprovals();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to process approval.');
    }
  };

  const handleReject = async (approvalId: string) => {
    setErrorMessage(null);
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/agent/approvals/${approvalId}/reject`, {
        method: 'POST'
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({ detail: 'Failed to reject action.' }));
        throw new Error(errData.detail || 'Rejection failed');
      }

      if (taskResult && taskResult.approval_request?.approval_id === approvalId) {
        setTaskResult({
          ...taskResult,
          status: 'BLOCKED',
          gateway_decision: 'BLOCK',
          explanation: 'Human Operator REJECTED tool execution. Action cancelled.',
          execution_result: { status: 'cancelled', message: 'Action rejected by operator.' },
          approval_request: undefined
        });
      }

      await fetchPendingApprovals();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to process rejection.');
    }
  };

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'LOW':
        return <span className="badge badge-safe"><CheckCircle2 size={12} /> LOW</span>;
      case 'MEDIUM':
        return <span className="badge badge-warning"><AlertTriangle size={12} /> MEDIUM</span>;
      case 'HIGH':
        return <span className="badge badge-danger"><ShieldAlert size={12} /> HIGH</span>;
      case 'CRITICAL':
        return <span className="badge badge-danger" style={{ backgroundColor: '#7f1d1d', color: '#fca5a5' }}><AlertOctagon size={12} /> CRITICAL</span>;
      default:
        return <span className="badge badge-neutral">{level}</span>;
    }
  };

  const getDecisionBadge = (decision: string) => {
    switch (decision) {
      case 'ALLOW':
        return <span className="badge badge-safe"><CheckCircle2 size={12} /> ALLOWED</span>;
      case 'REVIEW':
        return <span className="badge badge-warning"><Lock size={12} /> HUMAN REVIEW REQUIRED</span>;
      case 'BLOCK':
        return <span className="badge badge-danger"><AlertOctagon size={12} /> BLOCKED</span>;
      default:
        return <span className="badge badge-neutral">NONE</span>;
    }
  };

  return (
    <div className="page-container">
      <div className="page-header">
        <h1 className="page-title">Secure AI Agent Playground</h1>
        <p className="page-description">
          Agent planner monitored by server-side Permission Gateway policies and human operator approval gates.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '1.5rem', alignItems: 'start' }}>
        
        {/* Left Column: Task Input, Plan, and Timeline */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Task Dispatcher Card */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <Cpu size={18} style={{ color: 'var(--color-primary)' }} />
                Agent Task Command Center
              </div>
              <span className="badge badge-primary">Server-Gated Execution</span>
            </div>

            {/* Demo Scenario Buttons */}
            <div style={{ marginBottom: '1rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Demo Scenarios:</span>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {demoScenarios.map((scen, idx) => (
                  <button
                    key={idx}
                    className="btn btn-secondary"
                    style={{ fontSize: '0.75rem', padding: '0.3rem 0.65rem' }}
                    onClick={() => {
                      setTaskInput(scen.task);
                      handleRunTask(scen.task);
                    }}
                  >
                    {scen.label}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <textarea
                rows={3}
                value={taskInput}
                onChange={(e) => setTaskInput(e.target.value)}
                placeholder="Ask the security agent to analyze a URL, inspect a message, generate a report, or transfer data..."
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  backgroundColor: 'var(--bg-input)',
                  border: '1px solid var(--border-card)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-sans)',
                  fontSize: '0.9rem',
                  resize: 'vertical'
                }}
              />

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  className="btn btn-primary"
                  onClick={() => handleRunTask()}
                  disabled={isLoading}
                  style={{ minWidth: '180px' }}
                >
                  {isLoading ? (
                    <>
                      <RefreshCw size={16} className="spin" /> Dispatching...
                    </>
                  ) : (
                    <>
                      <Play size={16} /> Run Security Task
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Error Banner */}
          {errorMessage && (
            <div className="card" style={{ borderColor: 'var(--color-danger-border)', backgroundColor: 'var(--color-danger-bg)', color: '#fca5a5' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <AlertOctagon size={20} style={{ color: 'var(--color-danger)' }} />
                <div>
                  <div style={{ fontWeight: 600 }}>Task Execution Error</div>
                  <div style={{ fontSize: '0.85rem', marginTop: '0.2rem' }}>{errorMessage}</div>
                </div>
              </div>
            </div>
          )}

          {/* Agent Plan Visualization */}
          {taskResult && (
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <Terminal size={18} style={{ color: 'var(--color-primary)' }} />
                  Agent Execution Plan
                </div>
                <span className="badge badge-neutral">Plan ID: {taskResult.task_id}</span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '0.75rem', marginBottom: '1.25rem' }}>
                {taskResult.plan.map((step) => (
                  <div
                    key={step.step_number}
                    style={{
                      backgroundColor: 'var(--bg-app)',
                      border: `1px solid ${
                        step.status === 'COMPLETED'
                          ? 'var(--color-safe-border)'
                          : step.status === 'WAITING_HUMAN'
                          ? 'var(--color-warning-border)'
                          : step.status === 'BLOCKED'
                          ? 'var(--color-danger-border)'
                          : 'var(--border-subtle)'
                      }`,
                      borderRadius: 'var(--radius-md)',
                      padding: '0.75rem'
                    }}
                  >
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>
                      STEP 0{step.step_number}
                    </div>
                    <div style={{ fontWeight: 600, fontSize: '0.85rem', marginTop: '0.2rem', color: 'var(--text-primary)' }}>
                      {step.title}
                    </div>
                    <div style={{ marginTop: '0.5rem' }}>
                      {step.status === 'COMPLETED' && <span className="badge badge-safe" style={{ fontSize: '0.65rem' }}>Done</span>}
                      {step.status === 'WAITING_HUMAN' && <span className="badge badge-warning" style={{ fontSize: '0.65rem' }}>Pause: Gate</span>}
                      {step.status === 'BLOCKED' && <span className="badge badge-danger" style={{ fontSize: '0.65rem' }}>Blocked</span>}
                      {step.status === 'IN_PROGRESS' && <span className="badge badge-primary" style={{ fontSize: '0.65rem' }}>Running</span>}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ backgroundColor: 'var(--bg-app)', padding: '1rem', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
                <div style={{ fontWeight: 600, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Gateway Explanation:</div>
                <p style={{ fontSize: '0.9rem', color: 'var(--text-primary)', marginTop: '0.25rem' }}>{taskResult.explanation}</p>
              </div>

              {/* Execution Result Box */}
              {taskResult.execution_result && (
                <div style={{ marginTop: '1rem', backgroundColor: '#091322', border: '1px solid var(--border-accent)', borderRadius: 'var(--radius-md)', padding: '1rem' }}>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-primary)', fontWeight: 600, marginBottom: '0.4rem' }}>
                    EXECUTION OUTPUT:
                  </div>
                  <pre style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#e2e8f0', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                    {JSON.stringify(taskResult.execution_result, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* Timeline Feed */}
          {taskResult && (
            <div className="card">
              <div className="card-header">
                <div className="card-title">
                  <Clock size={18} style={{ color: 'var(--text-secondary)' }} />
                  Agent Execution Timeline
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                {taskResult.timeline.map((evt, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.85rem', fontSize: '0.85rem' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)', width: '65px', flexShrink: 0 }}>
                      {evt.timestamp}
                    </span>
                    <div style={{ flex: 1, backgroundColor: 'var(--bg-app)', padding: '0.55rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)' }}>
                      <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{evt.label}: </span>
                      <span style={{ color: 'var(--text-secondary)' }}>{evt.detail}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Permission Gateway Panel & Human Approvals */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
          
          {/* Permission Gateway Monitor */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">
                <ShieldCheck size={18} style={{ color: 'var(--color-safe)' }} />
                Gateway Status
              </div>
              <span className="badge badge-safe">Enforcing</span>
            </div>

            {taskResult ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Selected Tool:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                    {taskResult.selected_tool || 'None'}
                  </span>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Tool Risk Level:</span>
                  {getRiskBadge(taskResult.risk_level)}
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Gateway Decision:</span>
                  {getDecisionBadge(taskResult.gateway_decision)}
                </div>
              </div>
            ) : (
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                Submit a task to observe server-side permission gateway evaluations in real-time.
              </p>
            )}
          </div>

          {/* Active Human Approval Panel */}
          <div className="card" style={{ borderColor: pendingApprovals.length > 0 ? 'var(--color-warning-border)' : 'var(--border-card)' }}>
            <div className="card-header">
              <div className="card-title">
                <Lock size={18} style={{ color: 'var(--color-warning)' }} />
                Human Approval Gate ({pendingApprovals.length})
              </div>
              {pendingApprovals.length > 0 && <span className="badge badge-warning">Action Required</span>}
            </div>

            {pendingApprovals.length === 0 ? (
              <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>
                No high-risk operations currently paused for human approval.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {pendingApprovals.map((appr) => (
                  <div
                    key={appr.approval_id}
                    style={{
                      backgroundColor: 'var(--bg-app)',
                      border: '1px solid var(--color-warning-border)',
                      borderRadius: 'var(--radius-md)',
                      padding: '1rem',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '0.75rem'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: 'var(--color-warning)', fontWeight: 600 }}>
                        ID: {appr.approval_id}
                      </span>
                      {getRiskBadge(appr.risk_level)}
                    </div>

                    <div>
                      <div style={{ fontWeight: 600, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                        Tool: {appr.tool_name}
                      </div>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
                        {appr.reason}
                      </p>
                    </div>

                    {/* Approve & Reject Buttons */}
                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.25rem' }}>
                      <button
                        className="btn btn-primary"
                        style={{ flex: 1, backgroundColor: 'var(--color-safe)', borderColor: 'var(--color-safe-border)', color: '#022c22' }}
                        onClick={() => handleApprove(appr.approval_id)}
                      >
                        <Check size={16} /> APPROVE
                      </button>
                      <button
                        className="btn btn-danger"
                        style={{ flex: 1 }}
                        onClick={() => handleReject(appr.approval_id)}
                      >
                        <X size={16} /> REJECT
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
