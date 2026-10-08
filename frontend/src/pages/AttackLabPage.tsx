import React, { useState, useEffect } from 'react';
import { Flame, Play, RefreshCw, CheckCircle2, AlertOctagon, Shield } from 'lucide-react';

interface ScenarioResult {
  id: string;
  name: string;
  category: string;
  description: string;
  input_text: string;
  expected_defense: string;
  actual_defense: string;
  risk_level: string;
  score: number;
  status: 'PASS' | 'FAIL';
  explanation: string;
}

interface AttackLabSuiteResult {
  total_scenarios: number;
  passed_scenarios: number;
  failed_scenarios: number;
  protection_score_pct: number;
  overall_status: string;
  results: ScenarioResult[];
}

export const AttackLabPage: React.FC = () => {
  const [suiteResult, setSuiteResult] = useState<AttackLabSuiteResult | null>(null);
  const [isLoadingAll, setIsLoadingAll] = useState(false);
  const [runningScenarioId, setRunningScenarioId] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    handleRunAllTests();
  }, []);

  const handleRunAllTests = async () => {
    setIsLoadingAll(true);
    setErrorMessage(null);
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/attack-lab/suite`);
      if (!res.ok) throw new Error('Failed to run Attack Lab suite');
      const data: AttackLabSuiteResult = await res.json();
      setSuiteResult(data);
    } catch (err: any) {
      setErrorMessage('Unable to connect to Attack Lab API at http://localhost:8000.');
    } finally {
      setIsLoadingAll(false);
    }
  };

  const handleRunSingleTest = async (scenarioId: string) => {
    setRunningScenarioId(scenarioId);
    setErrorMessage(null);
    try {
      const apiHost = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const res = await fetch(`${apiHost}/api/attack-lab/scenario/${scenarioId}`, {
        method: 'POST'
      });
      if (!res.ok) throw new Error('Failed to run scenario');
      const updatedScenario: ScenarioResult = await res.json();

      if (suiteResult) {
        const updatedResults = suiteResult.results.map((scen) =>
          scen.id === scenarioId ? updatedScenario : scen
        );
        const passed = updatedResults.filter((r) => r.status === 'PASS').length;
        const total = updatedResults.length;
        const pct = Math.round((passed / total) * 100);

        setSuiteResult({
          ...suiteResult,
          passed_scenarios: passed,
          failed_scenarios: total - passed,
          protection_score_pct: pct,
          results: updatedResults
        });
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to run test scenario.');
    } finally {
      setRunningScenarioId(null);
    }
  };

  const getRiskBadge = (level: string) => {
    switch (level) {
      case 'LOW': return <span className="badge badge-safe">LOW</span>;
      case 'MEDIUM': return <span className="badge badge-warning">MEDIUM</span>;
      case 'HIGH': return <span className="badge badge-danger">HIGH</span>;
      case 'CRITICAL': return <span className="badge badge-danger" style={{ backgroundColor: '#7f1d1d', color: '#fca5a5' }}>CRITICAL</span>;
      default: return <span className="badge badge-neutral">{level}</span>;
    }
  };

  return (
    <div className="page-container">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Defensive Attack Lab & Security Sandbox</h1>
          <p className="page-description">
            Evaluate deterministic rule defenses against adversarial prompts, jailbreaks, and unauthorized tool calls.
          </p>
        </div>
        <button className="btn btn-primary" onClick={handleRunAllTests} disabled={isLoadingAll}>
          {isLoadingAll ? <RefreshCw size={14} className="spin" /> : <Play size={14} />} RUN ALL TESTS
        </button>
      </div>

      {/* Safe Sandbox Banner */}
      <div className="card" style={{ marginBottom: '1.5rem', borderColor: 'var(--color-primary-border)', backgroundColor: 'var(--color-primary-bg)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Shield size={20} style={{ color: 'var(--color-primary)' }} />
          <div>
            <div style={{ fontWeight: 600, color: 'var(--color-primary)' }}>SAFE DEFENSIVE TESTING ENVIRONMENT</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
              All tests execute against local deterministic security rules. No external web traffic or shell commands are performed.
            </div>
          </div>
        </div>
      </div>

      {/* Summary Score Banner */}
      {suiteResult && (
        <div className="card" style={{ marginBottom: '1.75rem' }}>
          <div className="card-header">
            <div>
              <span className="card-subtitle">System Security Protection Score</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginTop: '0.35rem' }}>
                <span style={{ fontSize: '2.5rem', fontWeight: 800, color: suiteResult.protection_score_pct >= 80 ? 'var(--color-safe)' : 'var(--color-warning)', fontFamily: 'var(--font-mono)' }}>
                  {suiteResult.protection_score_pct}%
                </span>
                <span className={`badge badge-${suiteResult.protection_score_pct >= 80 ? 'safe' : 'warning'}`}>
                  {suiteResult.overall_status}
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: '1rem', textAlign: 'right' }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>PASSED</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--color-safe)' }}>
                  {suiteResult.passed_scenarios} / {suiteResult.total_scenarios}
                </div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>FAILED</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--color-danger)' }}>
                  {suiteResult.failed_scenarios}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error Alert */}
      {errorMessage && (
        <div className="card" style={{ borderColor: 'var(--color-danger-border)', backgroundColor: 'var(--color-danger-bg)', color: '#fca5a5', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertOctagon size={20} style={{ color: 'var(--color-danger)' }} />
            <div>
              <div style={{ fontWeight: 600 }}>Attack Lab Error</div>
              <div style={{ fontSize: '0.85rem' }}>{errorMessage}</div>
            </div>
          </div>
        </div>
      )}

      {/* Test Scenarios Grid */}
      {suiteResult && (
        <div className="grid-cols-2">
          {suiteResult.results.map((scen) => (
            <div key={scen.id} className="card" style={{ borderColor: scen.status === 'PASS' ? 'var(--border-card)' : 'var(--color-danger-border)' }}>
              <div className="card-header">
                <div>
                  <div className="card-title">
                    <Flame size={16} style={{ color: 'var(--color-danger)' }} />
                    {scen.name}
                  </div>
                  <div className="card-subtitle">{scen.category}</div>
                </div>
                {scen.status === 'PASS' ? (
                  <span className="badge badge-safe" style={{ fontSize: '0.8rem' }}>
                    <CheckCircle2 size={13} /> PASS
                  </span>
                ) : (
                  <span className="badge badge-danger" style={{ fontSize: '0.8rem' }}>
                    <AlertOctagon size={13} /> FAIL
                  </span>
                )}
              </div>

              <p style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.85rem' }}>
                {scen.description}
              </p>

              {/* Input Box */}
              <div style={{ backgroundColor: 'var(--bg-app)', border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', padding: '0.65rem 0.85rem', marginBottom: '0.85rem' }}>
                <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.2rem' }}>TEST INPUT PAYLOAD:</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-primary)', wordBreak: 'break-word' }}>
                  {scen.input_text}
                </div>
              </div>

              {/* Defense Specs */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.85rem', fontSize: '0.8rem' }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Expected: </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text-primary)' }}>{scen.expected_defense}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Actual: </span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--color-primary)' }}>{scen.actual_defense}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Risk: </span>
                  {getRiskBadge(scen.risk_level)}
                </div>
              </div>

              {/* Rule Explanation */}
              <div style={{ backgroundColor: '#091322', padding: '0.65rem 0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-subtle)', marginBottom: '1rem', fontSize: '0.8rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Defense Rationale: </span>
                <span style={{ color: 'var(--text-primary)' }}>{scen.explanation}</span>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: '0.75rem', padding: '0.3rem 0.75rem' }}
                  onClick={() => handleRunSingleTest(scen.id)}
                  disabled={runningScenarioId === scen.id}
                >
                  {runningScenarioId === scen.id ? (
                    <RefreshCw size={12} className="spin" />
                  ) : (
                    <Play size={12} />
                  )}
                  Run Test
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
