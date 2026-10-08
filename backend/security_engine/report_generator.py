from datetime import datetime, timezone
from typing import Dict, Any, List
from pydantic import BaseModel, Field

from .event_logger import event_store

class SecurityReport(BaseModel):
    title: str = "AI SECURITY GUARDIAN — Executive Security Assessment Report"
    generated_at: str
    system_status: str
    executive_summary: str
    threat_summary: Dict[str, int]
    risk_breakdown: Dict[str, int]
    top_events: List[Dict[str, Any]]
    recommendations: List[str]

def generate_security_report() -> SecurityReport:
    """
    Generate an executive security assessment report compiled directly from live event telemetry.
    """
    events = event_store.get_events(limit=200)
    stats = event_store.get_stats()

    # Risk level breakdown
    low_cnt = sum(1 for e in events if e.risk_level == "LOW")
    med_cnt = sum(1 for e in events if e.risk_level == "MEDIUM")
    high_cnt = sum(1 for e in events if e.risk_level == "HIGH")
    crit_cnt = sum(1 for e in events if e.risk_level == "CRITICAL")

    threats_detected = med_cnt + high_cnt + crit_cnt
    high_crit_threats = high_cnt + crit_cnt
    blocked_actions = sum(1 for e in events if e.status == "BLOCKED")
    pending_approvals = stats["status_breakdown"].get("REVIEW", 0)

    # Determine System Status
    if crit_cnt > 0 or stats["status_breakdown"].get("REJECTED", 0) > 2:
        sys_status = "CRITICAL ACTIVITY"
        exec_summary = "CRITICAL THREAT ALERT: High-risk security events and adversarial attempts have been detected and contained by the deterministic Permission Gateway."
    elif high_cnt > 0 or pending_approvals > 0:
        sys_status = "ATTENTION REQUIRED"
        exec_summary = "ATTENTION REQUIRED: High-risk operations or phishing indicators detected. Server-side policies are actively managing tool permissions."
    else:
        sys_status = "PROTECTED"
        exec_summary = "SYSTEM PROTECTED: All AI agent tool invocations and user scans are operating within safe deterministic parameters."

    # Top high-risk events
    high_risk_events = [e for e in events if e.risk_level in ["HIGH", "CRITICAL"]][:10]
    top_events_list = [
        {
            "event_id": e.event_id,
            "timestamp": e.timestamp,
            "event_type": e.event_type,
            "action": e.action,
            "risk_level": e.risk_level,
            "score": e.score,
            "status": e.status,
            "reason": e.reason,
            "is_demo": e.is_demo
        }
        for e in high_risk_events
    ]

    # Generate Actionable Recommendations based on actual event telemetry
    recommendations = [
        "Enforce strict server-side Permission Gateway validation for all AI agent tool invocations."
    ]

    # Check for prompt injections in log
    if any(e.event_type == "prompt_scan" for e in events):
        recommendations.append("Isolate LLM system instructions server-side to prevent system prompt extraction.")

    # Check for phishing/url events
    if any(e.event_type in ["url_scan", "message_scan"] for e in events):
        recommendations.append("Do not enter credentials or OTP codes on unverified domains or external links.")

    # Check for tool approvals
    if pending_approvals > 0 or any(e.status in ["APPROVED", "REJECTED"] for e in events):
        recommendations.append("Require explicit human operator sign-off before approving high-impact tool actions.")

    recommendations.append("Maintain append-only security event audit trails for compliance verification.")

    return SecurityReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        system_status=sys_status,
        executive_summary=exec_summary,
        threat_summary={
            "total_events": len(events),
            "threats_detected": threats_detected,
            "high_critical_threats": high_crit_threats,
            "blocked_actions": blocked_actions,
            "pending_approvals": pending_approvals
        },
        risk_breakdown={
            "LOW": low_cnt,
            "MEDIUM": med_cnt,
            "HIGH": high_cnt,
            "CRITICAL": crit_cnt
        },
        top_events=top_events_list,
        recommendations=recommendations
    )
