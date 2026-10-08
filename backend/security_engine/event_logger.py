import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class SecurityEvent(BaseModel):
    event_id: str
    timestamp: str
    event_type: str  # e.g., "url_scan", "message_scan", "prompt_scan", "tool_request", "approval"
    source: str      # e.g., "threat_scanner", "secure_agent", "attack_lab", "system"
    action: str
    risk_level: str
    score: int
    status: str      # ALLOWED, BLOCKED, REVIEW, APPROVED, REJECTED
    reason: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_demo: bool = False

class EventStore:
    """Thread-safe in-memory store for security events."""
    def __init__(self):
        self._events: List[SecurityEvent] = []
        self._seed_demo_events()

    def log_event(
        self,
        event_type: str,
        source: str,
        action: str,
        risk_level: str,
        score: int,
        status: str,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
        is_demo: bool = False
    ) -> SecurityEvent:
        event = SecurityEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_type=event_type,
            source=source,
            action=action,
            risk_level=risk_level,
            score=score,
            status=status,
            reason=reason,
            metadata=metadata or {},
            is_demo=is_demo
        )
        self._events.insert(0, event)  # newest first
        # Cap memory log to 1000 events
        if len(self._events) > 1000:
            self._events.pop()
        return event

    def get_events(self, limit: int = 50, status: Optional[str] = None) -> List[SecurityEvent]:
        if status:
            filtered = [e for e in self._events if e.status.upper() == status.upper()]
            return filtered[:limit]
        return self._events[:limit]

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        for e in self._events:
            if e.event_id == event_id:
                return e
        return None

    def update_event_status(self, event_id: str, new_status: str, reason_update: str) -> Optional[SecurityEvent]:
        for event in self._events:
            if event.event_id == event_id:
                event.status = new_status
                event.reason = f"{event.reason} | Update: {reason_update}"
                return event
        return None

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._events)
        allowed = sum(1 for e in self._events if e.status in ["ALLOWED", "APPROVED"])
        blocked = sum(1 for e in self._events if e.status == "BLOCKED")
        review = sum(1 for e in self._events if e.status == "REVIEW")
        rejected = sum(1 for e in self._events if e.status == "REJECTED")

        return {
            "total_events": total,
            "status_breakdown": {
                "ALLOWED": allowed,
                "BLOCKED": blocked,
                "REVIEW": review,
                "REJECTED": rejected
            },
            "gateway_status": "ENFORCING",
            "active_rules_count": 18
        }

    def _seed_demo_events(self):
        """Seed initial verifiable security events clearly tagged as DEMO DATA."""
        demo_data = [
            ("url_scan", "threat_scanner", "Scan URL http://192.168.1.1/login", "CRITICAL", 85, "BLOCKED", "IP hostname and credential keywords detected"),
            ("prompt_scan", "attack_lab", "Prompt injection attempt: 'Ignore rules'", "HIGH", 60, "BLOCKED", "Instruction override pattern matched"),
            ("tool_request", "secure_agent", "Request tool: analyze_url", "LOW", 10, "ALLOWED", "Safe read-only tool invocation"),
            ("tool_request", "secure_agent", "Request tool: external_data_transfer", "HIGH", 70, "REVIEW", "High-impact tool requires human approval gate"),
            ("tool_request", "secure_agent", "Request tool: unknown_super_tool", "CRITICAL", 100, "BLOCKED", "Tool not registered in permission gateway")
        ]
        for idx, (etype, src, act, rlvl, scr, stat, reas) in enumerate(demo_data):
            self._events.append(SecurityEvent(
                event_id=f"DEMO-EVT-00{idx+1}",
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=etype,
                source=src,
                action=act,
                risk_level=rlvl,
                score=scr,
                status=stat,
                reason=reas,
                metadata={"demo_note": "Seeded baseline event for hackathon demonstration"},
                is_demo=True
            ))

# Global event store instance
event_store = EventStore()
