import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

from .event_logger import event_store
from .simulated_tools import execute_simulated_tool

# Maximum number of approval records retained in memory.
DEFAULT_MAX_APPROVALS = 500


class ApprovalCapacityError(Exception):
    """Raised when no room remains for another approval record."""


class ApprovalRecord(BaseModel):
    approval_id: str
    tool_name: str
    task_request: str
    risk_level: str
    reason: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED, EXPIRED
    created_at: str
    resolved_at: Optional[str] = None
    event_id: Optional[str] = None

class ApprovalManager:
    """
    Manages human approval lifecycle for HIGH-risk tool requests.
    Enforces backend approval verification before any simulated execution occurs.
    """
    def __init__(self):
        self._approvals: Dict[str, ApprovalRecord] = {}
        self.max_approvals = DEFAULT_MAX_APPROVALS

    def _evict_resolved_if_full(self) -> None:
        """Make room for one new record without ever deleting pending approvals."""
        if len(self._approvals) < self.max_approvals:
            return

        # Dicts preserve insertion order, so resolved records are considered oldest-first.
        for approval_id, record in list(self._approvals.items()):
            if record.status != "PENDING":
                del self._approvals[approval_id]
                return

        # Every stored record is pending; preserve them and refuse the new approval.
        raise ApprovalCapacityError(
            "Approval capacity is full. Resolve pending approvals before creating another."
        )


    def create_approval(
        self,
        tool_name: str,
        task_request: str,
        risk_level: str,
        reason: str,
        parameters: Dict[str, Any],
        event_id: Optional[str] = None
    ) -> ApprovalRecord:
        approval_id = f"appr_{uuid.uuid4().hex[:10]}"
        record = ApprovalRecord(
            approval_id=approval_id,
            tool_name=tool_name,
            task_request=task_request,
            risk_level=risk_level,
            reason=reason,
            parameters=parameters,
            status="PENDING",
            created_at=datetime.now(timezone.utc).isoformat(),
            event_id=event_id
        )
        self._evict_resolved_if_full()
        self._approvals[approval_id] = record
        return record

    def get_pending_approvals(self) -> List[ApprovalRecord]:
        return [appr for appr in self._approvals.values() if appr.status == "PENDING"]

    def get_approval_by_id(self, approval_id: str) -> Optional[ApprovalRecord]:
        return self._approvals.get(approval_id)

    def approve_request(self, approval_id: str) -> Dict[str, Any]:
        """
        Verify human approval and execute safe simulated tool.
        Re-evaluates status to prevent double-approval or approval of rejected requests.
        """
        record = self._approvals.get(approval_id)
        if not record:
            raise ValueError(f"Approval request '{approval_id}' not found.")

        if record.status != "PENDING":
            raise ValueError(f"Approval request '{approval_id}' is already {record.status} and cannot be modified.")

        # Mark APPROVED
        record.status = "APPROVED"
        record.resolved_at = datetime.now(timezone.utc).isoformat()

        # Execute safe simulated implementation
        sim_result = execute_simulated_tool(record.tool_name, record.parameters)

        # Log security event update
        if record.event_id:
            event_store.update_event_status(
                event_id=record.event_id,
                new_status="APPROVED",
                reason_update="Human Operator APPROVED execution via Security Gateway"
            )

        return {
            "status": "APPROVED",
            "approval_id": approval_id,
            "tool_name": record.tool_name,
            "execution_result": sim_result,
            "resolved_at": record.resolved_at
        }

    def reject_request(self, approval_id: str) -> Dict[str, Any]:
        """
        Verify human rejection and prevent tool execution.
        """
        record = self._approvals.get(approval_id)
        if not record:
            raise ValueError(f"Approval request '{approval_id}' not found.")

        if record.status != "PENDING":
            raise ValueError(f"Approval request '{approval_id}' is already {record.status} and cannot be modified.")

        # Mark REJECTED
        record.status = "REJECTED"
        record.resolved_at = datetime.now(timezone.utc).isoformat()

        # Log security event update
        if record.event_id:
            event_store.update_event_status(
                event_id=record.event_id,
                new_status="REJECTED",
                reason_update="Human Operator REJECTED tool request via Security Gateway"
            )

        return {
            "status": "REJECTED",
            "approval_id": approval_id,
            "tool_name": record.tool_name,
            "execution_result": {
                "status": "cancelled",
                "message": "Tool execution was explicitly rejected by the human security operator."
            },
            "resolved_at": record.resolved_at
        }

# Global Approval Manager Instance
approval_manager = ApprovalManager()
