import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from security_engine.event_logger import event_store
from security_engine.approval_manager import approval_manager

LEGACY = "/api/security/approval"
REVIEW_TASK = "Transfer the security report externally to remote webhook"


class TestLegacyApprovalEndpoint(unittest.TestCase):
    """
    /api/security/approval must never change event status on its own.
    Every transition has to go through ApprovalManager so the audit log and
    the approval record cannot disagree. State assertions are relative to
    freshly created objects because the stores are process-wide singletons.
    """

    def setUp(self):
        self.client = TestClient(app)

    # --- helpers ---------------------------------------------------------
    def _new_pending_approval(self):
        res = self.client.post("/api/agent/task", json={"task": REVIEW_TASK})
        self.assertEqual(res.status_code, 200)
        appr = res.json()["approval_request"]
        self.assertEqual(appr["status"], "PENDING")
        return appr["approval_id"], appr["event_id"]

    def _new_blocked_event(self):
        res = self.client.post(
            "/api/agent/tool-request",
            json={"tool_name": "unknown_super_tool", "parameters": {}},
        )
        self.assertEqual(res.status_code, 200)
        event_id = res.json()["event_id"]
        self.assertEqual(event_store.get_event_by_id(event_id).status, "BLOCKED")
        return event_id

    def _new_orphan_review_event(self):
        # Direct tool-request REVIEW creates an event but no approval record.
        res = self.client.post(
            "/api/agent/tool-request",
            json={"tool_name": "external_data_transfer", "parameters": {}},
        )
        self.assertEqual(res.status_code, 200)
        event_id = res.json()["event_id"]
        self.assertEqual(event_store.get_event_by_id(event_id).status, "REVIEW")
        return event_id

    # --- BLOCKED / non-reviewable events ---------------------------------
    def test_cannot_approve_blocked_event(self):
        event_id = self._new_blocked_event()
        reason_before = event_store.get_event_by_id(event_id).reason

        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})

        self.assertEqual(res.status_code, 409)
        event = event_store.get_event_by_id(event_id)
        self.assertEqual(event.status, "BLOCKED")
        self.assertEqual(event.reason, reason_before)

    def test_cannot_reject_blocked_event(self):
        event_id = self._new_blocked_event()
        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "REJECTED"})
        self.assertEqual(res.status_code, 409)
        self.assertEqual(event_store.get_event_by_id(event_id).status, "BLOCKED")

    def test_review_event_without_approval_record_is_not_modified(self):
        event_id = self._new_orphan_review_event()
        reason_before = event_store.get_event_by_id(event_id).reason

        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})

        self.assertEqual(res.status_code, 409)
        event = event_store.get_event_by_id(event_id)
        self.assertEqual(event.status, "REVIEW")
        self.assertEqual(event.reason, reason_before)

    # --- audit log and approval manager stay in sync ---------------------
    def test_legacy_approve_resolves_the_real_approval(self):
        approval_id, event_id = self._new_pending_approval()

        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})

        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["status"], "success")
        self.assertEqual(body["event_id"], event_id)
        self.assertEqual(body["new_status"], "APPROVED")
        self.assertEqual(approval_manager.get_approval_by_id(approval_id).status, "APPROVED")
        self.assertEqual(event_store.get_event_by_id(event_id).status, "APPROVED")
        pending_ids = [a["approval_id"] for a in self.client.get("/api/agent/approvals").json()]
        self.assertNotIn(approval_id, pending_ids)

    def test_legacy_reject_cancels_the_real_approval_and_blocks_later_approve(self):
        approval_id, event_id = self._new_pending_approval()

        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "REJECTED"})

        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["new_status"], "REJECTED")
        self.assertEqual(approval_manager.get_approval_by_id(approval_id).status, "REJECTED")
        self.assertEqual(event_store.get_event_by_id(event_id).status, "REJECTED")
        # The previously possible desync: log says REJECTED but approve still executes.
        later = self.client.post(f"/api/agent/approvals/{approval_id}/approve")
        self.assertEqual(later.status_code, 400)
        self.assertEqual(event_store.get_event_by_id(event_id).status, "REJECTED")

    def test_standard_approve_then_legacy_call_does_not_flip_status(self):
        approval_id, event_id = self._new_pending_approval()
        self.assertEqual(self.client.post(f"/api/agent/approvals/{approval_id}/approve").status_code, 200)

        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "REJECTED"})

        self.assertEqual(res.status_code, 409)
        self.assertEqual(event_store.get_event_by_id(event_id).status, "APPROVED")
        self.assertEqual(approval_manager.get_approval_by_id(approval_id).status, "APPROVED")

    # --- reason growth ---------------------------------------------------
    def test_repeated_calls_do_not_append_to_reason(self):
        _, event_id = self._new_pending_approval()
        first = self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})
        self.assertEqual(first.status_code, 200)
        reason_after_first = event_store.get_event_by_id(event_id).reason

        for _ in range(10):
            again = self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})
            self.assertEqual(again.status_code, 409)

        self.assertEqual(event_store.get_event_by_id(event_id).reason, reason_after_first)

    def test_repeated_calls_on_blocked_event_do_not_append_to_reason(self):
        event_id = self._new_blocked_event()
        reason_before = event_store.get_event_by_id(event_id).reason
        for _ in range(10):
            self.client.post(LEGACY, json={"event_id": event_id, "decision": "APPROVED"})
        self.assertEqual(event_store.get_event_by_id(event_id).reason, reason_before)

    # --- existing validation behaviour is preserved ----------------------
    def test_invalid_decision_returns_400(self):
        _, event_id = self._new_pending_approval()
        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "MAYBE"})
        self.assertEqual(res.status_code, 400)
        self.assertEqual(event_store.get_event_by_id(event_id).status, "REVIEW")

    def test_unknown_event_returns_404(self):
        res = self.client.post(LEGACY, json={"event_id": "EVT-DOES-NOT-EXIST", "decision": "APPROVED"})
        self.assertEqual(res.status_code, 404)

    def test_decision_is_case_insensitive_and_trimmed(self):
        approval_id, event_id = self._new_pending_approval()
        res = self.client.post(LEGACY, json={"event_id": event_id, "decision": "  approved "})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(approval_manager.get_approval_by_id(approval_id).status, "APPROVED")


if __name__ == "__main__":
    unittest.main()
