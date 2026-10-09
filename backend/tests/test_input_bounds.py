import json
import os
import sys
import unittest
from fastapi.testclient import TestClient
from pydantic import ValidationError

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from security_engine.event_logger import event_store
from security_engine.approval_manager import ApprovalManager, ApprovalCapacityError, approval_manager
from security_engine.permission_gateway import permission_gateway, ToolRequest

TOOL_REQUEST = "/api/agent/tool-request"

# Limits under test (kept as literals on purpose: they are the public contract).
MAX_TOOL_NAME = 64
MAX_SOURCE_AGENT = 64
MAX_USER_ROLE = 32
MAX_PARAMETERS_CHARS = 4096  # compact JSON length, counted in characters
DEFAULT_MAX_APPROVALS = 500


def _latest_event_id():
    events = event_store.get_events(limit=1)
    return events[0].event_id if events else None


class TestToolRequestFieldLimits(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def _assert_rejected(self, body):
        """Oversized/invalid input must fail validation (422) and log nothing."""
        before = _latest_event_id()
        res = self.client.post(TOOL_REQUEST, json=body)
        self.assertEqual(res.status_code, 422)
        self.assertIn("detail", res.json())
        self.assertEqual(_latest_event_id(), before)

    def test_valid_requests_are_unchanged(self):
        res = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "parameters": {"url": "https://example.com"}})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["decision"], "ALLOW")

        res = self.client.post(TOOL_REQUEST, json={"tool_name": "external_data_transfer", "parameters": {}})
        self.assertEqual((res.status_code, res.json()["decision"]), (200, "REVIEW"))

        res = self.client.post(TOOL_REQUEST, json={"tool_name": "delete_data"})
        self.assertEqual((res.status_code, res.json()["decision"]), (200, "BLOCK"))

        res = self.client.post(TOOL_REQUEST, json={
            "tool_name": "generate_report", "source_agent": "secure_agent", "user_role": "operator"})
        self.assertEqual(res.status_code, 200)

    def test_empty_tool_name_still_returns_400(self):
        self.assertEqual(self.client.post(TOOL_REQUEST, json={"tool_name": ""}).status_code, 400)
        self.assertEqual(self.client.post(TOOL_REQUEST, json={"tool_name": "   "}).status_code, 400)

    def test_tool_name_length_limit(self):
        res = self.client.post(TOOL_REQUEST, json={"tool_name": "a" * MAX_TOOL_NAME})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["decision"], "BLOCK")  # unregistered, but accepted input
        self._assert_rejected({"tool_name": "a" * (MAX_TOOL_NAME + 1)})
        self._assert_rejected({"tool_name": "x" * 200_000})

    def test_source_agent_length_limit(self):
        ok = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "source_agent": "s" * MAX_SOURCE_AGENT})
        self.assertEqual(ok.status_code, 200)
        self._assert_rejected({"tool_name": "analyze_url", "source_agent": "s" * (MAX_SOURCE_AGENT + 1)})
        self._assert_rejected({"tool_name": "analyze_url", "source_agent": "s" * 100_000})

    def test_user_role_length_limit(self):
        ok = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "user_role": "r" * MAX_USER_ROLE})
        self.assertEqual(ok.status_code, 200)
        self._assert_rejected({"tool_name": "analyze_url", "user_role": "r" * (MAX_USER_ROLE + 1)})
        self._assert_rejected({"tool_name": "analyze_url", "user_role": "r" * 100_000})


class TestToolRequestParametersLimit(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    @staticmethod
    def _params_of_compact_length(n):
        """{"k":"<x...>"} has 8 characters of overhead, so the value is n - 8 long."""
        params = {"k": "x" * (n - 8)}
        assert len(json.dumps(params, separators=(",", ":"), ensure_ascii=False)) == n
        return params

    def _assert_rejected(self, params):
        before = _latest_event_id()
        res = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "parameters": params})
        self.assertEqual(res.status_code, 422)
        self.assertIn("detail", res.json())
        self.assertEqual(_latest_event_id(), before)

    def test_parameters_exactly_at_limit_are_accepted(self):
        params = self._params_of_compact_length(MAX_PARAMETERS_CHARS)
        res = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "parameters": params})
        self.assertEqual(res.status_code, 200)

    def test_parameters_one_character_over_limit_are_rejected(self):
        self._assert_rejected(self._params_of_compact_length(MAX_PARAMETERS_CHARS + 1))

    def test_very_large_parameters_are_rejected_and_not_stored(self):
        self._assert_rejected({"k": "A" * 2_000_000})

    def test_nested_and_many_key_payloads_are_counted(self):
        self._assert_rejected({"a": {"b": ["x" * 5000]}})
        self._assert_rejected({f"key_{i}": i for i in range(2000)})

    def test_limit_counts_characters_so_non_ascii_is_not_penalised(self):
        # 4000 CJK characters are ~12 KB in UTF-8 but only ~4 KB of characters.
        params = {"k": "\u6f22" * 4000}
        res = self.client.post(TOOL_REQUEST, json={"tool_name": "analyze_url", "parameters": params})
        self.assertEqual(res.status_code, 200)

    def test_agent_tasks_at_max_length_in_any_script_still_work(self):
        # The agent builds ToolRequest(parameters={"message": task}) internally;
        # a 2048-character task must never trip the parameter limit.
        for ch in ("a", "\u6f22", "\U0001F600"):
            task = "email " + ch * 2042
            self.assertEqual(len(task), 2048)
            res = self.client.post("/api/agent/task", json={"task": task})
            self.assertEqual(res.status_code, 200, msg=f"script sample {ch!r}")
            self.assertEqual(res.json()["selected_tool"], "analyze_message")

    def test_non_serializable_parameters_fail_validation_cleanly(self):
        with self.assertRaises(ValidationError):
            ToolRequest(tool_name="analyze_url", parameters={"k": object()})

        circular = {}
        circular["self"] = circular
        with self.assertRaises(ValidationError):
            ToolRequest(tool_name="analyze_url", parameters=circular)

        deep = current = []
        for _ in range(5000):
            nxt = []
            current.append(nxt)
            current = nxt
        with self.assertRaises(ValidationError):
            ToolRequest(tool_name="analyze_url", parameters={"k": deep})


class TestUnregisteredToolNameIsTruncatedInEvents(unittest.TestCase):
    """
    Defence in depth: even if an over-long name reaches the gateway directly
    (model_construct skips field validation), event text stays short.
    """

    @staticmethod
    def _evaluate(name):
        req = ToolRequest.model_construct(
            tool_name=name, parameters={}, source_agent="secure_agent", user_role="operator")
        res = permission_gateway.evaluate_request(req)
        return res, event_store.get_event_by_id(res.event_id)

    def test_long_name_cannot_create_long_event_text(self):
        res, event = self._evaluate("N" * 10_000)
        self.assertEqual((res.decision, res.status), ("BLOCK", "BLOCKED"))
        self.assertLess(len(event.action), 200)
        self.assertLess(len(event.reason), 300)
        self.assertLess(len(res.reason), 300)
        self.assertLessEqual(len(res.tool_name), MAX_TOOL_NAME + 3)
        self.assertLessEqual(len(event.metadata["tool_name"]), MAX_TOOL_NAME + 3)
        self.assertTrue(res.tool_name.endswith("..."))

    def test_names_up_to_the_limit_are_not_altered(self):
        res, event = self._evaluate("A" * MAX_TOOL_NAME)
        self.assertEqual(res.tool_name, "A" * MAX_TOOL_NAME)
        res, _ = self._evaluate("A" * (MAX_TOOL_NAME + 1))
        self.assertEqual(res.tool_name, "A" * MAX_TOOL_NAME + "...")

    def test_short_unregistered_name_text_is_byte_for_byte_unchanged(self):
        res, event = self._evaluate("  my_fake_tool  ")
        self.assertEqual(event.action, "Request unregistered tool: 'my_fake_tool'")
        self.assertEqual(res.reason, "SECURITY VIOLATION: Tool 'my_fake_tool' is not registered.")
        self.assertEqual(
            event.reason,
            "SECURITY VIOLATION: Tool 'my_fake_tool' is not registered in the Permission Gateway.")
        self.assertEqual(res.tool_name, "my_fake_tool")

    def test_truncation_is_safe_for_multibyte_names(self):
        res, event = self._evaluate("\U0001F600" * 500)
        self.assertEqual(len(res.tool_name), MAX_TOOL_NAME + 3)
        res.tool_name.encode("utf-8")  # no lone surrogates / encoding errors
        res.model_dump_json()
        event.model_dump_json()


class TestApprovalStoreCapacity(unittest.TestCase):
    @staticmethod
    def _manager(cap):
        m = ApprovalManager()
        m.max_approvals = cap
        return m

    @staticmethod
    def _new(m, label="t"):
        return m.create_approval("external_data_transfer", label, "HIGH", "r", {"payload": "security_report"})

    def test_default_cap_is_configured(self):
        self.assertEqual(ApprovalManager().max_approvals, DEFAULT_MAX_APPROVALS)
        self.assertEqual(approval_manager.max_approvals, DEFAULT_MAX_APPROVALS)

    def test_resolved_approvals_cannot_grow_past_the_cap(self):
        m = self._manager(5)
        for i in range(50):
            m.reject_request(self._new(m, f"task-{i}").approval_id)
        self.assertLessEqual(len(m._approvals), 5)

    def test_oldest_resolved_approval_is_evicted_first(self):
        m = self._manager(3)
        a, b, c = (self._new(m, n) for n in "abc")
        m.reject_request(a.approval_id)
        m.reject_request(b.approval_id)          # c stays PENDING
        d = self._new(m, "d")
        self.assertIsNone(m.get_approval_by_id(a.approval_id))      # oldest resolved gone
        for kept in (b, c, d):
            self.assertIsNotNone(m.get_approval_by_id(kept.approval_id))
        self.assertEqual(len(m._approvals), 3)

        e = self._new(m, "e")                    # now b (the only resolved one) goes
        self.assertIsNone(m.get_approval_by_id(b.approval_id))
        self.assertEqual({r.approval_id for r in m.get_pending_approvals()}, {c.approval_id, d.approval_id, e.approval_id})

    def test_pending_approvals_are_never_evicted_to_make_room(self):
        m = self._manager(3)
        pending = [self._new(m, f"p{i}") for i in range(3)]

        with self.assertRaisesRegex(ApprovalCapacityError, "Approval capacity is full"):
            self._new(m, "overflow")

        self.assertEqual(len(m._approvals), 3)
        for rec in pending:
            self.assertEqual(m.get_approval_by_id(rec.approval_id).status, "PENDING")
        self.assertEqual(len(m.get_pending_approvals()), 3)

        # Existing pending approvals remain actionable.
        self.assertEqual(m.approve_request(pending[0].approval_id)["status"], "APPROVED")
        self.assertEqual(m.reject_request(pending[1].approval_id)["status"], "REJECTED")

    def test_mixed_store_evicts_only_resolved_records(self):
        m = self._manager(4)
        p1 = self._new(m, "p1"); r1 = self._new(m, "r1"); p2 = self._new(m, "p2"); r2 = self._new(m, "r2")
        m.reject_request(r1.approval_id)
        m.reject_request(r2.approval_id)
        n = self._new(m, "n")
        self.assertIsNone(m.get_approval_by_id(r1.approval_id))
        for kept in (p1, p2, r2, n):
            self.assertIsNotNone(m.get_approval_by_id(kept.approval_id))
        self.assertEqual(len(m._approvals), 4)

    def test_store_shrinks_back_to_cap_once_records_are_resolved(self):
        m = self._manager(3)
        recs = [self._new(m, f"x{i}") for i in range(3)]

        # A fourth approval is refused while all three records are pending.
        with self.assertRaisesRegex(ApprovalCapacityError, "Approval capacity is full"):
            self._new(m, "overflow")
        self.assertEqual(len(m._approvals), 3)

        # Once records are resolved, a new approval can evict an old resolved record.
        for rec in recs[:2]:
            m.reject_request(rec.approval_id)

        new = self._new(m, "new")
        self.assertEqual(len(m._approvals), 3)
        self.assertIsNone(m.get_approval_by_id(recs[0].approval_id))
        self.assertIsNotNone(m.get_approval_by_id(recs[2].approval_id))
        self.assertIsNotNone(m.get_approval_by_id(new.approval_id))
        self.assertEqual(
            {r.approval_id for r in m.get_pending_approvals()},
            {recs[2].approval_id, new.approval_id},
        )

    def test_evicted_approval_can_no_longer_be_actioned(self):
        m = self._manager(2)
        a = self._new(m, "a"); b = self._new(m, "b")
        m.reject_request(a.approval_id)
        self._new(m, "c")                                       # evicts a
        self.assertIsNone(m.get_approval_by_id(a.approval_id))
        with self.assertRaisesRegex(ValueError, "not found"):
            m.approve_request(a.approval_id)
        self.assertIsNotNone(m.get_approval_by_id(b.approval_id))


if __name__ == "__main__":
    unittest.main()
