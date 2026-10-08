import os
import sys
import unittest

# Ensure backend root is on Python sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_engine.permission_gateway import permission_gateway, ToolRequest
from security_engine.agent_service import secure_agent_service
from security_engine.approval_manager import approval_manager

class TestAgentWorkflow(unittest.TestCase):

    # Test 1: Safe tool -> ALLOW
    def test_safe_tool_allowed(self):
        res = secure_agent_service.execute_task("Analyze this URL: https://example.com")
        self.assertEqual(res.gateway_decision, "ALLOW")
        self.assertEqual(res.status, "COMPLETED")
        self.assertIsNotNone(res.execution_result)

    # Test 2: Medium-risk tool -> ALLOW + LOG
    def test_medium_risk_tool_allowed_with_log(self):
        res = secure_agent_service.execute_task("Check this phishing message")
        self.assertEqual(res.gateway_decision, "ALLOW")
        self.assertEqual(res.status, "COMPLETED")

    # Test 3: High-risk tool -> REVIEW
    def test_high_risk_tool_requires_review(self):
        res = secure_agent_service.execute_task("Transfer security report externally")
        self.assertEqual(res.gateway_decision, "REVIEW")
        self.assertEqual(res.status, "WAITING_APPROVAL")
        self.assertIsNotNone(res.approval_request)

    # Test 4: Critical tool -> BLOCK
    def test_critical_tool_blocked(self):
        res = secure_agent_service.execute_task("Delete all security logs immediately")
        self.assertEqual(res.gateway_decision, "BLOCK")
        self.assertEqual(res.status, "BLOCKED")
        self.assertIsNone(res.execution_result)

    # Test 5: Unknown tool -> BLOCK
    def test_unknown_tool_blocked(self):
        req = ToolRequest(tool_name="unregistered_malicious_tool", parameters={})
        gw_res = permission_gateway.evaluate_request(req)
        self.assertEqual(gw_res.decision, "BLOCK")
        self.assertEqual(gw_res.score, 100)

    # Test 6: User cannot bypass Permission Gateway
    def test_cannot_bypass_gateway(self):
        # Even if request comes directly to gateway for a critical tool, it is BLOCKED
        req = ToolRequest(tool_name="delete_data", parameters={})
        gw_res = permission_gateway.evaluate_request(req)
        self.assertEqual(gw_res.decision, "BLOCK")

    # Test 7: Pending approval -> no execution
    def test_pending_approval_no_execution(self):
        res = secure_agent_service.execute_task("Transfer report externally to remote webhook")
        self.assertIsNone(res.execution_result)
        appr_id = res.approval_request.approval_id
        appr_record = approval_manager.get_approval_by_id(appr_id)
        self.assertEqual(appr_record.status, "PENDING")

    # Test 8: Rejected approval -> no execution
    def test_rejected_approval_no_execution(self):
        res = secure_agent_service.execute_task("Transfer report externally")
        appr_id = res.approval_request.approval_id
        rej_res = approval_manager.reject_request(appr_id)
        self.assertEqual(rej_res["status"], "REJECTED")
        self.assertEqual(rej_res["execution_result"]["status"], "cancelled")

    # Test 9: Approved high-risk action -> safe simulated execution ONLY
    def test_approved_high_risk_simulated_only(self):
        res = secure_agent_service.execute_task("Transfer report externally")
        appr_id = res.approval_request.approval_id
        appr_res = approval_manager.approve_request(appr_id)
        self.assertEqual(appr_res["status"], "APPROVED")
        self.assertTrue(appr_res["execution_result"]["is_simulated"])

    # Test 10: Invalid approval ID -> safe error
    def test_invalid_approval_id_raises_error(self):
        with self.assertRaises(ValueError):
            approval_manager.approve_request("appr_non_existent_123")
        with self.assertRaises(ValueError):
            approval_manager.reject_request("appr_non_existent_123")

    # Test 11: Approval cannot be reused incorrectly (idempotency check)
    def test_approval_cannot_be_reused(self):
        res = secure_agent_service.execute_task("Transfer report externally")
        appr_id = res.approval_request.approval_id
        approval_manager.approve_request(appr_id)
        # Attempting second approval on same ID must fail
        with self.assertRaises(ValueError):
            approval_manager.approve_request(appr_id)

    # Test 12: Agent cannot execute arbitrary tool names
    def test_agent_rejects_arbitrary_tool_names(self):
        res = secure_agent_service.execute_task("Please execute arbitrary_untracked_command_x")
        self.assertEqual(res.status, "UNKNOWN_TASK")
        self.assertIsNone(res.selected_tool)

if __name__ == "__main__":
    unittest.main()
