import os
import sys
import unittest

# Ensure backend root is on Python sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from security_engine.event_logger import event_store
from security_engine.attack_lab import run_attack_lab_scenario, run_all_attack_lab_scenarios
from security_engine.report_generator import generate_security_report

class TestPhase4Functionality(unittest.TestCase):

    # Test 1: Event statistics calculated correctly
    def test_event_stats_calculated(self):
        stats = event_store.get_stats()
        self.assertIn("total_events", stats)
        self.assertIn("status_breakdown", stats)
        self.assertGreaterEqual(stats["total_events"], 5)

    # Test 2: Event filtering works
    def test_event_filtering_by_status(self):
        blocked_events = event_store.get_events(limit=50, status="BLOCKED")
        self.assertTrue(all(e.status == "BLOCKED" for e in blocked_events))

    # Test 3: Risk distribution calculation
    def test_risk_distribution_in_events(self):
        events = event_store.get_events(limit=100)
        low_cnt = sum(1 for e in events if e.risk_level == "LOW")
        crit_cnt = sum(1 for e in events if e.risk_level == "CRITICAL")
        self.assertGreaterEqual(low_cnt + crit_cnt, 1)

    # Test 4: Status distribution accuracy
    def test_status_distribution_in_stats(self):
        stats = event_store.get_stats()
        status_bd = stats["status_breakdown"]
        self.assertIn("ALLOWED", status_bd)
        self.assertIn("BLOCKED", status_bd)

    # Test 5: Attack Lab Scenario 1 - Prompt Injection detected
    def test_attack_lab_scenario_1_prompt_injection(self):
        res = run_attack_lab_scenario("scen_1")
        self.assertEqual(res.status, "PASS")
        self.assertIn(res.risk_level, ["HIGH", "CRITICAL"])
        self.assertIn(res.actual_defense, ["BLOCK", "DETECT"])

    # Test 6: Attack Lab Scenario 3 - Credential Harvest detected
    def test_attack_lab_scenario_3_credential_harvest(self):
        res = run_attack_lab_scenario("scen_3")
        self.assertEqual(res.status, "PASS")
        self.assertIn(res.risk_level, ["HIGH", "CRITICAL"])

    # Test 7: Attack Lab Scenario 6 - Unsafe Tool Request blocked
    def test_attack_lab_scenario_6_unsafe_tool_blocked(self):
        res = run_attack_lab_scenario("scen_6")
        self.assertEqual(res.status, "PASS")
        self.assertEqual(res.actual_defense, "BLOCK")

    # Test 8: Attack Lab Scenario 5 - Data Exfiltration reviewed/blocked
    def test_attack_lab_scenario_5_data_exfiltration_gate(self):
        res = run_attack_lab_scenario("scen_5")
        self.assertEqual(res.status, "PASS")
        self.assertIn(res.actual_defense, ["REVIEW", "BLOCK"])

    # Test 9: Attack Lab Protection Score calculated correctly
    def test_attack_lab_suite_protection_score(self):
        suite_res = run_all_attack_lab_scenarios()
        self.assertEqual(suite_res.total_scenarios, 6)
        self.assertEqual(suite_res.passed_scenarios, 6)
        self.assertEqual(suite_res.protection_score_pct, 100)

    # Test 10: PASS/FAIL based on actual engine results
    def test_attack_lab_results_have_actual_engine_data(self):
        res = run_attack_lab_scenario("scen_4")
        self.assertGreater(res.score, 0)
        self.assertIn(res.actual_defense, ["DETECT", "BLOCK"])

    # Test 11: Security Report contains live statistics & high-risk events
    def test_security_report_generation(self):
        rep = generate_security_report()
        self.assertIsNotNone(rep.generated_at)
        self.assertIn("threats_detected", rep.threat_summary)
        self.assertIn("high_critical_threats", rep.threat_summary)
        self.assertIsInstance(rep.top_events, list)

    # Test 12: Security Report recommendations generated from findings
    def test_security_report_recommendations(self):
        rep = generate_security_report()
        self.assertGreater(len(rep.recommendations), 0)
        self.assertTrue(any("Permission Gateway" in r for r in rep.recommendations))

if __name__ == "__main__":
    unittest.main()
