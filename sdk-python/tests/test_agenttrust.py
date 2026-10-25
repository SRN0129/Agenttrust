"""
Unit tests for AgentTrust Python SDK
"""
import unittest
from agenttrust import (
    AgentTrustClient,
    wrap_agent,
    guard_tool,
    QuantumCircuitParser,
    PolicyDenialError,
    ApprovalRequiredError,
)


class MockAgent:
    def read_document(self, doc_id: str):
        return f"Content of {doc_id}"

    def drop_database(self, db_name: str):
        return "Dropped"


class MockClient:
    def __init__(self):
        self.outcomes = []

    def check_goal_drift(self, system_goal, action, resource, parameters):
        if "drop" in action:
            return {"divergenceScore": 0.95, "reason": "Destructive action violates read goal"}
        return {"divergenceScore": 0.1, "reason": "Aligned"}

    def authorize(self, action, resource, parameters, estimated_cost_usd=0.0):
        if "drop" in action:
            return {"decision": "DENY", "reason": "Deny-by-default policy"}
        elif "delete" in action:
            return {"decision": "NEEDS_APPROVAL", "approvalId": "app_test_123", "reason": "High impact action"}
        return {"decision": "ALLOW", "reason": "Permitted"}

    def wait_for_approval(self, approval_id, poll_interval_sec=0.1, max_wait_sec=1.0):
        return {"status": "APPROVED"}

    def report_outcome(self, action, resource, status, output_summary, details):
        self.outcomes.append((action, status))


class TestAgentTrustPythonSDK(unittest.TestCase):
    def test_wrap_agent_allows_permitted_action(self):
        mock_client = MockClient()
        agent = MockAgent()
        safe_agent = wrap_agent(agent, client=mock_client, system_goal="Read reports")

        result = safe_agent.read_document("report_2026.pdf")
        self.assertEqual(result, "Content of report_2026.pdf")
        self.assertEqual(len(mock_client.outcomes), 1)
        self.assertEqual(mock_client.outcomes[0][1], "SUCCESS")

    def test_wrap_agent_blocks_denied_action(self):
        mock_client = MockClient()
        agent = MockAgent()
        safe_agent = wrap_agent(agent, client=mock_client, system_goal="Read reports")

        with self.assertRaises(PolicyDenialError):
            safe_agent.drop_database("production")

    def test_quantum_circuit_parser(self):
        qasm = """
        OPENQASM 2.0;
        include "qelib1.inc";
        qreg q[8];
        h q[0];
        cx q[0], q[1];
        cx q[1], q[2];
        swap q[2], q[3];
        """
        metrics = QuantumCircuitParser.parse_qasm(qasm)
        self.assertEqual(metrics["qubit_count"], 8)
        self.assertEqual(metrics["two_qubit_gate_count"], 3)
        self.assertEqual(metrics["total_gate_count"], 4)


if __name__ == "__main__":
    unittest.main()
