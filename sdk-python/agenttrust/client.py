"""
AgentTrust Python SDK - API Client
"""
import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any, Optional
from .exceptions import PolicyDenialError, ApprovalRequiredError, CircuitBreakerError


class AgentTrustClient:
    """
    Client for the AgentTrust Zero-Trust Security Gateway.
    """
    def __init__(self, base_url: str, api_key: str, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _request(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "AgentTrust-Python-SDK/1.0.0",
        }
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8")
            try:
                parsed = json.loads(error_body)
                msg = parsed.get("error", f"HTTP {e.code}: {e.reason}")
            except Exception:
                msg = f"HTTP {e.code}: {error_body}"
            raise PolicyDenialError(msg, decision="HTTP_ERROR")
        except Exception as e:
            raise PolicyDenialError(str(e), decision="CONNECTION_ERROR")

    def authorize(
        self,
        action: str,
        resource: str,
        parameters: Optional[Dict[str, Any]] = None,
        estimated_cost_usd: float = 0.0,
    ) -> Dict[str, Any]:
        """Request pre-flight authorization for an action on a resource."""
        return self._request(
            "POST",
            "/api/v1/authorize",
            {
                "action": action,
                "resource": resource,
                "parameters": parameters or {},
                "estimatedCostUsd": estimated_cost_usd,
            },
        )

    def get_approval(self, approval_id: str) -> Dict[str, Any]:
        """Fetch the current state of a human approval ticket."""
        res = self._request("GET", f"/api/v1/approvals/{approval_id}")
        return res.get("approval", {})

    def wait_for_approval(
        self,
        approval_id: str,
        poll_interval_sec: float = 2.0,
        max_wait_sec: float = 60.0,
    ) -> Dict[str, Any]:
        """Poll for human approval decision until decided or timed out."""
        start_time = time.time()
        while time.time() - start_time < max_wait_sec:
            approval = self.get_approval(approval_id)
            status = approval.get("status")
            if status == "APPROVED":
                return approval
            elif status == "REJECTED":
                raise PolicyDenialError("Human operator rejected the action request.", "REJECTED")
            elif status == "EXPIRED":
                raise PolicyDenialError("Approval request expired before review.", "EXPIRED")
            time.sleep(poll_interval_sec)

        raise TimeoutError(f"Timed out waiting for approval ticket {approval_id} after {max_wait_sec}s")

    def check_goal_drift(
        self,
        system_goal: str,
        action: str,
        resource: str,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze proposed execution against agent's stated goal to catch prompt hijacks."""
        return self._request(
            "POST",
            "/api/v1/governance/drift-check",
            {
                "systemGoal": system_goal,
                "action": action,
                "resource": resource,
                "parameters": parameters or {},
            },
        )

    def report_outcome(
        self,
        action: str,
        resource: str,
        status: str,
        output_summary: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record tool execution outcome to the tamper-evident hash-linked audit ledger."""
        return self._request(
            "POST",
            "/api/v1/audit/outcome",
            {
                "action": action,
                "resource": resource,
                "executionStatus": status,
                "outputSummary": output_summary,
                "details": details or {},
            },
        )

    def inspect_quantum_circuit(
        self,
        circuit_name: str,
        qubit_count: int,
        circuit_depth: int,
        two_qubit_gate_count: int,
        total_gate_count: int,
        requested_shots: int,
        qasm_source: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Pre-flight QPU circuit gate and decoherence boundary inspection."""
        return self._request(
            "POST",
            "/api/v1/quantum/inspect-circuit",
            {
                "circuitName": circuit_name,
                "qubitCount": qubit_count,
                "circuitDepth": circuit_depth,
                "twoQubitGateCount": two_qubit_gate_count,
                "totalGateCount": total_gate_count,
                "requestedShots": requested_shots,
                "qasmSource": qasm_source,
            },
        )
