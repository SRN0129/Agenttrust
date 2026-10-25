"""
AgentTrust Drop-In Callback Handler for LangChain & LangGraph.
Intercepts all LangChain tool calls, evaluates policy with AgentTrust,
and halts execution if an action is denied or requires approval.
"""
from typing import Any, Dict, Optional
import os

try:
    from langchain_core.callbacks import BaseCallbackHandler
except ImportError:
    class BaseCallbackHandler:  # Fallback stub if langchain_core is not installed
        pass

from agenttrust import AgentTrustClient, PolicyDenialError, ApprovalRequiredError


class AgentTrustCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that routes every tool start event through AgentTrust.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
        auto_poll_approvals: bool = False,
    ):
        self.endpoint = endpoint or os.getenv("AGENT_TRUST_URL", "http://localhost:3000")
        self.api_key = api_key or os.getenv("AGENT_TRUST_KEY", "")
        self.agent_id = agent_id or os.getenv("AGENT_TRUST_AGENT_ID", "langchain-agent")
        self.auto_poll = auto_poll_approvals
        self.client = AgentTrustClient(
            endpoint=self.endpoint,
            api_key=self.api_key,
            agent_id=self.agent_id,
        )

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """
        Intercepts tool execution before execution begins.
        """
        tool_name = serialized.get("name", "unknown_tool")
        decision = self.client.authorize(
            action=tool_name,
            resource="langchain:tool_execution",
            parameters={"input": input_str},
        )

        if decision.get("decision") == "DENY":
            raise PolicyDenialError(decision.get("reason", "Blocked by AgentTrust zero-trust policy."))

        if decision.get("decision") == "NEEDS_APPROVAL":
            approval_id = decision.get("approvalId")
            if not self.auto_poll:
                raise ApprovalRequiredError(
                    approval_id=approval_id,
                    reason=decision.get("reason", "Tool execution requires human supervisor approval."),
                )
            
            status = self.client.wait_for_approval(approval_id)
            if status.get("status") != "APPROVED":
                raise PolicyDenialError(f"Approval for {tool_name} was rejected or timed out.")

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        """
        Logs successful tool outcome to the immutable audit ledger.
        """
        self.client.report_outcome(
            action="langchain:tool_success",
            resource="langchain:output",
            status="SUCCESS",
            output_summary=str(output)[:200],
            details={},
        )

    def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
        """
        Logs tool faults and exceptions to audit trail.
        """
        self.client.report_outcome(
            action="langchain:tool_error",
            resource="langchain:exception",
            status="ERROR",
            output_summary=str(error)[:200],
            details={"error_type": type(error).__name__},
        )
