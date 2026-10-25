"""
AgentTrust Guardrail Hook for CrewAI Multi-Agent Teams.
Attaches to CrewAI agent steps and enforces rate limits, spend ceilings,
and human approval escalation.
"""
from typing import Any, Dict, Optional
import os
from agenttrust import AgentTrustClient, PolicyDenialError, ApprovalRequiredError


class CrewAIAgentTrustGuard:
    """
    CrewAI step execution guardrail.
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        api_key: Optional[str] = None,
        agent_id: Optional[str] = None,
    ):
        self.client = AgentTrustClient(
            endpoint=endpoint or os.getenv("AGENT_TRUST_URL", "http://localhost:3000"),
            api_key=api_key or os.getenv("AGENT_TRUST_KEY", ""),
            agent_id=agent_id or "crewai-agent",
        )

    def guard_task_step(self, step_context: Dict[str, Any]) -> None:
        """
        Evaluates task execution before crew member runs it.
        """
        tool_name = step_context.get("tool", "crew_task")
        tool_input = step_context.get("tool_input", {})

        decision = self.client.authorize(
            action=tool_name,
            resource=f"crewai:{step_context.get('task_name', 'task')}",
            parameters=tool_input if isinstance(tool_input, dict) else {"raw": str(tool_input)},
        )

        if decision.get("decision") == "DENY":
            raise PolicyDenialError(f"CrewAI action blocked: {decision.get('reason')}")

        if decision.get("decision") == "NEEDS_APPROVAL":
            raise ApprovalRequiredError(
                approval_id=decision.get("approvalId", ""),
                reason="Crew action requires operator sign-off.",
            )
