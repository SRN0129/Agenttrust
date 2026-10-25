"""
AgentTrust Python SDK - Agent and Tool Decorators
"""
import functools
import inspect
from typing import Callable, Any, Optional
from .client import AgentTrustClient
from .exceptions import PolicyDenialError, ApprovalRequiredError


def guard_tool(
    client: AgentTrustClient,
    action: str,
    resource: str,
    system_goal: Optional[str] = None,
    auto_poll_approval: bool = False,
    poll_timeout_sec: float = 30.0,
):
    """
    Decorator for hardening individual Python tool functions with zero-trust authorization.
    """
    def decorator(fn: Callable):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            parameters = {"args": args, "kwargs": kwargs}

            # 1. Goal Drift Analysis
            if system_goal:
                try:
                    drift = client.check_goal_drift(system_goal, action, resource, parameters)
                    if drift.get("divergenceScore", 0) >= 0.85:
                        raise PolicyDenialError(drift.get("reason", "Critical goal drift"), "DENY_GOAL_DRIFT")
                except PolicyDenialError:
                    raise
                except Exception:
                    pass

            # 2. Server-Side Policy Authorization
            authz = client.authorize(action, resource, parameters)
            decision = authz.get("decision", "DENY")

            if decision == "DENY":
                raise PolicyDenialError(authz.get("reason", "Action denied by security policy"), "DENY")

            if decision == "NEEDS_APPROVAL":
                approval_id = authz.get("approvalId")
                if not auto_poll_approval:
                    raise ApprovalRequiredError(approval_id, authz.get("reason", "Requires human review"))
                client.wait_for_approval(approval_id, max_wait_sec=poll_timeout_sec)

            # 3. Execution
            status = "SUCCESS"
            output_summary = "Executed successfully"
            try:
                result = fn(*args, **kwargs)
                return result
            except Exception as e:
                status = "FAILED"
                output_summary = f"Exception: {str(e)}"
                raise
            finally:
                try:
                    client.report_outcome(action, resource, status, output_summary, parameters)
                except Exception:
                    pass

        return wrapper
    return decorator


def wrap_agent(agent_instance: Any, client: AgentTrustClient, system_goal: str = "Autonomous agent execution"):
    """
    Universal 1-line wrapper for Python agents (LangChain tools, CrewAI agents, AutoGen assistants).
    Wraps all public methods dynamically with zero-trust policy interception.
    """
    class SafeAgentProxy:
        def __init__(self, target):
            self._target = target

        def __getattr__(self, name):
            attr = getattr(self._target, name)
            if callable(attr) and not name.startswith("_"):
                action = f"agent:{name}"
                resource = f"tool:{name}"
                return guard_tool(client=client, action=action, resource=resource, system_goal=system_goal)(attr)
            return attr

    return SafeAgentProxy(agent_instance)
