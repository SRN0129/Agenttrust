"""
AgentTrust Python SDK - Exceptions
"""

class AgentTrustError(Exception):
    """Base exception for all AgentTrust runtime errors."""
    pass


class PolicyDenialError(AgentTrustError):
    """Raised when an agent action is denied by security policy."""
    def __init__(self, reason: str, decision: str = "DENY"):
        super().__init__(f"AgentTrust Policy Denial [{decision}]: {reason}")
        self.reason = reason
        self.decision = decision


class ApprovalRequiredError(AgentTrustError):
    """Raised when an action requires human review and auto_poll is disabled."""
    def __init__(self, approval_id: str, reason: str):
        super().__init__(f"Action requires human approval. Approval ID: {approval_id}. Reason: {reason}")
        self.approval_id = approval_id
        self.reason = reason


class CircuitBreakerError(AgentTrustError):
    """Raised when velocity or spend circuit breaker trips."""
    def __init__(self, reason: str):
        super().__init__(f"AgentTrust Circuit Breaker Tripped: {reason}")
        self.reason = reason
