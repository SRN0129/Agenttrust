"""
AgentTrust Python SDK
Zero-trust policy enforcement, cryptographic audit ledger, and human-in-the-loop governance for AI agents.
"""
from .client import AgentTrustClient
from .decorator import wrap_agent, guard_tool
from .quantum import QuantumCircuitParser
from .exceptions import (
    AgentTrustError,
    PolicyDenialError,
    ApprovalRequiredError,
    CircuitBreakerError,
)

__version__ = "1.0.0"
__all__ = [
    "AgentTrustClient",
    "wrap_agent",
    "guard_tool",
    "QuantumCircuitParser",
    "AgentTrustError",
    "PolicyDenialError",
    "ApprovalRequiredError",
    "CircuitBreakerError",
]
