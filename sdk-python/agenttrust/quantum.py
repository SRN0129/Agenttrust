"""
AgentTrust Python SDK - Quantum Circuit Inspector & OpenQASM Parser
"""
import re
from typing import Dict, Any, Optional


class QuantumCircuitParser:
    """
    Lightweight OpenQASM 2.0/3.0 parser for gate complexity and qubit boundary verification.
    """
    @staticmethod
    def parse_qasm(qasm_string: str) -> Dict[str, int]:
        qubit_count = 0
        gate_count = 0
        two_qubit_count = 0

        for line in qasm_string.splitlines():
            trimmed = line.strip().lower()
            if not trimmed or trimmed.startswith("//") or trimmed.startswith("openqasm") or trimmed.startswith("include") or trimmed.startswith("creg"):
                continue

            # Qubit register count
            if trimmed.startswith("qreg "):
                match = re.search(r"\[(\d+)\]", trimmed)
                if match:
                    qubit_count += int(match.group(1))
            # Two-qubit entangling gates
            elif trimmed.startswith(("cx ", "cz ", "swap ", "cphase ")):
                two_qubit_count += 1
                gate_count += 1
            # Single qubit gates
            else:
                gate_count += 1

        return {
            "qubit_count": qubit_count,
            "total_gate_count": gate_count,
            "two_qubit_gate_count": two_qubit_count,
        }
