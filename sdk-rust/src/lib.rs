//! # AgentTrust Rust SDK
//!
//! Official Rust client and security middleware for AgentTrust.
//! Intercepts LLM tool invocations, enforces declarative policies,
//! monitors goal divergence, and audits actions to cryptographic ledgers.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentTrustError {
    #[error("Action denied by policy: {reason} (rule_id: {rule_id})")]
    PolicyDenial { reason: String, rule_id: String },

    #[error("Action requires human approval: {approval_id}")]
    ApprovalRequired { approval_id: String, reason: String },

    #[error("Network or protocol error: {0}")]
    Network(String),

    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Decision {
    ALLOW,
    DENY,
    NEEDS_APPROVAL,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    #[serde(rename = "agentId", skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub action: String,
    pub resource: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub parameters: HashMap<String, serde_json::Value>,
    #[serde(rename = "estimatedCostUSD", default)]
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub decision: Decision,
    pub reason: String,
    #[serde(rename = "ruleId", skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(rename = "approvalId", skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    #[serde(rename = "executionId", skip_serializing_if = "Option::is_none")]
    pub execution_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumCircuitMetrics {
    pub qubit_count: usize,
    pub total_gate_count: usize,
    pub two_qubit_gate_count: usize,
    pub measurement_count: usize,
    pub estimated_fidelity: f64,
}

/// Static OpenQASM parser and security analyzer.
pub struct QuantumCircuitParser;

impl QuantumCircuitParser {
    pub fn parse_qasm(qasm: &str) -> QuantumCircuitMetrics {
        let mut qubit_count: usize = 0;
        let mut total_gates: usize = 0;
        let mut two_qubit_gates: usize = 0;
        let mut measurements: usize = 0;

        for line in qasm.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.is_empty() {
                continue;
            }

            if trimmed.starts_with("qreg ") || trimmed.starts_with("qubit[") {
                if let Some(start) = trimmed.find('[') {
                    if let Some(end) = trimmed.find(']') {
                        if let Ok(count) = trimmed[start + 1..end].parse::<usize>() {
                            qubit_count += count;
                        }
                    }
                }
                continue;
            }

            if trimmed.contains("measure") || trimmed.contains("->") {
                measurements += 1;
                continue;
            }

            let two_q_ops = ["cx ", "cz ", "swap ", "iswap ", "cphase ", "cp "];
            if two_q_ops.iter().any(|op| trimmed.contains(op)) {
                two_qubit_gates += 1;
                total_gates += 1;
                continue;
            }

            let single_q_ops = ["h ", "x ", "y ", "z ", "s ", "t ", "rx(", "ry(", "rz("];
            if single_q_ops.iter().any(|op| trimmed.contains(op)) {
                total_gates += 1;
                continue;
            }
        }

        let one_q = total_gates.saturating_sub(two_qubit_gates);
        let fidelity = (0.999f64).powi(one_q as i32) * (0.990f64).powi(two_qubit_gates as i32);

        QuantumCircuitMetrics {
            qubit_count,
            total_gate_count: total_gates,
            two_qubit_gate_count: two_qubit_gates,
            measurement_count: measurements,
            estimated_fidelity: (fidelity * 10000.0).round() / 10000.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_qasm() {
        let qasm = r#"
            OPENQASM 2.0;
            qreg q[4];
            h q[0];
            cx q[0], q[1];
            measure q[0] -> c[0];
        "#;
        let metrics = QuantumCircuitParser::parse_qasm(qasm);
        assert_eq!(metrics.qubit_count, 4);
        assert_eq!(metrics.total_gate_count, 2);
        assert_eq!(metrics.two_qubit_gate_count, 1);
        assert_eq!(metrics.measurement_count, 1);
    }
}
