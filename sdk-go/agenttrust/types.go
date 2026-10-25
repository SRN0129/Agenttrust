package agenttrust

import "time"

// Decision represents the policy evaluation outcome.
type Decision string

const (
	DecisionAllow         Decision = "ALLOW"
	DecisionDeny          Decision = "DENY"
	DecisionNeedsApproval Decision = "NEEDS_APPROVAL"
)

// ClientConfig holds configuration for the AgentTrust client.
type ClientConfig struct {
	Endpoint string
	APIKey   string
	AgentID  string
	Timeout  time.Duration
}

// AuthorizationRequest encapsulates an agent action query.
type AuthorizationRequest struct {
	AgentID          string                 `json:"agentId,omitempty"`
	SessionID        string                 `json:"sessionId,omitempty"`
	Action           string                 `json:"action"`
	Resource         string                 `json:"resource"`
	Parameters       map[string]interface{} `json:"parameters,omitempty"`
	EstimatedCostUSD float64                `json:"estimatedCostUSD,omitempty"`
}

// AuthorizationResponse is the decision returned by the gateway.
type AuthorizationResponse struct {
	Decision    Decision `json:"decision"`
	Reason      string   `json:"reason"`
	RuleID      string   `json:"ruleId,omitempty"`
	ApprovalID  string   `json:"approvalId,omitempty"`
	ExecutionID string   `json:"executionId,omitempty"`
}

// ApprovalStatus represents human-in-the-loop review state.
type ApprovalStatus struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"` // PENDING, APPROVED, REJECTED, TIMEOUT
	DecidedBy string    `json:"decidedBy,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// GoalDriftRequest evaluates whether an action diverges from an intent.
type GoalDriftRequest struct {
	AgentID    string                 `json:"agentId,omitempty"`
	SystemGoal string                 `json:"systemGoal"`
	Action     string                 `json:"action"`
	Resource   string                 `json:"resource"`
	Parameters map[string]interface{} `json:"parameters,omitempty"`
}

// GoalDriftResponse returns divergence score metrics.
type GoalDriftResponse struct {
	DivergenceScore float64 `json:"divergenceScore"`
	Threshold       float64 `json:"threshold"`
	IsDrifting      bool    `json:"isDrifting"`
	Reason          string  `json:"reason"`
}

// QuantumCircuitMetrics holds structural analysis of quantum circuits.
type QuantumCircuitMetrics struct {
	QubitCount         int `json:"qubit_count"`
	TotalGateCount     int `json:"total_gate_count"`
	TwoQubitGateCount  int `json:"two_qubit_gate_count"`
	MeasurementCount   int `json:"measurement_count"`
	EstimatedFidelity  float64 `json:"estimated_fidelity"`
}

// PolicyDenialError indicates that an action was blocked by security policy.
type PolicyDenialError struct {
	Reason string
	RuleID string
}

func (e *PolicyDenialError) Error() string {
	return "agenttrust: action denied: " + e.Reason
}

// ApprovalRequiredError indicates human approval is required before execution.
type ApprovalRequiredError struct {
	ApprovalID string
	Reason     string
}

func (e *ApprovalRequiredError) Error() string {
	return "agenttrust: action requires human approval (id=" + e.ApprovalID + "): " + e.Reason
}
