package agenttrust

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseQASM(t *testing.T) {
	qasm := `
OPENQASM 2.0;
include "qelib1.inc";
qreg q[4];
creg c[4];
h q[0];
cx q[0], q[1];
cx q[1], q[2];
measure q[0] -> c[0];
`
	metrics := ParseQASM(qasm)
	if metrics.QubitCount != 4 {
		t.Fatalf("expected 4 qubits, got %d", metrics.QubitCount)
	}
	if metrics.TotalGateCount != 3 {
		t.Fatalf("expected 3 gates, got %d", metrics.TotalGateCount)
	}
	if metrics.TwoQubitGateCount != 2 {
		t.Fatalf("expected 2 two-qubit gates, got %d", metrics.TwoQubitGateCount)
	}
	if metrics.MeasurementCount != 1 {
		t.Fatalf("expected 1 measurement, got %d", metrics.MeasurementCount)
	}
}

func TestClientAuthorize(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/decision" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != "secret-test-key" {
			t.Errorf("missing or invalid api key header")
		}

		var req AuthorizationRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		resp := AuthorizationResponse{
			Decision:    DecisionAllow,
			Reason:      "Default policy match",
			ExecutionID: "exec-test-999",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ClientConfig{
		Endpoint: ts.URL,
		APIKey:   "secret-test-key",
		AgentID:  "agent-go-worker",
		Timeout:  2 * time.Second,
	})

	ctx := context.Background()
	res, err := client.Authorize(ctx, AuthorizationRequest{
		Action:   "database:query",
		Resource: "customers",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Decision != DecisionAllow {
		t.Fatalf("expected DecisionAllow, got %s", res.Decision)
	}
	if res.ExecutionID != "exec-test-999" {
		t.Fatalf("expected exec-test-999, got %s", res.ExecutionID)
	}
}

func TestClientCheckGoalDrift(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/goal-drift/check" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		resp := GoalDriftResponse{
			DivergenceScore: 0.12,
			Threshold:       0.70,
			IsDrifting:      false,
			Reason:          "Action is aligned with system goal",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	client := NewClient(ClientConfig{
		Endpoint: ts.URL,
		AgentID:  "agent-go-worker",
	})

	res, err := client.CheckGoalDrift(context.Background(), GoalDriftRequest{
		SystemGoal: "Index public documents",
		Action:     "fs:read",
		Resource:   "/docs/index.md",
	})
	if err != nil {
		t.Fatalf("unexpected drift error: %v", err)
	}
	if res.IsDrifting {
		t.Fatalf("expected isDrifting=false, got true")
	}
	if res.DivergenceScore != 0.12 {
		t.Fatalf("expected divergence score 0.12, got %f", res.DivergenceScore)
	}
}
