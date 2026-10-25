package agenttrust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is the Go client for interacting with the AgentTrust Gateway.
type Client struct {
	config     ClientConfig
	httpClient *http.Client
}

// NewClient initializes a new AgentTrust client.
func NewClient(config ClientConfig) *Client {
	endpoint := strings.TrimRight(config.Endpoint, "/")
	if endpoint == "" {
		endpoint = "http://localhost:3000"
	}
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &Client{
		config: ClientConfig{
			Endpoint: endpoint,
			APIKey:   config.APIKey,
			AgentID:  config.AgentID,
			Timeout:  timeout,
		},
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}
}

func (c *Client) request(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	url := fmt.Sprintf("%s%s", c.config.Endpoint, path)

	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("agenttrust: marshal error: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("agenttrust: request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if c.config.APIKey != "" {
		req.Header.Set("x-api-key", c.config.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agenttrust: network error: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("agenttrust: read response error: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("agenttrust: api error status %d: %s", resp.StatusCode, string(respBytes))
	}

	if out != nil {
		if err := json.Unmarshal(respBytes, out); err != nil {
			return fmt.Errorf("agenttrust: unmarshal error: %w", err)
		}
	}

	return nil
}

// Authorize checks whether an action is permitted by policy before execution.
func (c *Client) Authorize(ctx context.Context, req AuthorizationRequest) (*AuthorizationResponse, error) {
	if req.AgentID == "" {
		req.AgentID = c.config.AgentID
	}
	var res AuthorizationResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/auth/decision", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GetApproval retrieves the current status of a human approval request.
func (c *Client) GetApproval(ctx context.Context, approvalID string) (*ApprovalStatus, error) {
	path := fmt.Sprintf("/api/v1/approvals/%s", approvalID)
	var res ApprovalStatus
	if err := c.request(ctx, http.MethodGet, path, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// WaitForApproval polls until a human-in-the-loop decision is made or deadline expires.
func (c *Client) WaitForApproval(ctx context.Context, approvalID string, pollInterval, maxWait time.Duration) (*ApprovalStatus, error) {
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	if maxWait <= 0 {
		maxWait = 60 * time.Second
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctxTimeout.Done():
			return nil, fmt.Errorf("agenttrust: timed out waiting for approval %s: %w", approvalID, ctxTimeout.Err())
		case <-ticker.C:
			status, err := c.GetApproval(ctxTimeout, approvalID)
			if err != nil {
				return nil, err
			}
			if status.Status != "PENDING" {
				return status, nil
			}
		}
	}
}

// CheckGoalDrift evaluates if the action drifts from intent.
func (c *Client) CheckGoalDrift(ctx context.Context, req GoalDriftRequest) (*GoalDriftResponse, error) {
	if req.AgentID == "" {
		req.AgentID = c.config.AgentID
	}
	var res GoalDriftResponse
	if err := c.request(ctx, http.MethodPost, "/api/v1/goal-drift/check", req, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ReportOutcome logs the execution outcome to the immutable audit trail.
func (c *Client) ReportOutcome(ctx context.Context, action, resource, status, summary string, details map[string]interface{}) error {
	payload := map[string]interface{}{
		"agentId":       c.config.AgentID,
		"action":        action,
		"resource":      resource,
		"status":        status,
		"outputSummary": summary,
		"details":       details,
		"timestamp":     time.Now().UTC().Format(time.RFC3339),
	}
	return c.request(ctx, http.MethodPost, "/api/v1/audit/outcome", payload, nil)
}

// InspectQuantumCircuit inspects and validates an OpenQASM circuit against safety bounds.
func (c *Client) InspectQuantumCircuit(ctx context.Context, qasmCircuit string) (*QuantumCircuitMetrics, error) {
	metrics := ParseQASM(qasmCircuit)
	return &metrics, nil
}
