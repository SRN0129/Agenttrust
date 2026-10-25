# AgentTrust Go SDK

Official Go SDK and client middleware for [AgentTrust](https://github.com/SRN0129/Agenttrust), an autonomous agent security gateway and policy enforcement engine.

## Installation

```bash
go get github.com/SRN0129/Agenttrust/sdk-go
```

## Quick Start

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/SRN0129/Agenttrust/sdk-go/agenttrust"
)

func main() {
	client := agenttrust.NewClient(agenttrust.ClientConfig{
		Endpoint: "http://localhost:3000",
		APIKey:   "your-agenttrust-api-key",
		AgentID:  "data-sync-worker",
		Timeout:  5 * time.Second,
	})

	ctx := context.Background()

	// 1. Authorize an action
	decision, err := client.Authorize(ctx, agenttrust.AuthorizationRequest{
		Action:   "database:update",
		Resource: "orders",
		Parameters: map[string]interface{}{
			"orderId": "ORD-12345",
			"status":  "SHIPPED",
		},
		EstimatedCostUSD: 0.005,
	})
	if err != nil {
		log.Fatalf("Authorization failed: %v", err)
	}

	if decision.Decision == agenttrust.DecisionDeny {
		log.Fatalf("Action blocked by policy: %s", decision.Reason)
	}

	if decision.Decision == agenttrust.DecisionNeedsApproval {
		fmt.Printf("Awaiting human approval (id: %s)...\n", decision.ApprovalID)
		approval, err := client.WaitForApproval(ctx, decision.ApprovalID, 2*time.Second, 2*time.Minute)
		if err != nil || approval.Status != "APPROVED" {
			log.Fatalf("Approval rejected or timed out: %v", err)
		}
	}

	// 2. Perform protected action
	fmt.Println("Action authorized. Executing order update...")

	// 3. Report execution outcome to cryptographic audit ledger
	_ = client.ReportOutcome(ctx, "database:update", "orders", "SUCCESS", "Updated status to SHIPPED", nil)
}
```

## Features

- **Policy Interception**: Real-time evaluation of LLM actions against security boundaries.
- **Human-in-the-Loop Polling**: Async escalation with non-blocking approval resolution.
- **Goal Drift Verification**: Evaluates semantic vector distance between original goals and generated tool calls.
- **Cryptographic Audit**: Automatic logging to the SHA-256 hash-chained ledger.
- **Quantum Circuit Safety**: Static inspection of OpenQASM 2.0 / 3.0 circuits for qubit limits and gate depths.
