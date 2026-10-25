# Client SDK & Universal Wrapper Guide

## Installation

```bash
npm install @srn0129/agenttrust
```

## 1-Line Universal Agent Wrap

```typescript
import { wrapAgent, AgentTrustClient } from "@agenttrust/sdk";

const client = new AgentTrustClient({
  baseUrl: "https://agenttrust.yourdomain.com",
  apiKey: process.env.AGENT_TRUST_KEY!,
});

// Wrap any agent object (LangChain, CrewAI, AutoGen, custom tools)
const safeAgent = wrapAgent(rawAgentInstance, {
  client,
  systemGoal: "Verify vendor invoices and calculate taxes",
  autoPollApproval: false,
});

// Calls are transparently intercepted, pre-flight scanned, and audited
await safeAgent.processInvoice({ id: "INV-90210" });
```
