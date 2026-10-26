### Background
Anthropic's [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) is becoming the open standard for connecting LLMs to external data sources and tools (local filesystems, GitHub, PostgreSQL, etc.).

Currently, AgentTrust provides zero-trust middleware for:
- LangChain / LangGraph (`integrations/langchain/`)
- CrewAI (`integrations/crewai/`)
- Python universal decorator (`sdk-python/agenttrust/decorator.py`)
- TypeScript universal wrapper (`client/src/`)

### Feature Request
We would love to add a native, lightweight **AgentTrust MCP Proxy Server** that acts as a transparent reverse-proxy between any MCP client (such as Claude Desktop or custom agents) and backend MCP tool servers.

### Expected Behavior
1. Intercepts incoming `tools/call` JSON-RPC requests from the MCP client.
2. Evaluates the tool name and arguments against AgentTrust `/api/v1/authorize`.
3. Checks for prompt injections or sensitive credential leaks using `PromptInjectionScanner`.
4. If authorized, forwards to the target MCP server and records an entry in the cryptographic audit ledger.
5. If denied or blast radius exceeds threshold, returns a standard JSON-RPC error or triggers a 1-click human approval callback link.

### Mentorship & Code Pointers
This is a fantastic first issue for newcomers interested in AI security and agent infrastructure!
- See the existing CrewAI hook for how tool interception is structured: `integrations/crewai/agenttrust_hook.py`
- See policy check API: `server/app.ts` (`/api/v1/authorize`)
- We are happy to review PRs and provide guidance on Discord / GitHub Discussions!
