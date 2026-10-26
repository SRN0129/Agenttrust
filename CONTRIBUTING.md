# Contributing to AgentTrust

Thank you for your interest in contributing to **AgentTrust**! We are building the industry standard zero-trust control plane and cryptographic black box for autonomous AI agent runtimes. We welcome code contributions, architectural RFCs, security audits, and bug fixes from engineers across the world.

---

## Code of Conduct

We are committed to providing a welcoming, rigorous, and harassment-free environment for all contributors. We expect all participants to uphold standards of technical integrity, thoughtful peer review, and constructive discourse.

---

## Development Workflow & Setup

### Prerequisites
- **Node.js**: v18.0.0+ (Tested against Node v20 & v22 LTS)
- **Python**: 3.9+ (for `sdk-python` and middleware integrations)
- **Git**

### 1. Clone & Install
```bash
git clone https://github.com/SRN0129/Agenttrust.git
cd Agenttrust

# Install root & server dependencies
npm install

# Install UI dashboard dependencies
npm --prefix client install
```

### 2. Verify Full Test Suite
AgentTrust enforces zero regressions on security boundaries. Before writing code, ensure all 80 automated test suites pass locally:

```bash
# Run core TypeScript security & crypto test suites (Vitest)
npm test

# Run Python SDK & LangChain/CrewAI integration tests
cd sdk-python
python -m unittest discover -s tests
cd ..
```

### 3. Local Development Server
To launch the API control plane and frontend dashboard concurrently:
```bash
npm run dev
```
The AgentTrust security control panel will be accessible at `http://localhost:5173`, with the backend policy gateway running at `http://localhost:3000`.

---

## Architectural Principles for Contributors

When submitting PRs, adhere strictly to these core security principles:

1. **Deny-by-Default**: Agents must never possess ambient authority. Every action, tool dispatch, or egress packet must match an explicit policy rule or be rejected.
2. **Cryptographic Non-Repudiation**: Every decision—whether allowed, denied, or escalated—must append a cryptographically hashed event to the audit ledger. Never delete or overwrite audit rows.
3. **Sub-Millisecond Policy Fast-Path**: The core `/api/v1/authorize` pipeline must execute in under 5 milliseconds on standard CPU cores. Avoid heavy blocking I/O on the fast-path.
4. **Hardware & PQC Readiness**: Cryptographic components must support classical (ECDSA P-256) and post-quantum (NIST FIPS 204 ML-DSA) verification.

---

## How to Submit a Pull Request

1. **Find or Open an Issue**: For significant changes or new features, please discuss them first in an RFC or issue.
2. **Branch Naming**:
   - `feat/feature-name`
   - `fix/bug-description`
   - `perf/optimization-target`
   - `docs/documentation-update`
3. **Commit Messages**: We enforce the [Conventional Commits](https://www.conventionalcommits.org/) standard:
   - `feat(policy): add regex pattern matching for dynamic resource globs`
   - `fix(egress): enforce IPv6 loopback filtration in transparent proxy`
   - `perf(pqc): vectorize polynomial multiplication for ML-DSA-87`
4. **Run Security Linters & Type Checks**:
   ```bash
   npm run build:client
   npm test
   ```
5. **Open PR**: Submit your pull request to the `main` branch with a clear description of the problem solved, verification steps, and test output.

---

## Submitting Architecture RFCs & Reviews

We actively invite high-profile researchers, systems engineers, and cryptographers to participate in architectural review. If you are submitting an RFC or design proposal:
- Use GitHub Discussions or open an issue prefixed with `[RFC]`.
- Provide concrete mathematical formulations or threat models where applicable.
- Reference relevant RFCs, NIST standards, or academic literature.

---

## Reporting Vulnerabilities

Security vulnerabilities must be reported responsibly under our [Security Policy](SECURITY.md). Please **do not** open public GitHub issues for critical zero-day vulnerabilities. Report them directly via private GitHub Security Advisories or to the maintainers at `security@agenttrust.dev`.
