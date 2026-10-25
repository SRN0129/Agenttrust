# Contributing to AgentTrust

Thank you for your interest in contributing to **AgentTrust**! We welcome community contributions, bug reports, and enhancements.

## Development Setup

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   npm install
   npm --prefix client install
   ```
3. Run the automated test suite (41 security tests):
   ```bash
   npm test
   ```
4. Build the client interface:
   ```bash
   npm run build:client
   ```
5. Run the live end-to-end audit demonstration:
   ```bash
   npm run demo
   ```

## Contribution Guidelines

- All new features or security boundary modifications must include comprehensive unit and integration tests under `tests/`.
- Ensure all tests pass (`npm test`) before opening a pull request.
- Keep commits semantic and clean (`feat: ...`, `fix: ...`, `docs: ...`).

## Commercial & Enterprise Partnerships

If your company is interested in enterprise feature requests, sponsorship, or licensing, please refer to our [Commercial Inquiry Template](.github/ISSUE_TEMPLATE/commercial_inquiry.yml).
