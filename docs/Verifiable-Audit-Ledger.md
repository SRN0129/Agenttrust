# Verifiable Audit Ledger & Merkle Proofs

## Backward Hash Chaining

Every audit event is cryptographically bound to its predecessor:

$$\text{entry\_hash}_n = \text{SHA-256}(\text{index}_n \parallel \text{timestamp}_n \parallel \text{agent\_id}_n \parallel \text{action}_n \parallel \text{payload\_hash}_n \parallel \text{entry\_hash}_{n-1})$$

Modifying any historical record invalidates the entire subsequent hash chain.

## Merkle Inclusion Proofs

AgentTrust constructs binary Merkle trees over ledger events. For any recorded transaction, an auditor can request a self-contained **Attestation Receipt** (`GET /api/v1/audit/attestation/:id`) containing:
- The target entry hash
- The Merkle branch proof path
- The signed Merkle root
- The signer public key PEM

Verification can be executed completely offline with zero database dependencies.
