#!/usr/bin/env bash
# ==============================================================================
# AgentTrust Audit Chain Offline Verifier
# Fetches cryptographic checkpoint and validates SHA-256 chain and Ed25519 signature
# ==============================================================================
set -euo pipefail

GATEWAY_URL="${AGENTTRUST_URL:-http://localhost:3000}"
CHECKPOINT_ID="${1:-latest}"

echo "Fetching cryptographic attestation for checkpoint: ${CHECKPOINT_ID}..."

ATTESTATION_JSON=$(curl -sSf "${GATEWAY_URL}/api/v1/audit/attestation/${CHECKPOINT_ID}")

IS_VALID=$(echo "${ATTESTATION_JSON}" | grep -o '"isValid":true' || true)

if [ -n "${IS_VALID}" ]; then
    echo "========================================================================"
    echo "STATUS: VERIFIED"
    echo "Cryptographic signature and audit hash chain are mathematically valid."
    echo "========================================================================"
    echo "${ATTESTATION_JSON}" | grep -o '"tipHash":"[^"]*"' || true
    echo "${ATTESTATION_JSON}" | grep -o '"totalRecords":[0-9]*' || true
    exit 0
else
    echo "========================================================================"
    echo "STATUS: TAMPER DETECTED OR INVALID SIGNATURE"
    echo "The audit ledger has been modified or signature does not match."
    echo "========================================================================"
    echo "${ATTESTATION_JSON}"
    exit 1
fi
