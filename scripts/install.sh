#!/usr/bin/env bash
# ==============================================================================
# AgentTrust Enterprise Security Gateway - Automated Linux/macOS Installer
# ==============================================================================
set -euo pipefail

BOLD="$(tput bold 2>/dev/null || echo '')"
RESET="$(tput sgr0 2>/dev/null || echo '')"
GREEN="$(tput setaf 2 2>/dev/null || echo '')"
RED="$(tput setaf 1 2>/dev/null || echo '')"
BLUE="$(tput setaf 4 2>/dev/null || echo '')"

log_info() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

log_error() {
    printf "${RED}[ERROR]${RESET} %s\n" "$1" >&2
}

check_prerequisites() {
    log_info "Verifying host runtime prerequisites..."
    if ! command -v node >/dev/null 2>&1; then
        log_error "Node.js 18+ is required but not installed. Please install Node.js."
        exit 1
    fi

    local node_major
    node_major=$(node -v | cut -d'.' -f1 | sed 's/v//')
    if [ "$node_major" -lt 18 ]; then
        log_error "Node.js version must be >= 18 (detected v${node_major})."
        exit 1
    fi

    if ! command -v npm >/dev/null 2>&1; then
        log_error "npm package manager is missing."
        exit 1
    fi
    log_success "Node.js $(node -v) and npm $(npm -v) verified."
}

setup_environment() {
    local install_dir
    install_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    cd "$install_dir"

    log_info "Setting up local state directories..."
    mkdir -p data logs certs

    if [ ! -f .env ]; then
        if [ -f .env.example ]; then
            log_info "Creating default .env from .env.example..."
            cp .env.example .env
        else
            log_info "Generating initial .env configuration..."
            cat <<EOF > .env
PORT=3000
DATABASE_PATH=./data/agent_trust.db
LOG_LEVEL=info
AGENT_TRUST_SECRET=$(openssl rand -hex 32 2>/dev/null || echo "default-insecure-secret-replace-me")
EOF
        fi
    fi

    log_info "Installing dependencies..."
    npm ci --silent || npm install --silent

    log_info "Building production bundles..."
    npm run build

    log_success "AgentTrust build complete."
}

print_summary() {
    cat <<EOF

${BOLD}========================================================================${RESET}
${GREEN}AgentTrust Enterprise Gateway successfully installed!${RESET}
========================================================================

To run the gateway in production mode:
    npm start

To run in development mode with hot-reloading:
    npm run dev

To execute full verification test suite:
    npm test

Default Endpoint:  http://localhost:3000
Documentation:     docs/
API Spec:          docs/api_reference.md

========================================================================
EOF
}

main() {
    check_prerequisites
    setup_environment
    print_summary
}

main "$@"
