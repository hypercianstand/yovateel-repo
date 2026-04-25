#!/usr/bin/env bash
# uninstall.sh — Remove gh-tunnel-server from a Linux system
# Usage: sudo bash uninstall.sh

set -euo pipefail

INSTALL_DIR="/opt/gh-tunnel"
SERVICE_NAME="gh-tunnel-server"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[uninstall]${NC} $*"; }
warn() { echo -e "${YELLOW}[warn]${NC} $*"; }

# Stop and disable service
if command -v systemctl &>/dev/null && [ -f "${SERVICE_FILE}" ]; then
    log "Stopping service ${SERVICE_NAME} ..."
    systemctl stop "${SERVICE_NAME}" 2>/dev/null || warn "Service was not running"
    systemctl disable "${SERVICE_NAME}" 2>/dev/null || true
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload
    log "Service removed"
else
    warn "systemd service not found; skipping"
fi

# Optionally remove logs
read -r -p "Remove log files in /var/log/gh-tunnel? [y/N] " removelogs
if [ "${removelogs}" = "y" ] || [ "${removelogs}" = "Y" ]; then
    rm -rf /var/log/gh-tunnel
    log "Logs removed"
fi

# Remove install directory
if [ -d "${INSTALL_DIR}" ]; then
    read -r -p "Remove ${INSTALL_DIR} (includes config + binary)? [y/N] " removeall
    if [ "${removeall}" = "y" ] || [ "${removeall}" = "Y" ]; then
        rm -rf "${INSTALL_DIR}"
        log "Removed ${INSTALL_DIR}"
    else
        warn "Kept ${INSTALL_DIR}"
    fi
else
    warn "${INSTALL_DIR} not found; nothing to remove"
fi

log "Uninstallation complete."
