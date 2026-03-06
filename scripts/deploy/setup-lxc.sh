#!/usr/bin/env bash
# =============================================================================
# setup-lxc.sh — Bootstrap a fresh Debian/Ubuntu LXC for ServiceNow MCP Server
# =============================================================================
# Run this INSIDE the LXC after creating it in Proxmox.
#
# Proxmox LXC creation (run on Proxmox host):
#   pct create 210 local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst \
#     --hostname servicenow-mcp \
#     --memory 1024 \
#     --cores 2 \
#     --rootfs local-lvm:8 \
#     --net0 name=eth0,bridge=vmbr0,ip=dhcp \
#     --features nesting=1,keyctl=1 \
#     --unprivileged 1 \
#     --onboot 1 \
#     --start 1
#
# Then SSH/console in and run:
#   curl -fsSL https://raw.githubusercontent.com/your-org/servicenow-mcp/main/scripts/deploy/setup-lxc.sh | bash
# Or copy this script in and run: bash setup-lxc.sh
# =============================================================================

set -euo pipefail

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  ServiceNow MCP Server — LXC Setup                  ${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"
echo ""

# ─── 1. System updates ───
info "Updating system packages..."
apt-get update -qq && apt-get upgrade -y -qq
log "System updated"

# ─── 2. Install prerequisites ───
info "Installing prerequisites..."
apt-get install -y -qq \
  ca-certificates \
  curl \
  gnupg \
  lsb-release \
  git \
  unattended-upgrades \
  apt-listchanges
log "Prerequisites installed"

# ─── 3. Install Docker (official method) ───
if command -v docker &> /dev/null; then
  log "Docker already installed: $(docker --version)"
else
  info "Installing Docker..."
  install -m 0755 -d /etc/apt/keyrings

  # Detect distro
  DISTRO=$(. /etc/os-release && echo "$ID")
  if [ "$DISTRO" = "debian" ]; then
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  elif [ "$DISTRO" = "ubuntu" ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
  else
    err "Unsupported distro: $DISTRO. Use Debian 12 or Ubuntu 22.04+."
  fi

  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable docker
  systemctl start docker
  log "Docker installed: $(docker --version)"
fi

# ─── 4. Create deploy user ───
DEPLOY_USER="deploy"
DEPLOY_HOME="/home/${DEPLOY_USER}"

if id "$DEPLOY_USER" &>/dev/null; then
  log "User '${DEPLOY_USER}' already exists"
else
  info "Creating deploy user..."
  useradd -m -s /bin/bash "$DEPLOY_USER"
  usermod -aG docker "$DEPLOY_USER"
  log "User '${DEPLOY_USER}' created and added to docker group"
fi

# ─── 5. Clone the repo ───
APP_DIR="${DEPLOY_HOME}/servicenow-mcp"

if [ -d "$APP_DIR" ]; then
  warn "Directory ${APP_DIR} already exists — pulling latest..."
  cd "$APP_DIR"
  sudo -u "$DEPLOY_USER" git pull origin main || true
else
  info "Cloning repository..."
  sudo -u "$DEPLOY_USER" git clone https://github.com/dobromirmontauk/servicenow-mcp.git "$APP_DIR"
  log "Repository cloned to ${APP_DIR}"
fi

cd "$APP_DIR"

# ─── 6. Create .env.production from template ───
ENV_FILE="${APP_DIR}/.env.production"

if [ -f "$ENV_FILE" ]; then
  warn ".env.production already exists — skipping creation"
else
  info "Creating .env.production from template..."
  cp .env.production.template "$ENV_FILE"
  chown "${DEPLOY_USER}:${DEPLOY_USER}" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
  log ".env.production created with chmod 600"
  echo ""
  warn "You MUST edit .env.production with your actual credentials:"
  echo "   nano ${ENV_FILE}"
  echo ""
  echo "   Required values:"
  echo "   - SERVICENOW_CLIENT_ID"
  echo "   - SERVICENOW_CLIENT_SECRET"
  echo "   - MCP_AUTH_TOKEN        (generate: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\")"
  echo "   - CLOUDFLARE_TUNNEL_TOKEN"
  echo ""
fi

# ─── 7. Enable unattended security updates ───
info "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'AUTOUPDATE'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPDATE
log "Automatic security updates enabled"

# ─── 8. Create systemd service for auto-start ───
info "Creating systemd service for auto-start on boot..."
cat > /etc/systemd/system/servicenow-mcp.service << SYSTEMD
[Unit]
Description=ServiceNow MCP Server (Docker Compose)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
User=${DEPLOY_USER}
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable servicenow-mcp.service
log "Systemd service created and enabled (auto-starts on boot)"

# ─── 9. Create update helper script ───
info "Creating update helper script..."
cat > "${APP_DIR}/update.sh" << 'UPDATE'
#!/usr/bin/env bash
# Quick update: pull latest code and rebuild
set -euo pipefail
cd "$(dirname "$0")"
echo "[i] Pulling latest code..."
git pull origin main
echo "[i] Rebuilding and restarting..."
docker compose up -d --build
echo "[✓] Update complete. Check status:"
docker compose ps
UPDATE
chown "${DEPLOY_USER}:${DEPLOY_USER}" "${APP_DIR}/update.sh"
chmod +x "${APP_DIR}/update.sh"
log "Update script created: ${APP_DIR}/update.sh"

# ─── 10. Summary ───
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Setup Complete!                                     ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Next steps:"
echo ""
echo "  1. Edit credentials:"
echo "     nano ${ENV_FILE}"
echo ""
echo "  2. Build and start:"
echo "     cd ${APP_DIR}"
echo "     sudo -u ${DEPLOY_USER} docker compose up -d --build"
echo ""
echo "  3. Verify:"
echo "     curl http://localhost:8080/health"
echo "     docker compose ps"
echo "     docker compose logs -f"
echo ""
echo "  4. To update later:"
echo "     sudo -u ${DEPLOY_USER} ${APP_DIR}/update.sh"
echo ""
echo "  Service auto-starts on LXC boot via systemd."
echo ""
