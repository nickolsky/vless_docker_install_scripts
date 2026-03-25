#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo -e "\nERROR line $LINENO: $BASH_COMMAND\n" >&2' ERR

log(){ echo -e "\n== $* =="; }
die(){ echo "ERROR: $*" >&2; exit 1; }
cmd(){ command -v "$1" >/dev/null 2>&1; }

require_root(){ [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo ./install.sh"; }

prompt_var() {
  local var="$1" text="$2" def="${3:-}"
  local cur="${!var:-}"
  [[ -n "$cur" ]] && return 0
  if [[ -t 0 ]]; then
    local input=""
    read -r -p "${text}${def:+ [${def}]}: " input
    [[ -z "$input" ]] && printf -v "$var" "%s" "$def" || printf -v "$var" "%s" "$input"
  else
    printf -v "$var" "%s" "$def"
    echo "No TTY detected; using default ${var}='${!var}'" >&2
  fi
}

ensure_prereqs(){
  log "Ensuring prerequisites"
  #apt-get update -y
  #apt-get install -y curl openssl coreutils dnsutils ca-certificates gnupg lsb-release
}

install_docker_ubuntu() {
  log "Installing Docker Engine + compose plugin"
  install -m 0755 -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/docker.gpg ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
  fi

  local codename; codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-jammy}")"
  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${codename} stable
EOF

  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker
}

ensure_docker(){
  if ! cmd docker; then install_docker_ubuntu; fi
  systemctl enable --now docker >/dev/null 2>&1 || true
  docker compose version >/dev/null 2>&1 || install_docker_ubuntu
}

docker_pull_or_die() {
  local img="$1"
  log "Pulling image: $img"
  timeout 240s docker pull "$img" >/dev/null || die "Failed to pull $img"
}

# --- FIREWALL (SSH-SAFE) ---

ensure_ssh_safe_ufw() {
  # Only if ufw exists; do NOT remove anything; only allow ssh then enable (if user has ufw installed)
  if cmd ufw; then
    ufw allow 22/tcp >/dev/null 2>&1 || true
    ufw allow OpenSSH >/dev/null 2>&1 || true
    # If ufw is inactive, enabling can lock you out unless ssh allowed (we ensure it above)
    if ufw status | grep -qi inactive; then
      ufw --force enable >/dev/null 2>&1 || true
    fi
  fi
}

open_firewall_port() {
  local port="$1" proto="${2:-tcp}"

  # UFW
  if cmd ufw; then
    ufw allow "${port}/${proto}" >/dev/null 2>&1 || true
    echo "Firewall: opened ${port}/${proto} via ufw"
    return 0
  fi

  # firewalld
  if cmd firewall-cmd && systemctl is-active --quiet firewalld; then
    firewall-cmd --zone=public --add-port="${port}/${proto}" >/dev/null 2>&1 || true
    firewall-cmd --zone=public --add-port="${port}/${proto}" --permanent >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    echo "Firewall: opened ${port}/${proto} via firewalld"
    return 0
  fi

  # iptables fallback
  if cmd iptables; then
    iptables -I INPUT -p "${proto}" --dport "${port}" -j ACCEPT >/dev/null 2>&1 || true
    echo "Firewall: opened ${port}/${proto} via iptables (non-persistent)"
    return 0
  fi

  echo "WARNING: No firewall tool found; open ${port}/${proto} manually."
}

is_port_in_use(){
  local port="$1"
  ss -lntp 2>/dev/null | awk '{print $4}' | grep -qE ":${port}$"
}

stop_host_webservers() {
  for svc in nginx apache2; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      log "Stopping host service $svc (free 80/443)"
      systemctl stop "$svc" || true
      systemctl disable "$svc" || true
    fi
  done
}

# --- XRAY REALITY CREDS (supports old+new x25519 output) ---

gen_xray_secrets() {
  local img="ghcr.io/xtls/xray-core:latest"
  echo "== Pulling official Xray image for REALITY key generation: ${img} =="
  docker_pull_or_die "$img"

  echo "== Generating UUID =="
  XRAY_UUID="$(docker run --rm "$img" uuid 2>&1 | tr -d '\r' | head -n1)"
  [[ -n "$XRAY_UUID" ]] || die "Failed to generate UUID"

  echo "== Generating REALITY x25519 keypair =="
  local xout
  xout="$(docker run --rm "$img" x25519 2>&1 | tr -d '\r')"

  # Robust parsing for Private Key and Public Key/Password
  # Xray output can be "PrivateKey: <key>" or "Private key: <key>"
  XRAY_PRIVKEY="$(echo "$xout" | grep -Ei '^Private[ ]?key:' | head -n1 | awk -F': ' '{print $2}')"
  XRAY_PUBKEY="$(echo "$xout" | grep -Ei '^(Public[ ]?key:|Password:)' | head -n1 | awk -F': ' '{print $2}')"

  # Clean up any trailing/leading whitespace
  XRAY_PRIVKEY="$(echo "$XRAY_PRIVKEY" | xargs)"
  XRAY_PUBKEY="$(echo "$XRAY_PUBKEY" | xargs)"

  # Final sanity: must look like base64url-ish token
  if [[ -z "$XRAY_PRIVKEY" || -z "$XRAY_PUBKEY" ]]; then
    echo "Failed to parse x25519 output:"
    echo "---- Raw output ----"
    echo "$xout"
    echo "-------------------"
    die "x25519 parse failed"
  fi
  if ! echo "$XRAY_PRIVKEY" | grep -Eq '^[A-Za-z0-9_-]{43,}$'; then
    echo "Parsed private key looks invalid: $XRAY_PRIVKEY"
    die "Invalid private key format"
  fi
  if ! echo "$XRAY_PUBKEY" | grep -Eq '^[A-Za-z0-9_-]{43,}$'; then
    echo "Parsed public key/password looks invalid: $XRAY_PUBKEY"
    die "Invalid public key format"
  fi

  XRAY_SHORTID="$(openssl rand -hex 8)"
  [[ -n "$XRAY_SHORTID" ]] || die "Failed to generate shortId"
}

write_xray(){
  log "Writing /opt/xray"
  mkdir -p /opt/xray

  cat > /opt/xray/docker-compose.yml <<'YAML'
services:
  xray:
    image: ghcr.io/xtls/xray-core:latest
    container_name: xray-reality
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config.json:/etc/xray/config.json:ro
    command: run -config /etc/xray/config.json
    environment:
      - XRAY_LOG_LEVEL=info
YAML

  cat > /opt/xray/config.json <<JSON
{
  "log": { "loglevel": "info" },
  "inbounds": [
    {
      "tag": "reality-in",
      "port": ${XRAY_PORT},
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          { "id": "${XRAY_UUID}", "flow": "xtls-rprx-vision", "email": "user@xray" }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${REALITY_DOMAIN}:443",
          "xver": 0,
          "serverNames": [ "${REALITY_DOMAIN}" ],
          "privateKey": "${XRAY_PRIVKEY}",
          "shortIds": [ "${XRAY_SHORTID}", "" ],
          "spiderX": "/"
        }
      }
    }
  ],
  "outbounds": [
    { "tag": "direct", "protocol": "freedom", "settings": {} },
    { "tag": "block", "protocol": "blackhole", "settings": {} }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      { "type": "field", "inboundTag": [ "reality-in" ], "outboundTag": "direct" }
    ]
  }
}
JSON
}

start_xray(){
  log "Starting Xray"
  docker_pull_or_die "ghcr.io/xtls/xray-core:latest"

  # Clean old container if exists (host network can keep port busy)
  (cd /opt/xray && docker compose down) >/dev/null 2>&1 || true
  docker rm -f xray-reality >/dev/null 2>&1 || true

  (cd /opt/xray && docker compose up -d --force-recreate)
  sleep 2

  if docker ps --format '{{.Names}} {{.Status}}' | grep -q '^xray-reality .*Restarting'; then
    docker logs --tail=150 xray-reality || true
    die "xray-reality is restarting (see logs above)"
  fi
}

write_www(){
  log "Writing /opt/www/html"
  mkdir -p /opt/www/html
  cat > /opt/www/html/index.html <<'HTML'
<!doctype html>
<html><head><meta charset="utf-8"><title>Welcome home</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>body{font-family:system-ui,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;margin:40px;line-height:1.5}
.card{max-width:720px;padding:24px;border:1px solid #ddd;border-radius:12px}</style></head>
<body><div class="card"><h1>Welcome home</h1><p>Nginx is working (HTTP).</p></div></body></html>
HTML
}

reset_nginx_dir(){
  log "Resetting /opt/nginx (remove old configs)"
  rm -rf /opt/nginx
  mkdir -p /opt/nginx/conf.d /opt/nginx/certbot-www /opt/nginx/certbot-conf
}

write_nginx_http_only(){
  log "Writing Nginx HTTP-only config"
  cat > /opt/nginx/conf.d/00-http.conf <<CONF
server {
  listen 80;
  server_name ${NGINX_DOMAIN:-_};

  location /.well-known/acme-challenge/ { root /var/www/certbot; }
  location / { root /usr/share/nginx/html; index index.html; }
}
CONF
  # Ensure no leftover https configs
  rm -f /opt/nginx/conf.d/*https*.conf /opt/nginx/conf.d/*443*.conf 2>/dev/null || true
}

write_nginx_compose(){
  log "Writing /opt/nginx/docker-compose.yml"
  cat > /opt/nginx/docker-compose.yml <<'YAML'
services:
  nginx:
    image: nginx:stable
    container_name: nginx-web
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/www/html:/usr/share/nginx/html:ro
      - ./conf.d:/etc/nginx/conf.d:ro
      - ./certbot-www:/var/www/certbot
      - ./certbot-conf:/etc/letsencrypt
  certbot:
    image: certbot/certbot:latest
    container_name: certbot
    volumes:
      - ./certbot-www:/var/www/certbot
      - ./certbot-conf:/etc/letsencrypt
YAML
}

start_nginx(){
  log "Starting nginx (HTTP-only first)"
  docker_pull_or_die "nginx:stable"
  docker rm -f nginx-web >/dev/null 2>&1 || true
  (cd /opt/nginx && docker compose up -d nginx)
  sleep 2

  if docker ps --format '{{.Names}} {{.Status}}' | grep -q '^nginx-web .*Restarting'; then
    docker logs --tail=150 nginx-web || true
    die "nginx-web is restarting (likely port 80/443 already in use)"
  fi

  curl -fsS --max-time 3 http://127.0.0.1/ >/dev/null || die "nginx not reachable on localhost:80"
  echo "nginx HTTP OK."
}

issue_cert_then_enable_443(){
  if [[ -z "${NGINX_DOMAIN}" || -z "${LE_EMAIL}" ]]; then
    echo "Skipping Let's Encrypt (no NGINX_DOMAIN or LE_EMAIL)."
    return 0
  fi
  if [[ "${NGINX_DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Skipping Let's Encrypt: NGINX_DOMAIN is an IP."
    return 0
  fi
  if [[ "${NGINX_DOMAIN}" == "${REALITY_DOMAIN}" ]]; then
    echo "Skipping Let's Encrypt: NGINX_DOMAIN must be a domain you control (not REALITY mimic)."
    return 0
  fi

  docker_pull_or_die "certbot/certbot:latest"

  log "Requesting Let's Encrypt cert for ${NGINX_DOMAIN}"
  set +e
  (cd /opt/nginx && docker compose run --rm certbot certonly \
    --webroot -w /var/www/certbot \
    -d "${NGINX_DOMAIN}" \
    --email "${LE_EMAIL}" \
    --agree-tos --no-eff-email)
  local rc=$?
  set -e
  [[ $rc -eq 0 ]] || { echo "Certbot failed; keeping HTTP only."; return 0; }

  log "Enabling HTTPS (443) config and reloading nginx"
  cat > /opt/nginx/conf.d/10-https.conf <<CONF
server {
  listen 443 ssl http2;
  server_name ${NGINX_DOMAIN};

  ssl_certificate     /etc/letsencrypt/live/${NGINX_DOMAIN}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${NGINX_DOMAIN}/privkey.pem;

  location /.well-known/acme-challenge/ { root /var/www/certbot; }
  location / { root /usr/share/nginx/html; index index.html; }
}
CONF

  docker exec nginx-web nginx -s reload || true
}

get_public_ip(){ curl -fsSL https://api.ipify.org 2>/dev/null || true; }

print_out(){
  local ip; ip="$(get_public_ip)"
  echo ""
  echo "==================== XRAY REALITY VLESS ===================="
  echo "1. Address:    ${ip:-<your-server-ip>}"
  echo "2. Port:       ${XRAY_PORT}"
  echo "3. ID (UUID):  ${XRAY_UUID}"
  echo "4. Flow:       xtls-rprx-vision"
  echo "5. Encryption: none"
  echo "6. Transport:  tcp"
  echo "7. Security:   reality"
  echo "8. SNI:        ${REALITY_DOMAIN}"
  echo "9. Fingerprint: chrome (uTLS)"
  echo "10. PublicKey: ${XRAY_PUBKEY}"
  echo "11. ShortID:   ${XRAY_SHORTID} (or leave blank)"
  echo "12. SpiderX:   /"
  echo "============================================================"
  echo ""
  echo "Troubleshooting:"
  echo "- IMPORTANT: In v2rayN, ensure 'Flow' is set to 'xtls-rprx-vision' and 'Fingerprint' is 'chrome'."
  echo "- If using v2rayN 7.x, try setting 'SpiderX' to '/' in the transport/reality settings if available."
  echo "- Ensure your client supports Xray REALITY (e.g., v2rayN 6.0+, v2rayNG 1.8+, Nekoray 3.0+)."
  echo "- If connection still fails, try changing the mimic domain (REALITY_DOMAIN) to 'dl.google.com'."
  echo ""
  echo "Web (HTTP):    http://${ip:-<server-ip>}/"
  [[ -n "${NGINX_DOMAIN}" ]] && echo "Web (Domain):  http://${NGINX_DOMAIN}/"
  [[ -n "${NGINX_DOMAIN}" ]] && echo "HTTPS:         https://${NGINX_DOMAIN}/ (only after cert success)"
  echo ""
}

main(){
  require_root
  ensure_prereqs
  ensure_docker

  prompt_var REALITY_DOMAIN "Enter REALITY domain to mimic (e.g., dl.google.com)" "dl.google.com"
  prompt_var XRAY_PORT      "Enter XRAY listen port" "8443"
  prompt_var NGINX_DOMAIN   "Enter YOUR domain for nginx/certbot (must point to this server). Blank=HTTP only" ""
  prompt_var LE_EMAIL       "Enter email for Let's Encrypt (blank=skip cert)" ""

  [[ "${XRAY_PORT}" =~ ^[0-9]+$ ]] || die "Invalid XRAY_PORT"
  (( XRAY_PORT >= 1 && XRAY_PORT <= 65535 )) || die "XRAY_PORT out of range"

  # If port is used, auto-increment until free (no extra prompts)
  while is_port_in_use "${XRAY_PORT}"; do
    echo "Port ${XRAY_PORT} in use; trying next..."
    XRAY_PORT=$((XRAY_PORT+1))
    (( XRAY_PORT <= 65535 )) || die "No free port found"
  done
  echo "Using XRAY_PORT=${XRAY_PORT}"

  stop_host_webservers

  # Firewall: keep SSH safe, then open ports
  ensure_ssh_safe_ufw
  open_firewall_port 22 tcp
  open_firewall_port "${XRAY_PORT}" tcp
  open_firewall_port 80 tcp
  open_firewall_port 443 tcp

  gen_xray_secrets
  write_xray
  start_xray

  write_www
  reset_nginx_dir
  write_nginx_http_only
  write_nginx_compose
  start_nginx
  issue_cert_then_enable_443

  print_out

  log "Status"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | sed 's/\t/  /g'
  echo ""
  echo "Logs:"
  echo "  docker logs -f xray-reality"
  echo "  docker logs -f nginx-web"
}

main "$@"