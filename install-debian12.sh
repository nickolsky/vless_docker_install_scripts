#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo -e "\nERROR line $LINENO: $BASH_COMMAND\n" >&2' ERR

log(){ echo -e "\n== $* =="; }
die(){ echo "ERROR: $*" >&2; exit 1; }
cmd(){ command -v "$1" >/dev/null 2>&1; }

require_root(){ [[ "${EUID}" -eq 0 ]] || die "Run as root: sudo bash install-debian12.sh"; }

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

trim_value() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf "%s" "$value"
}

url_encode() {
  local value="$1" out="" i ch
  for (( i=0; i<${#value}; i++ )); do
    ch="${value:i:1}"
    case "$ch" in
      [a-zA-Z0-9.~_-]) out+="$ch" ;;
      *) printf -v out '%s%%%02X' "$out" "'$ch" ;;
    esac
  done
  printf "%s" "$out"
}

require_debian12(){
  . /etc/os-release
  [[ "${ID:-}" == "debian" && "${VERSION_ID:-}" == "12" ]] || die "This script requires Debian 12 (Bookworm)"
}

check_space(){
  local path="$1" minimum_mb="$2" available_kb
  available_kb="$(df -Pk "$path" | awk 'END {print $4}')"
  (( available_kb >= minimum_mb * 1024 )) || die "Need at least ${minimum_mb} MiB free on $path; found $((available_kb / 1024)) MiB"
}

configure_journal(){
  log "Limiting system journal size and retention (host-wide)"
  install -d -m 0755 /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/99-xray-small-disk.conf <<'EOF'
[Journal]
SystemMaxUse=32M
SystemKeepFree=256M
SystemMaxFileSize=4M
RuntimeMaxUse=16M
RuntimeKeepFree=64M
RuntimeMaxFileSize=2M
MaxRetentionSec=1day
MaxFileSec=15min
EOF
  systemctl restart systemd-journald
  # Vacuum only archived journals; rotate first to include previous active files.
  journalctl --rotate --vacuum-size=32M --vacuum-time=1d
  cat > /etc/systemd/system/xray-journal-cleanup.service <<'EOF'
[Unit]
Description=Rotate and vacuum host journal for small Xray server
[Service]
Type=oneshot
ExecStart=/usr/bin/journalctl --rotate --vacuum-size=32M --vacuum-time=1d
EOF
  cat > /etc/systemd/system/xray-journal-cleanup.timer <<'EOF'
[Unit]
Description=Clean host journal every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=1min
[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now xray-journal-cleanup.timer
}

ensure_prereqs(){
  log "Installing minimal prerequisites"
  apt-get update
  apt-get install -y --no-install-recommends curl openssl ca-certificates iproute2
  apt-get clean
}

install_docker_debian() {
  log "Installing Docker Engine + compose plugin (without Buildx)"
  # Do not silently remove an existing distro Docker/container runtime.
  local package
  for package in docker.io docker-compose podman-docker containerd runc; do
    if [[ "$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)" == "install ok installed" ]]; then
      die "Conflicting package: $package. Migrate the existing Docker installation before rerunning."
    fi
  done
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  cat > /etc/apt/sources.list.d/docker.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable
EOF
  apt-get update
  apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin
  apt-get clean
}

ensure_docker(){
  if ! cmd docker || ! docker compose version >/dev/null 2>&1; then
    install_docker_debian
  fi
  systemctl enable --now docker
  docker info >/dev/null
  local docker_root
  docker_root="$(docker info --format '{{.DockerRootDir}}')"
  check_space "$docker_root" 512
  # New Docker versions may store image content separately in containerd.
  if [[ -d /var/lib/containerd ]]; then check_space /var/lib/containerd 512; fi
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

cleanup_legacy_web(){
  log "Removing legacy fake web containers"
  if [[ -d /opt/nginx ]]; then
    (cd /opt/nginx && docker compose down) >/dev/null 2>&1 || true
  fi
  docker rm -f nginx-web certbot >/dev/null 2>&1 || true
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

  # Robust parsing for Private Key and Public Key across Xray output variants.
  # Recent images may emit:
  #   PrivateKey: <key>
  #   PublicKey: <key>
  #   Password (PublicKey): <key>
  XRAY_PRIVKEY="$(echo "$xout" | sed -n 's/^Private[ ]\?key:[ ]*//Ip' | head -n1)"
  XRAY_PUBKEY="$(echo "$xout" | sed -n 's/^\(Public[ ]\?key\|Password\([ ]*(PublicKey)\)\?\):[ ]*//Ip' | head -n1)"

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
  install -d -m 0700 /opt/xray

  cat > /opt/xray/docker-compose.yml <<'YAML'
services:
  xray:
    image: ghcr.io/xtls/xray-core:latest
    container_name: xray-reality
    restart: unless-stopped
    user: "0:0"
    cap_add:
      - NET_BIND_SERVICE
    network_mode: host
    volumes:
      - ./config.json:/etc/xray/config.json:ro
    command: run -config /etc/xray/config.json
    logging:
      driver: local
      options:
        max-size: "2m"
        max-file: "3"
        compress: "true"
YAML

  local client_json transport_extra_json
  if [[ "${XRAY_TRANSPORT}" == "tcp" ]]; then
    client_json="{ \"id\": \"${XRAY_UUID}\", \"flow\": \"xtls-rprx-vision\", \"email\": \"user@xray\" }"
    transport_extra_json=""
  else
    client_json="{ \"id\": \"${XRAY_UUID}\", \"email\": \"user@xray\" }"
    transport_extra_json=$(cat <<JSON
,
        "xhttpSettings": {
          "path": "${XHTTP_PATH}",
          "mode": "auto"
        }
JSON
)
  fi

  cat > /opt/xray/config.json <<JSON
{
  "log": { "access": "none", "error": "", "loglevel": "warning" },
  "inbounds": [
    {
      "tag": "reality-in",
      "port": ${XRAY_PORT},
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [
          ${client_json}
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "${XRAY_TRANSPORT}",
        "security": "reality"${transport_extra_json},
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
  (cd /opt/xray && docker compose config --quiet)
  (cd /opt/xray && docker compose run --rm --no-deps xray run -test -config /etc/xray/config.json)

  # Clean old container if exists (host network can keep port busy)
  (cd /opt/xray && docker compose down) >/dev/null 2>&1 || true
  docker rm -f xray-reality >/dev/null 2>&1 || true

  (cd /opt/xray && docker compose up -d --force-recreate --pull never)
  sleep 2

  local state restarting
  state="$(docker inspect --format '{{.State.Status}}' xray-reality)"
  restarting="$(docker inspect --format '{{.RestartCount}}' xray-reality)"
  if [[ "$state" != "running" || "$restarting" != "0" ]]; then
    docker logs --tail=150 xray-reality || true
    die "xray-reality did not start cleanly (see logs above)"
  fi
}

get_public_ip(){ curl -fsSL https://api.ipify.org 2>/dev/null || true; }

print_out(){
  local ip; ip="$(get_public_ip)"
  local address="${ip:-YOUR_SERVER_IP}"
  local flow_value="<empty>" vless_link

  if [[ "${XRAY_TRANSPORT}" == "tcp" ]]; then
    flow_value="xtls-rprx-vision"
    vless_link="vless://${XRAY_UUID}@${address}:${XRAY_PORT}?encryption=none&security=reality&sni=$(url_encode "${REALITY_DOMAIN}")&fp=edge&pbk=$(url_encode "${XRAY_PUBKEY}")&sid=$(url_encode "${XRAY_SHORTID}")&spx=$(url_encode "/")&type=tcp&flow=xtls-rprx-vision#$(url_encode "xray-reality-tcp")"
  else
    vless_link="vless://${XRAY_UUID}@${address}:${XRAY_PORT}?encryption=none&security=reality&sni=$(url_encode "${REALITY_DOMAIN}")&fp=edge&pbk=$(url_encode "${XRAY_PUBKEY}")&sid=$(url_encode "${XRAY_SHORTID}")&spx=$(url_encode "/")&type=xhttp&host=$(url_encode "${REALITY_DOMAIN}")&path=$(url_encode "${XHTTP_PATH}")&mode=auto#$(url_encode "xray-reality-xhttp")"
  fi

  echo ""
  echo "==================== XRAY REALITY VLESS ===================="
  echo "1. Address:    ${ip:-<your-server-ip>}"
  echo "2. Port:       ${XRAY_PORT}"
  echo "3. ID (UUID):  ${XRAY_UUID}"
  echo "4. Flow:       ${flow_value}"
  echo "5. Encryption: none"
  echo "6. Transport:  ${XRAY_TRANSPORT}"
  echo "7. Security:   reality"
  echo "8. SNI:        ${REALITY_DOMAIN}"
  echo "9. Fingerprint: edge (uTLS)"
  echo "10. PublicKey: ${XRAY_PUBKEY}"
  echo "11. ShortID:   ${XRAY_SHORTID} (or leave blank)"
  echo "12. SpiderX:   /"
  if [[ "${XRAY_TRANSPORT}" == "xhttp" ]]; then
    echo "13. XHTTP path:${XHTTP_PATH}"
    echo "14. XHTTP mode:auto"
  fi
  echo ""
  echo "VLESS URL:"
  echo "${vless_link}"
  echo "============================================================"
  echo ""
  echo "Troubleshooting:"
  if [[ "${XRAY_TRANSPORT}" == "tcp" ]]; then
    echo "- IMPORTANT: In v2rayN, set 'Flow' to 'xtls-rprx-vision' and transport to 'tcp'."
  else
    echo "- IMPORTANT: In v2rayN, leave 'Flow' empty, set transport to 'xhttp', and set XHTTP path to '${XHTTP_PATH}'."
  fi
  echo "- Set 'Fingerprint' to 'edge' and 'SpiderX' to '/' if your client exposes those fields."
  echo "- Ensure your client supports Xray REALITY (e.g., v2rayN 6.0+, v2rayNG 1.8+, Nekoray 3.0+)."
  echo "- If connection still fails, try changing the mimic domain (REALITY_DOMAIN) to 'dl.google.com'."
  echo ""
}
main(){
  require_root
  require_debian12
  umask 077
  apt-get clean
  configure_journal
  check_space / 1536
  check_space /var 1536
  ensure_prereqs
  ensure_docker

  prompt_var REALITY_DOMAIN "Enter REALITY domain to mimic (e.g., dl.google.com)" "dl.google.com"
  prompt_var XRAY_TRANSPORT "Enter Xray transport (xhttp/tcp)" "xhttp"
  prompt_var XRAY_PORT      "Enter XRAY listen port" "443"

  REALITY_DOMAIN="$(trim_value "${REALITY_DOMAIN}")"
  XRAY_TRANSPORT="$(trim_value "${XRAY_TRANSPORT}")"
  XRAY_TRANSPORT="${XRAY_TRANSPORT,,}"
  XRAY_PORT="$(trim_value "${XRAY_PORT}")"

  [[ -n "${REALITY_DOMAIN}" ]] || die "REALITY_DOMAIN cannot be empty"
  [[ "${XRAY_TRANSPORT}" == "xhttp" || "${XRAY_TRANSPORT}" == "tcp" ]] || die "XRAY_TRANSPORT must be 'xhttp' or 'tcp'"
  [[ "${XRAY_PORT}" =~ ^[0-9]+$ ]] || die "Invalid XRAY_PORT"
  (( XRAY_PORT >= 1 && XRAY_PORT <= 65535 )) || die "XRAY_PORT out of range"

  if [[ "${XRAY_TRANSPORT}" == "xhttp" ]]; then
    prompt_var XHTTP_PATH "Enter XHTTP path" "/xhttp"
    XHTTP_PATH="$(trim_value "${XHTTP_PATH}")"
    [[ -n "${XHTTP_PATH}" ]] || die "XHTTP_PATH cannot be empty"
    [[ "${XHTTP_PATH}" == /* ]] || XHTTP_PATH="/${XHTTP_PATH}"
    [[ "${XHTTP_PATH}" != *\"* && "${XHTTP_PATH}" != *\\* && "${XHTTP_PATH}" != *" "* ]] || die "XHTTP_PATH must not contain spaces, quotes, or backslashes"
  else
    XHTTP_PATH=""
  fi

  echo "Using XRAY_TRANSPORT=${XRAY_TRANSPORT}"
  echo "Using XRAY_PORT=${XRAY_PORT}"
  [[ "${XRAY_TRANSPORT}" == "xhttp" ]] && echo "Using XHTTP_PATH=${XHTTP_PATH}"

  # Firewall: keep SSH safe, then open ports
  ensure_ssh_safe_ufw
  open_firewall_port 22 tcp
  open_firewall_port "${XRAY_PORT}" tcp

  cleanup_legacy_web
  gen_xray_secrets
  write_xray
  start_xray

  apt-get clean
  print_out

  log "Status"
  docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | sed 's/\t/  /g'
  echo ""
  echo "Logs:"
  echo "  docker logs --tail=100 -f xray-reality"
  echo "Xray logs: local driver, 2 MiB x 3 files, compressed; access logs disabled."
  echo "Host journal: 32 MiB disk / 16 MiB runtime, 1 day retention; cleanup every 15 minutes."
  echo "  systemctl status xray-journal-cleanup.timer"
  echo "  journalctl --disk-usage"
  df -h / /var
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
