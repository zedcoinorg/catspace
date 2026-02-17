#!/usr/bin/env bash
set -euo pipefail

log() {
  printf "\n[%s] %s\n" "$(date +'%F %T')" "$*"
}

die() {
  echo "ERROR: $*" >&2
  exit 1
}

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    die "Run as root. Example: sudo bash $0"
  fi
}

prompt() {
  local __var="$1"
  local _prompt="$2"
  local _default="${3:-}"
  local _val
  if [ -n "$_default" ]; then
    read -r -p "${_prompt} [${_default}]: " _val
  else
    read -r -p "${_prompt}: " _val
  fi
  if [ -z "${_val}" ]; then
    _val="${_default}"
  fi
  if [ -z "${_val}" ]; then
    die "Value required for: ${_prompt}"
  fi
  printf -v "${__var}" "%s" "${_val}"
}

prompt_secret() {
  local __var="$1"
  local _prompt="$2"
  local _default="${3:-}"
  local _val
  if [ -n "$_default" ]; then
    read -r -s -p "${_prompt} [${_default}]: " _val
  else
    read -r -s -p "${_prompt}: " _val
  fi
  echo
  if [ -z "${_val}" ]; then
    _val="${_default}"
  fi
  if [ -z "${_val}" ]; then
    die "Value required for: ${_prompt}"
  fi
  printf -v "${__var}" "%s" "${_val}"
}

prompt_optional() {
  local __var="$1"
  local _prompt="$2"
  local _default="${3:-}"
  local _val
  if [ -n "$_default" ]; then
    read -r -p "${_prompt} [${_default}]: " _val
  else
    read -r -p "${_prompt}: " _val
  fi
  if [ -z "${_val}" ]; then
    _val="${_default}"
  fi
  printf -v "${__var}" "%s" "${_val}"
}

confirm() {
  local _prompt="$1"
  local _default="${2:-y}"
  local _val
  local _hint="[y/N]"
  if [ "$_default" = "y" ]; then _hint="[Y/n]"; fi
  read -r -p "${_prompt} ${_hint}: " _val
  if [ -z "${_val}" ]; then _val="${_default}"; fi
  case "${_val}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

set_conf_kv() {
  local key="$1"
  local value="$2"
  local file="$3"
  if grep -qE "^${key}=" "$file"; then
    sed -i "s#^${key}=.*#${key}=${value}#" "$file"
  else
    echo "${key}=${value}" >> "$file"
  fi
}

install_packages() {
  log "Installing system packages"
  apt-get update -y
  apt-get install -y \
    curl git ca-certificates gnupg lsb-release \
    nginx rsync jq \
    mariadb-server mariadb-client \
    build-essential pkg-config libssl-dev zlib1g-dev libsqlite3-dev patch \
    clang llvm-dev libclang-dev \
    python3 python3-pip \
    certbot python3-certbot-nginx
}

patch_electrs() {
  if [ ! -d "$ELECTRS_DIR" ]; then
    return
  fi
  if [ -f "$ELECTRS_DIR/src/chain.rs" ] && grep -q "new_with_genesis" "$ELECTRS_DIR/src/chain.rs"; then
    log "Electrs already patched"
    return
  fi

  log "Patching electrs for Catcoin compatibility"
  (cd "$ELECTRS_DIR" && python3 - <<'PY'
import re
from pathlib import Path

def replace_once(path, pattern, repl):
    data = Path(path).read_text()
    new, count = re.subn(pattern, repl, data, flags=re.S)
    if count == 0:
        raise SystemExit(f"pattern not found in {path}")
    Path(path).write_text(new)

# chain.rs: add new_with_genesis
chain = Path("src/chain.rs").read_text()
if "new_with_genesis" not in chain:
    replace_once(
        "src/chain.rs",
        r"(pub fn new\\(network: Network\\) -> Self \\{.*?\\n\\s*\\})",
        r\"\"\"\\1

    // create an empty chain with a custom genesis header
    pub fn new_with_genesis(genesis: BlockHeader) -> Self {
        let genesis_hash = genesis.block_hash();
        Self {
            headers: vec![(genesis_hash, genesis)],
            heights: std::iter::once((genesis_hash, 0)).collect(), // genesis header @ zero height
        }
    }\"\"\",
    )

# daemon.rs: add BlockHeader import + genesis_header
daemon = Path("src/daemon.rs").read_text()
if "genesis_header" not in daemon:
    if "Header as BlockHeader" not in daemon:
        replace_once(
            "src/daemon.rs",
            r"(use anyhow::\\{Context, Result\\};\\n\\n)",
            r\"\"\"\\1use bitcoin::blockdata::block::Header as BlockHeader;
\"\"\",
        )
    replace_once(
        "src/daemon.rs",
        r"(Ok\\(Self \\{ p2p, rpc \\}\\)\\n    \\})",
        r\"\"\"\\1

    pub(crate) fn genesis_header(&self) -> Result<BlockHeader> {
        let genesis_hash = self.rpc.get_block_hash(0)?;
        let header_hex: String =
            self.rpc
                .call("getblockheader", &[json!(genesis_hash), json!(false)])?;
        let header_bytes = Vec::from_hex(&header_hex)?;
        let header: BlockHeader = deserialize(&header_bytes)?;
        Ok(header)
    }\"\"\",
    )

# electrum.rs: wire genesis to tracker
electrum = Path("src/electrum.rs").read_text()
if "genesis_header" not in electrum:
    replace_once(
        "src/electrum.rs",
        r\"\"\"\\s*let tracker = Tracker::new\\(config, metrics\\)\\?;\\n\\s*let signal = Signal::new\\(\\);\\n\\s*let daemon = Daemon::connect\\(config, signal.exit_flag\\(\\), tracker.metrics\\(\\)\\)\\?;\"\"\",
        r\"\"\"        let signal = Signal::new();
        let daemon = Daemon::connect(config, signal.exit_flag(), &metrics)?;
        let genesis = daemon.genesis_header()?;
        let tracker = Tracker::new(config, metrics, Some(genesis))?;\"\"\",
    )

# tracker.rs: add BlockHeader import + genesis param
tracker = Path("src/tracker.rs").read_text()
if "genesis: Option<BlockHeader>" not in tracker:
    replace_once(
        "src/tracker.rs",
        r"use anyhow::\\{Context, Result\\};\\nuse bitcoin::\\{BlockHash, Txid\\};",
        "use anyhow::{Context, Result};\\nuse bitcoin::{blockdata::block::Header as BlockHeader, BlockHash, Txid};",
    )
    replace_once(
        "src/tracker.rs",
        r\"\"\"pub fn new\\(config: &Config, metrics: Metrics\\) -> Result<Self> \\{\"\"\",
        r\"\"\"pub fn new(
        config: &Config,
        metrics: Metrics,
        genesis: Option<BlockHeader>,
    ) -> Result<Self> {\"\"\",
    )
    replace_once(
        "src/tracker.rs",
        r"let chain = Chain::new\\(config.network\\);",
        "let chain = match genesis {\\n            Some(header) => Chain::new_with_genesis(header),\\n            None => Chain::new(config.network),\\n        };",
    )

# p2p.rs: protocol version + ignore unknown messages
p2p = Path("src/p2p.rs").read_text()
if "version: 70017" not in p2p:
    replace_once(
        "src/p2p.rs",
        r"version: p2p::PROTOCOL_VERSION,",
        "// Catcoin requires a newer protocol version than rust-bitcoin's default.\\n        // Align with catcoind's protocolversion (70017).\\n        version: 70017,",
    )
if "ignoring unsupported message" not in p2p:
    replace_once(
        "src/p2p.rs",
        r\"\"\"_ => bail!\\(\\n\\s*"unsupported message: command=\\{}, payload=\\{:\\?\\}",\\n\\s*self\\.cmd,\\n\\s*self\\.raw\\n\\s*\\),\"\"\",
        r\"\"\"_ => {
                debug!(
                    "ignoring unsupported message: command={}, payload={:?}",
                    self.cmd, self.raw
                );
                ParsedNetworkMessage::Ignored
            },\"\"\",
    )
PY
  )
}

install_node() {
  local node_ver
  node_ver="$(node -v 2>/dev/null || true)"
  if [[ -z "$node_ver" || ! "$node_ver" =~ ^v16\. ]]; then
    log "Installing Node.js 16.x"
    curl -fsSL https://deb.nodesource.com/setup_16.x | bash -
    apt-get install -y nodejs
  else
    log "Node.js already present: $node_ver"
  fi
}

setup_catcoind() {
  log "Configuring catcoind"
  mkdir -p "$CATCOIN_DATADIR"
  local conf="$CATCOIN_DATADIR/catcoin.conf"
  if [ -f "$conf" ]; then
    cp -a "$conf" "${conf}.bak.$(date +%s)"
  else
    touch "$conf"
  fi

  set_conf_kv "server" "1" "$conf"
  set_conf_kv "daemon" "1" "$conf"
  set_conf_kv "listen" "1" "$conf"
  set_conf_kv "txindex" "1" "$conf"
  set_conf_kv "blockfilterindex" "1" "$conf"
  set_conf_kv "rpcuser" "$RPC_USER" "$conf"
  set_conf_kv "rpcpassword" "$RPC_PASS" "$conf"
  set_conf_kv "rpcport" "$RPC_PORT" "$conf"
  set_conf_kv "rpcbind" "127.0.0.1" "$conf"
  set_conf_kv "rpcallowip" "127.0.0.1" "$conf"

  if [ -n "$CATCOIND_PATH" ]; then
    log "Creating systemd service for catcoind"
    cat > /etc/systemd/system/catcoind.service <<EOF
[Unit]
Description=Catcoin daemon
After=network.target

[Service]
Type=forking
ExecStart=${CATCOIND_PATH} -datadir=${CATCOIN_DATADIR}
ExecStop=${CATCOIND_PATH} -datadir=${CATCOIN_DATADIR} stop
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  if pgrep -x catcoind >/dev/null 2>&1; then
    log "catcoind is already running; skipping service start"
    systemctl enable catcoind.service
  else
    systemctl enable --now catcoind.service
  fi
  fi
}

setup_mariadb() {
  log "Configuring MariaDB"
  systemctl enable --now mariadb
  mysql -u root -e "CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`;"
  mysql -u root -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';"
  mysql -u root -e "CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';"
  mysql -u root -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';"
  mysql -u root -e "GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'127.0.0.1';"
  mysql -u root -e "FLUSH PRIVILEGES;"
}

setup_electrum() {
  if ! $INSTALL_ELECTRUM; then
    log "Skipping Electrum server installation"
    return
  fi

  log "Installing Electrum server (electrs)"
  if ! command -v cargo >/dev/null 2>&1; then
    log "Installing Rust toolchain (rustup)"
    curl https://sh.rustup.rs -sSf | sh -s -- -y
    source /root/.cargo/env
  fi

  if [ ! -d "$ELECTRS_DIR" ]; then
    git clone "$ELECTRS_REPO" "$ELECTRS_DIR"
  fi

  if [ -d "$ELECTRS_DIR/.git" ]; then
    (cd "$ELECTRS_DIR" && git pull --ff-only)
  fi
  patch_electrs
  (cd "$ELECTRS_DIR" && cargo build --release)
  install -m 0755 "$ELECTRS_DIR/target/release/electrs" /usr/local/bin/electrs

  mkdir -p /var/lib/electrs
  if [ ! -f "$CATCOIN_DATADIR/.cookie" ]; then
    printf '%s:%s' "$RPC_USER" "$RPC_PASS" > "$CATCOIN_DATADIR/.cookie"
    chmod 600 "$CATCOIN_DATADIR/.cookie"
  fi

  local network_arg=""
  if [ -n "$ELECTRS_NETWORK" ]; then
    network_arg="--network=${ELECTRS_NETWORK}"
  fi

  local magic_arg=""
  if [ -n "$ELECTRS_MAGIC" ]; then
    magic_arg="--magic=${ELECTRS_MAGIC}"
  fi

  log "Creating systemd service for electrs"
  cat > /etc/systemd/system/electrs.service <<EOF
[Unit]
Description=Electrs server
After=network.target catcoind.service

[Service]
Type=simple
ExecStart=/usr/local/bin/electrs \
  --db-dir=/var/lib/electrs \
  --daemon-dir=${CATCOIN_DATADIR} \
  --daemon-rpc-addr=127.0.0.1:${RPC_PORT} \
  --daemon-p2p-addr=127.0.0.1:${P2P_PORT} \
  --electrum-rpc-addr=${ELECTRUM_HOST}:${ELECTRUM_PORT} \
  --cookie-file=${CATCOIN_DATADIR}/.cookie \
  ${network_arg} \
  ${magic_arg}
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now electrs.service
}

ensure_repo() {
  if [ ! -d "$REPO_PATH/backend" ] || [ ! -d "$REPO_PATH/frontend" ]; then
    die "Run this script from the explorer repo (missing backend/ or frontend/). Current: $REPO_PATH"
  fi
  log "Using repo at $REPO_PATH"
}

configure_backend() {
  log "Configuring explorer backend"
  local cfg="$REPO_PATH/backend/mempool-config.json"
  local sample="$REPO_PATH/backend/mempool-config.sample.json"
  if [ ! -f "$cfg" ]; then
    cp "$sample" "$cfg"
  fi

  local tmp
  tmp="$(mktemp)"
  jq \
    --arg rpc_host "127.0.0.1" \
    --argjson rpc_port "$RPC_PORT" \
    --arg rpc_user "$RPC_USER" \
    --arg rpc_pass "$RPC_PASS" \
    --arg el_host "$ELECTRUM_HOST" \
    --argjson el_port "$ELECTRUM_PORT" \
    --argjson el_tls "$ELECTRUM_TLS" \
    --arg db_host "127.0.0.1" \
    --argjson db_port 3306 \
    --arg db_name "$DB_NAME" \
    --arg db_user "$DB_USER" \
    --arg db_pass "$DB_PASS" \
    --arg api_url "${PROTOCOL}://${PUBLIC_HOST}/api/v1" \
    --argjson backend_port "$BACKEND_PORT" \
    '.MEMPOOL.ENABLED=true
     | .MEMPOOL.BACKEND="electrum"
     | .MEMPOOL.HTTP_PORT=$backend_port
     | .CORE_RPC.HOST=$rpc_host
     | .CORE_RPC.PORT=$rpc_port
     | .CORE_RPC.USERNAME=$rpc_user
     | .CORE_RPC.PASSWORD=$rpc_pass
     | .SECOND_CORE_RPC.HOST=$rpc_host
     | .SECOND_CORE_RPC.PORT=$rpc_port
     | .SECOND_CORE_RPC.USERNAME=$rpc_user
     | .SECOND_CORE_RPC.PASSWORD=$rpc_pass
     | .ELECTRUM.HOST=$el_host
     | .ELECTRUM.PORT=$el_port
     | .ELECTRUM.TLS_ENABLED=$el_tls
     | .DATABASE.ENABLED=true
     | .DATABASE.HOST=$db_host
     | .DATABASE.PORT=$db_port
     | .DATABASE.DATABASE=$db_name
     | .DATABASE.USERNAME=$db_user
     | .DATABASE.PASSWORD=$db_pass
     | .EXTERNAL_DATA_SERVER.MEMPOOL_API=$api_url
    ' "$cfg" > "$tmp"
  mv "$tmp" "$cfg"

  log "Installing backend dependencies and building"
  (cd "$REPO_PATH/backend" && npm ci && npm run build)

  log "Creating backend systemd service"
  local node_path
  node_path="$(command -v node)"
  cat > /etc/systemd/system/catcoin-mempool.service <<EOF
[Unit]
Description=Catcoin Mempool Backend
After=network.target mariadb.service electrs.service

[Service]
Type=simple
WorkingDirectory=${REPO_PATH}/backend
ExecStart=${node_path} ${REPO_PATH}/backend/dist/index.js
Environment=MEMPOOL_CONFIG_FILE=${REPO_PATH}/backend/mempool-config.json
Environment=NODE_ENV=production
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now catcoin-mempool.service
}

configure_frontend() {
  log "Configuring explorer frontend"
  local cfg="$REPO_PATH/frontend/mempool-frontend-config.json"
  local sample="$REPO_PATH/frontend/mempool-frontend-config.sample.json"
  if [ ! -f "$cfg" ]; then
    cp "$sample" "$cfg"
  fi

  local tmp
  tmp="$(mktemp)"
  jq \
    --arg proto "$PROTOCOL" \
    --arg host "$PUBLIC_HOST" \
    --arg port "$WEB_PORT" \
    --arg url "${PROTOCOL}://${PUBLIC_HOST}" \
    '.NGINX_PROTOCOL=$proto
     | .NGINX_HOSTNAME=$host
     | .NGINX_PORT=$port
     | .MEMPOOL_WEBSITE_URL=$url
    ' "$cfg" > "$tmp"
  mv "$tmp" "$cfg"

  log "Installing frontend dependencies and building"
  (cd "$REPO_PATH/frontend" && npm ci && npm run build)

  log "Deploying frontend to ${WEB_ROOT}"
  mkdir -p "$WEB_ROOT"
  rsync -av "$REPO_PATH/frontend/dist/mempool/browser/" "$WEB_ROOT/"
  rsync -av "$REPO_PATH/frontend/dist/mempool/browser/en-US/" "$WEB_ROOT/"
  chown -R www-data:www-data "$WEB_ROOT"
}

configure_nginx() {
  log "Configuring nginx"
  local conf="/etc/nginx/sites-available/${PUBLIC_HOST}.conf"

  if [ "$PROTOCOL" = "https" ]; then
    cat > "$conf" <<EOF
server {
  listen 80;
  server_name ${PUBLIC_HOST};

  location /.well-known/acme-challenge/ {
    root ${WEB_ROOT};
  }

  return 301 https://${PUBLIC_HOST}\$request_uri;
}

server {
  listen 443 ssl http2;
  server_name ${PUBLIC_HOST};

  ssl_certificate /etc/letsencrypt/live/${PUBLIC_HOST}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/${PUBLIC_HOST}/privkey.pem;
  include /etc/letsencrypt/options-ssl-nginx.conf;
  ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

  set \$lang "en-US";

  access_log /var/log/nginx/${PUBLIC_HOST}.access.log;
  error_log /var/log/nginx/${PUBLIC_HOST}.error.log;

  root ${WEB_ROOT};
  index index.html;

  add_header Cache-Control "public, no-transform";
  add_header Vary Accept-Language;
  add_header Vary Cookie;

  location / {
    try_files /\$lang/\$uri /\$lang/\$uri/ \$uri \$uri/ /en-US/\$uri @index-redirect;
    expires 10m;
  }

  location /resources {
    try_files \$uri @index-redirect;
    expires 1h;
  }

  location /resources/config. {
    try_files \$uri =404;
    expires 5m;
  }

  location @index-redirect {
    rewrite (.*) /\$lang/index.html;
  }

  location = /api {
    try_files \$uri \$uri/ /en-US/index.html =404;
  }
  location = /api/ {
    try_files \$uri \$uri/ /en-US/index.html =404;
  }

  location /api/v1/ws {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "Upgrade";
  }
  location /api/v1 {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/v1;
  }
  location /api/ {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/v1/;
  }

  location /ws {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "Upgrade";
  }
}
EOF
  else
    cat > "$conf" <<EOF
server {
  listen 80;
  server_name ${PUBLIC_HOST};

  set \$lang "en-US";

  access_log /var/log/nginx/${PUBLIC_HOST}.access.log;
  error_log /var/log/nginx/${PUBLIC_HOST}.error.log;

  root ${WEB_ROOT};
  index index.html;

  add_header Cache-Control "public, no-transform";
  add_header Vary Accept-Language;
  add_header Vary Cookie;

  location / {
    try_files /\$lang/\$uri /\$lang/\$uri/ \$uri \$uri/ /en-US/\$uri @index-redirect;
    expires 10m;
  }

  location /resources {
    try_files \$uri @index-redirect;
    expires 1h;
  }

  location /resources/config. {
    try_files \$uri =404;
    expires 5m;
  }

  location @index-redirect {
    rewrite (.*) /\$lang/index.html;
  }

  location = /api {
    try_files \$uri \$uri/ /en-US/index.html =404;
  }
  location = /api/ {
    try_files \$uri \$uri/ /en-US/index.html =404;
  }

  location /api/v1/ws {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "Upgrade";
  }
  location /api/v1 {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/v1;
  }
  location /api/ {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/v1/;
  }

  location /ws {
    proxy_pass http://127.0.0.1:${BACKEND_PORT}/;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "Upgrade";
  }
}
EOF
  fi

  ln -sf "$conf" /etc/nginx/sites-enabled/${PUBLIC_HOST}.conf
  nginx -t
  systemctl enable --now nginx
  systemctl reload nginx
}

obtain_cert() {
  if [ "$PROTOCOL" != "https" ]; then
    log "Skipping certificate (HTTP only)"
    return
  fi

  if [ -f "/etc/letsencrypt/live/${PUBLIC_HOST}/fullchain.pem" ]; then
    log "Certificate already exists for ${PUBLIC_HOST}"
    return
  fi

  log "Obtaining Let's Encrypt certificate for ${PUBLIC_HOST}"
  certbot certonly --webroot -w "$WEB_ROOT" -d "$PUBLIC_HOST" --non-interactive --agree-tos -m "$CERTBOT_EMAIL"
}

health_check() {
  log "Health checks"
  curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/v1/init-data" >/dev/null && echo "Backend OK"
  curl -fsS "${PROTOCOL}://${PUBLIC_HOST}/api/v1/init-data" >/dev/null && echo "Public API OK" || true
}

main() {
  require_root

  log "Collecting parameters"
  prompt PUBLIC_HOST "Explorer hostname or IP (no port)" "localhost"
  SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
  REPO_PATH="$SCRIPT_DIR"
  prompt BACKEND_PORT "Backend HTTP port" "8999"
  prompt WEB_ROOT "Web root for nginx" "/var/www/${PUBLIC_HOST}"

  prompt DB_NAME "MariaDB database name" "mempool"
  prompt DB_USER "MariaDB username" "mempool"
  prompt_secret DB_PASS "MariaDB password" "mempool"

  prompt RPC_USER "catcoind RPC username" "catcoinrpc"
  prompt_secret RPC_PASS "catcoind RPC password" "catcoinrpc"
  prompt RPC_PORT "catcoind RPC port" "9932"
  prompt P2P_PORT "catcoind P2P port" "9933"

  prompt CATCOIN_DATADIR "catcoind data directory" "/root/.catcoin"
  CATCOIND_PATH="$(command -v catcoind || true)"
  if [ -z "$CATCOIND_PATH" ]; then
    prompt CATCOIND_PATH "Path to catcoind binary" "/root/catcoin/bin/catcoind"
  else
    echo "Found catcoind at ${CATCOIND_PATH}"
  fi

  if confirm "Install Electrum server (electrs)?" "y"; then
    INSTALL_ELECTRUM=true
  else
    INSTALL_ELECTRUM=false
  fi

  if $INSTALL_ELECTRUM; then
    prompt ELECTRUM_HOST "Electrum bind host" "127.0.0.1"
    prompt ELECTRUM_PORT "Electrum port" "50001"
    if confirm "Enable Electrum TLS?" "n"; then
      ELECTRUM_TLS=true
    else
      ELECTRUM_TLS=false
    fi
    prompt ELECTRS_REPO "Electrs repo URL (use your catcoin-compatible fork if needed)" "https://github.com/zedcoinorg/electrs"
    prompt ELECTRS_DIR "Electrs source directory" "/opt/electrs"
    prompt_optional ELECTRS_NETWORK "Electrs network name (leave empty for default)" ""
    prompt_optional ELECTRS_MAGIC "Electrs magic (hex, optional)" ""
  else
    ELECTRUM_HOST="127.0.0.1"
    ELECTRUM_PORT="50001"
    ELECTRUM_TLS=false
  fi

  if confirm "Enable HTTPS with Let's Encrypt? (requires valid domain + DNS)" "n"; then
    PROTOCOL="https"
    WEB_PORT="443"
    prompt CERTBOT_EMAIL "Email for Let's Encrypt" "admin@${PUBLIC_HOST}"
  else
    PROTOCOL="http"
    WEB_PORT="80"
    CERTBOT_EMAIL=""
  fi

  if [ "$PROTOCOL" = "https" ]; then
    if [[ "$PUBLIC_HOST" =~ ^[0-9.]+$ || "$PUBLIC_HOST" = "localhost" || "$PUBLIC_HOST" != *.* ]]; then
      log "HTTPS disabled: PUBLIC_HOST is not a valid FQDN for Let's Encrypt (${PUBLIC_HOST})"
      PROTOCOL="http"
      WEB_PORT="80"
      CERTBOT_EMAIL=""
    fi
  fi

  install_packages
  install_node
  setup_catcoind
  setup_mariadb
  setup_electrum
  ensure_repo
  configure_backend
  configure_frontend
  if [ "$PROTOCOL" = "https" ] && [ ! -f "/etc/letsencrypt/live/${PUBLIC_HOST}/fullchain.pem" ]; then
    log "Temporarily configuring HTTP to obtain certificate"
    PROTOCOL="http"
    configure_nginx
    PROTOCOL="https"
    obtain_cert
  fi
  configure_nginx
  health_check

  log "Done"
  echo "Explorer URL: ${PROTOCOL}://${PUBLIC_HOST}"
  echo "Services:"
  echo "  - catcoind.service"
  if $INSTALL_ELECTRUM; then
    echo "  - electrs.service"
  fi
  echo "  - catcoin-mempool.service"
  echo "  - mariadb.service"
  echo "  - nginx.service"
  echo
  echo "To change domain later:"
  echo "  1) Edit ${REPO_PATH}/frontend/mempool-frontend-config.json"
  echo "  2) Edit ${REPO_PATH}/backend/mempool-config.json (EXTERNAL_DATA_SERVER.MEMPOOL_API)"
  echo "  3) Edit /etc/nginx/sites-available/${PUBLIC_HOST}.conf"
  echo "  4) Rebuild frontend: cd ${REPO_PATH}/frontend && npm ci && npm run build"
  echo "  5) Deploy: rsync -av ${REPO_PATH}/frontend/dist/mempool/browser/ ${WEB_ROOT}/"
  echo "            rsync -av ${REPO_PATH}/frontend/dist/mempool/browser/en-US/ ${WEB_ROOT}/"
  echo "  6) Reload nginx: systemctl reload nginx"
}

main "$@"
