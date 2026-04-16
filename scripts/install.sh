#!/usr/bin/env bash
set -euo pipefail

VERSION="$(cat "$(dirname "$0")/../VERSION" 2>/dev/null || echo "dev")"
LOG_FILE="/var/log/nginx-hardening.log"
BACKUP_ROOT="/var/backups/nginx-hardening"

# ------------------------
# Helpers
# ------------------------
log() {
  local msg="$1"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[$ts] $msg" | tee -a "$LOG_FILE" >/dev/null
}

die() { log "ERROR: $1"; exit 1; }

need_root() {
  [[ "$(id -u)" -eq 0 ]] || die "Run as root (sudo)."
}

usage() {
  cat <<'USAGE'
nginx-hardening-framework (Ubuntu, reverse proxy) - install/rollback

Usage:
  install.sh --domain <fqdn> --upstream <url> [options]
  install.sh --domain <fqdn> --rollback

Required:
  --domain            FQDN (server_name) to harden
  --upstream          Reverse proxy upstream (e.g., http://localhost:1001) (not required for --rollback)

Options:
  --req-rate          Rate limit (default 20r/s)
  --burst             Burst (default 40)
  --conn              Max concurrent conns per IP (default 30)
  --hsts-max-age      HSTS max-age seconds (default 300)
  --csp-phase         0|1|2|3 (default 1) (Report-Only)
  --warning-page      on|off (default on) - direct IP warning page + logging
  --dry-run           Show intended actions only
  --rollback          Restore latest backups for domain

Examples:
  sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --upstream http://localhost:1001 --csp-phase 3
  sudo bash scripts/install.sh --domain vapt.backoffice.saafir.co --rollback
USAGE
}

tmpl_render() {
  # tmpl_render <template_file> <dest_file> KEY=VAL KEY2=VAL2...
  local tpl="$1"; shift
  local dest="$1"; shift
  local tmp
  tmp="$(mktemp)"
  cp "$tpl" "$tmp"
  local kv key val
  for kv in "$@"; do
    key="${kv%%=*}"
    val="${kv#*=}"
    # Escape for sed replacement
    val="$(printf '%s' "$val" | sed -e 's/[\/&|]/\\&/g')"
    sed -i "s|{{${key}}}|${val}|g" "$tmp"
  done
  mkdir -p "$(dirname "$dest")"
  mv "$tmp" "$dest"
}

find_vhost_file() {
  # Finds sites-available file that contains server_name <domain>
  local domain="$1"
  local f
  for f in /etc/nginx/sites-available/*; do
    [[ -f "$f" ]] || continue
    if grep -RqsE "^\s*server_name\s+.*\b${domain}\b" "$f"; then
      echo "$f"; return 0
    fi
  done
  return 1
}

detect_ssl_paths() {
  # Try to detect ssl_certificate and ssl_certificate_key from vhost file
  local vhost="$1"
  local cert key
  cert="$(grep -RhsE '^\s*ssl_certificate\s+' "$vhost" | head -n1 | awk '{print $2}' | tr -d ';' || true)"
  key="$(grep -RhsE '^\s*ssl_certificate_key\s+' "$vhost" | head -n1 | awk '{print $2}' | tr -d ';' || true)"

  if [[ -z "${cert:-}" || -z "${key:-}" ]]; then
    # fallback to LE live paths
    local domain="$2"
    cert="/etc/letsencrypt/live/${domain}/fullchain.pem"
    key="/etc/letsencrypt/live/${domain}/privkey.pem"
  fi

  [[ -f "$cert" ]] || die "SSL certificate not found: $cert"
  [[ -f "$key" ]]  || die "SSL key not found: $key"
  echo "$cert|$key"
}

ensure_enabled_symlink() {
  local vhost="$1"
  local name
  name="$(basename "$vhost")"
  if [[ ! -L "/etc/nginx/sites-enabled/${name}" ]]; then
    log "Creating symlink: /etc/nginx/sites-enabled/${name} -> $vhost"
    ln -s "$vhost" "/etc/nginx/sites-enabled/${name}"
  fi
}

backup_file() {
  local domain="$1"
  local src="$2"
  local ts="$3"
  local bdir="${BACKUP_ROOT}/${domain}/${ts}"
  mkdir -p "$bdir"
  if [[ -f "$src" || -L "$src" ]]; then
    cp -a "$src" "$bdir/"
    echo "$src" >> "${bdir}/MANIFEST.modified"
  fi
}

record_created() {
  local domain="$1"
  local created="$2"
  local ts="$3"
  local bdir="${BACKUP_ROOT}/${domain}/${ts}"
  mkdir -p "$bdir"
  echo "$created" >> "${bdir}/MANIFEST.created"
}

latest_backup_ts() {
  local domain="$1"
  ls -1 "${BACKUP_ROOT}/${domain}" 2>/dev/null | sort -r | head -n1
}

nginx_test() { nginx -t; }

nginx_reload() { systemctl reload nginx; }

inject_once_after_server_name() {
  # inject_once_after_server_name <file> <domain> <line_to_insert>
  local file="$1" domain="$2" insert="$3"
  grep -qF "$insert" "$file" && return 0
  # Insert after first server_name line matching domain
  awk -v dom="$domain" -v ins="$insert" '
    BEGIN{done=0}
    {
      print $0
      if(done==0 && $0 ~ "server_name" && $0 ~ dom){
        print "    " ins
        done=1
      }
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

inject_location_csp_report() {
  local file="$1"
  grep -qE 'location\s*=\s*/csp-report' "$file" && return 0
  # Insert a location block inside the 443 server block near the top.
  # Heuristic: after server_name line.
  awk '
    BEGIN{inserted=0}
    {
      print $0
      if(!inserted && $0 ~ /server_name/){
        print ""
        print "    # CSP report endpoint (POC)"
        print "    location = /csp-report {"
        print "        access_log /var/log/nginx/vapt_csp_report_access.log;"
        print "        return 204;"
        print "    }"
        print ""
        inserted=1
      }
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

inject_limits_into_location_root() {
  # Adds limit_conn/limit_req inside location / { } if missing
  local file="$1" zone_conn="$2" zone_req="$3" conn="$4" burst="$5"
  # Quick check if already there
  grep -qE "limit_conn\s+${zone_conn}\s+" "$file" && grep -qE "limit_req\s+zone=${zone_req}\s+" "$file" && return 0

  # Insert after "location / {" line
  awk -v zc="$zone_conn" -v zr="$zone_req" -v c="$conn" -v b="$burst" '
    BEGIN{in_loc=0; done=0}
    {
      print $0
      if(done==0 && $0 ~ /^\s*location\s+\/\s*\{/){
        print "        # Enforce rate & connection limits"
        print "        limit_conn " zc " " c ";"
        print "        limit_req zone=" zr " burst=" b " nodelay;"
        done=1
      }
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

inject_hsts() {
  local file="$1" maxage="$2"
  grep -qE 'Strict-Transport-Security' "$file" && return 0
  # Insert inside 443 server block (near ssl config or before closing brace)
  awk -v ma="$maxage" '
    BEGIN{done=0}
    {
      if(done==0 && $0 ~ /ssl_dhparam/){
        print $0
        print "    # HSTS (start small; increase after validation)"
        print "    add_header Strict-Transport-Security \"max-age=" ma "\" always;"
        done=1
        next
      }
      print $0
    }' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

apply() {
  local domain="$1" upstream="$2" req_rate="$3" burst="$4" conn="$5" hsts="$6" csp_phase="$7" warn="$8" dry="$9"

  log "Starting apply for domain=$domain version=$VERSION"

  local ts
  ts="$(date +%Y%m%d-%H%M%S)"

  local vhost
  vhost="$(find_vhost_file "$domain")" || die "Could not find vhost in /etc/nginx/sites-available/ for domain: $domain"

  log "Detected vhost: $vhost"

  local ssl
  ssl="$(detect_ssl_paths "$vhost" "$domain")"
  local ssl_cert="${ssl%%|*}"
  local ssl_key="${ssl#*|}"
  log "Detected SSL cert=$ssl_cert key=$ssl_key"

  # Derive safe zone names (limited to 20 chars to keep total zone name under 32)
  local safe_dom
  safe_dom="$(echo "$domain" | tr '.-' '__' | cut -c1-20)"
  [[ -n "$safe_dom" ]] || die "Failed to derive safe_dom from domain: $domain"

  local zone_req="vapt_${safe_dom}_req"
  local zone_conn="vapt_${safe_dom}_conn"

  local ratelimit_conf="/etc/nginx/conf.d/${domain}.ratelimit.conf"
  local snippet="/etc/nginx/snippets/${domain}.security.conf"

  # Backup vhost and existing files
  backup_file "$domain" "$vhost" "$ts"
  backup_file "$domain" "$ratelimit_conf" "$ts"
  backup_file "$domain" "$snippet" "$ts"

  if [[ "$dry" == "1" ]]; then
    log "[DRY-RUN] Would write ratelimit: $ratelimit_conf"
    log "[DRY-RUN] Would write snippet:   $snippet"
    log "[DRY-RUN] Would modify vhost:    $vhost"
    log "[DRY-RUN] Would reload nginx"
    return 0
  fi

  # Render CSP header from phase template
  local csp_tpl
  csp_tpl="$(dirname "$0")/../templates/csp/phase${csp_phase}.tpl"
  [[ -f "$csp_tpl" ]] || die "Invalid CSP phase template: $csp_tpl"

  local csp_header
  csp_header="$(grep -v '^[[:space:]]*#' "$csp_tpl" | tr -d '\r\n')"

  # Render and write files from templates
  tmpl_render "$(dirname "$0")/../templates/ratelimit.tpl" "$ratelimit_conf" \
    "DOMAIN=$domain" "ZONE_REQ=$zone_req" "ZONE_CONN=$zone_conn" "REQ_RATE=$req_rate"
  record_created "$domain" "$ratelimit_conf" "$ts"

  tmpl_render "$(dirname "$0")/../templates/security-snippet.tpl" "$snippet" \
    "DOMAIN=$domain" "CSP_HEADER=$csp_header"
  record_created "$domain" "$snippet" "$ts"

  # Ensure vhost enabled
  ensure_enabled_symlink "$vhost"

  # 1. Clean up any existing hardening lines from previous runs (Idempotency)
  log "Removing old hardening lines from $vhost if present..."
  sed -i '/vapt_.*_conn/d' "$vhost"
  sed -i '/vapt_.*_req/d' "$vhost"
  sed -i '/include.*security\.conf/d' "$vhost"
  sed -i '/location.*\/csp-report/,/}/d' "$vhost"
  sed -i '/Strict-Transport-Security/d' "$vhost"

  # 2. Inject include, CSP endpoint, limits, HSTS
  inject_once_after_server_name "$vhost" "$domain" "include /etc/nginx/snippets/${domain}.security.conf;"
  inject_location_csp_report "$vhost"
  inject_limits_into_location_root "$vhost" "$zone_conn" "$zone_req" "$conn" "$burst"
  inject_hsts "$vhost" "$hsts"

  # Ensure proxy_pass matches upstream? We won't rewrite automatically; just warn if mismatch.
  if ! grep -qE "proxy_pass\s+${upstream//\//\\/}\s*;" "$vhost"; then
    log "WARNING: vhost proxy_pass does not match --upstream. Framework does not rewrite upstream automatically."
  fi

  # Optional warning page + default_server
  if [[ "$warn" == "on" ]]; then
    mkdir -p /var/www/security-warning
    if [[ ! -f /var/www/security-warning/index.html ]]; then
      cp "$(dirname "$0")/../templates/warning-page.html" /var/www/security-warning/index.html
      record_created "$domain" "/var/www/security-warning/index.html" "$ts"
    fi

    local default_conf="/etc/nginx/sites-available/00-default-ip-block.conf"
    # Backup if exists
    backup_file "$domain" "$default_conf" "$ts"
    tmpl_render "$(dirname "$0")/../templates/default-ip-block.tpl" "$default_conf" \
      "SSL_CERT=$ssl_cert" "SSL_KEY=$ssl_key"
    record_created "$domain" "$default_conf" "$ts"

    if [[ ! -L /etc/nginx/sites-enabled/00-default-ip-block.conf ]]; then
      ln -s "$default_conf" /etc/nginx/sites-enabled/00-default-ip-block.conf
      record_created "$domain" "/etc/nginx/sites-enabled/00-default-ip-block.conf" "$ts"
    fi
  fi

  nginx_test
  nginx_reload
  log "Apply complete for domain=$domain"
  log "Backup stored at: ${BACKUP_ROOT}/${domain}/${ts}"
}

rollback() {
  local domain="$1" dry="$2"
  local ts
  ts="$(latest_backup_ts "$domain")"
  [[ -n "${ts:-}" ]] || die "No backups found for domain: $domain"

  local bdir="${BACKUP_ROOT}/${domain}/${ts}"
  log "Starting rollback for domain=$domain from backup=$bdir"

  if [[ "$dry" == "1" ]]; then
    log "[DRY-RUN] Would restore files from $bdir"
    return 0
  fi

  # Restore modified files
  if [[ -f "${bdir}/MANIFEST.modified" ]]; then
    while read -r orig; do
      local bfile="${bdir}/$(basename "$orig")"
      if [[ -e "$bfile" ]]; then
        cp -a "$bfile" "$(dirname "$orig")/"
        log "Restored: $orig"
      fi
    done < "${bdir}/MANIFEST.modified"
  fi

  # Remove created files (best-effort)
  if [[ -f "${bdir}/MANIFEST.created" ]]; then
    tac "${bdir}/MANIFEST.created" | while read -r created; do
      if [[ -L "$created" ]]; then
        rm -f "$created" && log "Removed symlink: $created"
      elif [[ -f "$created" ]]; then
        rm -f "$created" && log "Removed file: $created"
      fi
    done
  fi

  nginx_test
  nginx_reload
  log "Rollback complete for domain=$domain"
}

# ------------------------
# Args
# ------------------------
DOMAIN=""
UPSTREAM=""
REQ_RATE="20r/s"
BURST="40"
CONN="30"
HSTS_MAXAGE="300"
CSP_PHASE="1"
WARNING_PAGE="on"
DRY_RUN="0"
DO_ROLLBACK="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2;;
    --upstream) UPSTREAM="$2"; shift 2;;
    --req-rate) REQ_RATE="$2"; shift 2;;
    --burst) BURST="$2"; shift 2;;
    --conn) CONN="$2"; shift 2;;
    --hsts-max-age) HSTS_MAXAGE="$2"; shift 2;;
    --csp-phase) CSP_PHASE="$2"; shift 2;;
    --warning-page) WARNING_PAGE="$2"; shift 2;;
    --dry-run) DRY_RUN="1"; shift 1;;
    --rollback) DO_ROLLBACK="1"; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown argument: $1";;
  esac
done

need_root
touch "$LOG_FILE" || true

[[ -n "$DOMAIN" ]] || { usage; die "--domain is required"; }

if [[ "$DO_ROLLBACK" == "1" ]]; then
  rollback "$DOMAIN" "$DRY_RUN"
  exit 0
fi

[[ -n "$UPSTREAM" ]] || { usage; die "--upstream is required (unless --rollback)"; }

[[ "$CSP_PHASE" =~ ^[0-3]$ ]] || die "--csp-phase must be 0..3"
[[ "$WARNING_PAGE" == "on" || "$WARNING_PAGE" == "off" ]] || die "--warning-page must be on|off"

apply "$DOMAIN" "$UPSTREAM" "$REQ_RATE" "$BURST" "$CONN" "$HSTS_MAXAGE" "$CSP_PHASE" "$WARNING_PAGE" "$DRY_RUN"
