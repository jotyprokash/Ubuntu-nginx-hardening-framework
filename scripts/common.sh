\
#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/nginx-hardening.log"

log() {
  local msg="$*"
  local ts
  ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  echo "[$ts] $msg" | tee -a "$LOG_FILE" >/dev/null
}

die() {
  log "ERROR: $*"
  exit 1
}

need_root() {
  [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Run as root (use sudo)."
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"
}

nginx_test() {
  nginx -t
}

nginx_reload() {
  systemctl reload nginx
}

backup_file() {
  local src="$1"
  local tag="$2"
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  local dst="${src}.${tag}.${ts}.bak"
  cp -a "$src" "$dst"
  log "Backup created: $dst"
  echo "$dst"
}

detect_vhost_file() {
  local domain="$1"
  local escaped_domain
  escaped_domain="$(printf '%s' "$domain" | sed 's/\./\\./g')"
  # Prefer exact filename match if exists
  if [[ -f "/etc/nginx/sites-available/${domain}" ]]; then
    echo "/etc/nginx/sites-available/${domain}"
    return 0
  fi

  # Search by server_name in sites-available (exact domain token match)
  local matches
  matches="$(grep -Rsl --include="*" -E "^\s*server_name\s+(.*\s)?${escaped_domain}(\s|;)" /etc/nginx/sites-available 2>/dev/null || true)"
  local count
  count="$(echo "$matches" | sed '/^\s*$/d' | wc -l | tr -d ' ')"
  if [[ "$count" -eq 1 ]]; then
    echo "$matches"
    return 0
  fi
  if [[ "$count" -gt 1 ]]; then
    die "Multiple vhost files match domain '${domain}'. Specify --vhost-file explicitly. Matches: $(echo "$matches" | tr '\n' ' ')"
  fi
  die "Could not find vhost for domain '${domain}' in /etc/nginx/sites-available."
}

detect_cert_paths_from_vhost() {
  local vhost_file="$1"
  local cert key
  cert="$(grep -E "^\s*ssl_certificate\s+" "$vhost_file" | head -n1 | awk '{print $2}' | sed 's/;.*$//')"
  key="$(grep -E "^\s*ssl_certificate_key\s+" "$vhost_file" | head -n1 | awk '{print $2}' | sed 's/;.*$//')"
  if [[ -n "${cert:-}" && -n "${key:-}" && -f "$cert" && -f "$key" ]]; then
    echo "$cert|$key"
    return 0
  fi
  # fallback to standard certbot location from domain (if present)
  return 1
}

ensure_include_order() {
  local nginx_conf="/etc/nginx/nginx.conf"
  grep -nE 'include\s+/etc/nginx/conf\.d/\*\.conf|include\s+/etc/nginx/sites-enabled/\*' "$nginx_conf" >/dev/null \
    || die "nginx.conf missing includes for conf.d and/or sites-enabled."
  log "Include order looks present in /etc/nginx/nginx.conf"
}

apply_idempotent_line_after_match() {
  local file="$1" match="$2" insert="$3" marker="$4"
  if grep -Fq "$marker" "$file"; then
    log "Marker already present in $file: $marker"
    return 0
  fi
  # Insert after first line that matches regex
  local tmp; tmp="$(mktemp)"
  awk -v m="$match" -v ins="$insert" -v mark="$marker" '
    BEGIN{done=0}
    {
      print $0
      if(!done && $0 ~ m){
        print ins
        print mark
        done=1
      }
    }
  ' "$file" >"$tmp"
  mv "$tmp" "$file"
  log "Inserted block into $file after match: $match"
}

append_if_missing() {
  local file="$1" needle="$2" content="$3"
  if grep -Fq "$needle" "$file"; then
    log "Already present in $file: $needle"
    return 0
  fi
  printf "\n%s\n" "$content" >> "$file"
  log "Appended to $file: $needle"
}
