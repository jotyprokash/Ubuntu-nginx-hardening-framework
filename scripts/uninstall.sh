\
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
  cat <<'EOF'
Usage:
  sudo bash scripts/uninstall.sh --domain example.com [--dry-run]

This removes framework-generated files for the given domain:
- /etc/nginx/conf.d/<domain>.ratelimit.conf
- /etc/nginx/snippets/<domain>.security.conf
- /etc/nginx/sites-available/00-default-ip-warning.conf and its symlink
- /var/www/security-warning/index.html (only if created by this framework)

NOTE: It does NOT automatically restore your vhost file. Use the backups created during install.
EOF
}

DOMAIN=""
DRY_RUN="no"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2;;
    --dry-run) DRY_RUN="yes"; shift 1;;
    -h|--help) usage; exit 0;;
    *) die "Unknown arg: $1 (use --help)";;
  esac
done

need_root
[[ -n "$DOMAIN" ]] || die "--domain is required"

CONF_D_FILE="/etc/nginx/conf.d/${DOMAIN}.ratelimit.conf"
SNIPPET_FILE="/etc/nginx/snippets/${DOMAIN}.security.conf"
DEFAULT_IP_FILE="/etc/nginx/sites-available/00-default-ip-warning.conf"
DEFAULT_IP_LINK="/etc/nginx/sites-enabled/00-default-ip-warning.conf"
WARNING_ROOT="/var/www/security-warning"

rmf() {
  local p="$1"
  if [[ -e "$p" || -L "$p" ]]; then
    log "Removing: $p"
    [[ "$DRY_RUN" == "yes" ]] || rm -f "$p"
  else
    log "Not found: $p"
  fi
}

rmf "$CONF_D_FILE"
rmf "$SNIPPET_FILE"
rmf "$DEFAULT_IP_LINK"
rmf "$DEFAULT_IP_FILE"

# Remove warning page only if it matches our template signature
if [[ -f "$WARNING_ROOT/index.html" ]]; then
  if grep -q "Unauthorized / Direct-IP Access" "$WARNING_ROOT/index.html" 2>/dev/null; then
    log "Removing warning page: $WARNING_ROOT/index.html"
    [[ "$DRY_RUN" == "yes" ]] || rm -f "$WARNING_ROOT/index.html"
  else
    log "Warning page exists but doesn't look like ours; leaving: $WARNING_ROOT/index.html"
  fi
fi

log "Validating nginx config..."
nginx_test
if [[ "$DRY_RUN" == "yes" ]]; then
  log "DRY-RUN: skipping reload."
else
  nginx_reload
  log "Reloaded nginx."
fi

log "Done. To restore vhost, pick the appropriate *.bak file created during install."
